/*
 * pgaudit/pgaudit.c
 *
 * Copyright © 2014, PostgreSQL Global Development Group
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose, without fee, and without a
 * written agreement is hereby granted, provided that the above
 * copyright notice and this paragraph and the following two
 * paragraphs appear in all copies.
 *
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE TO ANY PARTY FOR DIRECT,
 * INDIRECT, SPECIAL, INCIDENTAL, OR CONSEQUENTIAL DAMAGES, INCLUDING
 * LOST PROFITS, ARISING OUT OF THE USE OF THIS SOFTWARE AND ITS
 * DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA HAS BEEN ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * THE AUTHOR SPECIFICALLY DISCLAIMS ANY WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS
 * IS" BASIS, AND THE AUTHOR HAS NO OBLIGATIONS TO PROVIDE MAINTENANCE,
 * SUPPORT, UPDATES, ENHANCEMENTS, OR MODIFICATIONS.
 */

#include "postgres.h"

#include "access/xact.h"
#include "catalog/objectaccess.h"
#include "commands/event_trigger.h"
#include "executor/executor.h"
#include "executor/spi.h"
#include "miscadmin.h"
#include "libpq/auth.h"
#include "nodes/nodes.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/ruleutils.h"
#include "utils/timestamp.h"

PG_MODULE_MAGIC;

void _PG_init(void);

Datum pgaudit_func_ddl_command_end(PG_FUNCTION_ARGS);
Datum pgaudit_func_sql_drop(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(pgaudit_func_ddl_command_end);
PG_FUNCTION_INFO_V1(pgaudit_func_sql_drop);

/*
 * pgaudit_log_str is the string value of the pgaudit.log configuration
 * variable, e.g. "read, write, user". Each token corresponds to a flag
 * in enum LogClass below. We convert the list of tokens into a bitmap
 * in pgaudit_log for internal use.
 */

char *pgaudit_log_str = NULL;
static uint64 pgaudit_log = 0;

enum LogClass {
	LOG_NONE = 0,

	/* SELECT */
	LOG_READ = (1 << 0),

	/* INSERT, UPDATE, DELETE, TRUNCATE */
	LOG_WRITE = (1 << 1),

	/* GRANT, REVOKE, ALTER … */
	LOG_PRIVILEGE = (1 << 2),

	/* CREATE/DROP/ALTER ROLE */
	LOG_USER = (1 << 3),

	/* DDL: CREATE/DROP/ALTER */
	LOG_DEFINITION = (1 << 4),

	/* DDL: CREATE OPERATOR etc. */
	LOG_CONFIG = (1 << 5),

	/* VACUUM, REINDEX, ANALYZE */
	LOG_ADMIN = (1 << 6),

	/* Absolutely everything */
	LOG_ALL = ~(uint64)0
};

/*
 * This module collects AuditEvents from various sources (event
 * triggers, and executor/utility hooks) and passes them to the
 * log_audit_event() function.
 *
 * An AuditEvent represents an operation that potentially affects a
 * single object. If an underlying command affects multiple objects,
 * multiple AuditEvents must be created to represent it.
 */

typedef struct {
	NodeTag type;
	const char *object_id;
	const char *object_type;
	const char *command_tag;
	const char *command_text;
} AuditEvent;

/*
 * Takes an AuditEvent and returns true or false depending on whether
 * the event should be logged according to the pgaudit.log setting. If
 * it returns true, it also fills in the name of the LogClass which it
 * is to be logged under.
 */

static bool
should_be_logged(AuditEvent *e, const char **classname)
{
	enum LogClass class = LOG_NONE;
	char *name;

	/*
	 * Look at the type of the command and decide what LogClass needs to
	 * be enabled for the command to be logged.
	 */

	switch (e->type)
	{
		case T_SelectStmt:
			name = "READ";
			class = LOG_READ;
			break;

		case T_InsertStmt:
		case T_UpdateStmt:
		case T_DeleteStmt:
		case T_TruncateStmt:
			name = "WRITE";
			class = LOG_WRITE;
			break;

		case T_GrantStmt:
		case T_GrantRoleStmt:
		case T_AlterDefaultPrivilegesStmt:
		case T_AlterOwnerStmt:
			name = "PRIVILEGE";
			class = LOG_PRIVILEGE;
			break;

		case T_CreateRoleStmt:
		case T_AlterRoleStmt:
		case T_DropRoleStmt:
			name = "USER";
			class = LOG_USER;
			break;

		case T_AlterTableStmt:
		case T_AlterTableCmd:
		case T_AlterDomainStmt:
		case T_CreateStmt:
		case T_DefineStmt:
		case T_DropStmt:
		case T_CommentStmt:
		case T_IndexStmt:
		case T_LockStmt:
		case T_CreateFunctionStmt:
		case T_AlterFunctionStmt:
		case T_DoStmt:
		case T_RenameStmt:
		case T_RuleStmt:
		case T_ViewStmt:
		case T_CreateDomainStmt:
		case T_CreateTableAsStmt:
		case T_CreateSeqStmt:
		case T_AlterSeqStmt:
		case T_CreateTrigStmt:
		case T_CreateSchemaStmt:
		case T_AlterObjectSchemaStmt:
		case T_CreateEnumStmt:
		case T_CreateRangeStmt:
		case T_AlterEnumStmt:
			name = "DEFINITION";
			class = LOG_DEFINITION;
			break;

		case T_CreatePLangStmt:
		case T_CreateConversionStmt:
		case T_CreateCastStmt:
		case T_CreateOpClassStmt:
		case T_CreateOpFamilyStmt:
		case T_AlterOpFamilyStmt:
		case T_CompositeTypeStmt:
		case T_AlterTSDictionaryStmt:
		case T_AlterTSConfigurationStmt:
			name = "CONFIG";
			class = LOG_CONFIG;
			break;

		case T_ClusterStmt:
		case T_CreatedbStmt:
		case T_DropdbStmt:
		case T_LoadStmt:
		case T_VacuumStmt:
		case T_ExplainStmt:
		case T_VariableSetStmt:
		case T_DiscardStmt:
		case T_ReindexStmt:
		case T_CheckPointStmt:
		case T_AlterDatabaseStmt:
		case T_AlterDatabaseSetStmt:
		case T_AlterRoleSetStmt:
		case T_CreateTableSpaceStmt:
		case T_DropTableSpaceStmt:
		case T_DropOwnedStmt:
		case T_ReassignOwnedStmt:
		case T_CreateFdwStmt:
		case T_AlterFdwStmt:
		case T_CreateForeignServerStmt:
		case T_AlterForeignServerStmt:
		case T_CreateUserMappingStmt:
		case T_AlterUserMappingStmt:
		case T_DropUserMappingStmt:
		case T_AlterTableSpaceOptionsStmt:
		case T_AlterTableSpaceMoveStmt:
		case T_SecLabelStmt:
		case T_CreateForeignTableStmt:
		case T_CreateExtensionStmt:
		case T_AlterExtensionStmt:
		case T_AlterExtensionContentsStmt:
		case T_CreateEventTrigStmt:
		case T_AlterEventTrigStmt:
		case T_RefreshMatViewStmt:
		case T_ReplicaIdentityStmt:
		case T_AlterSystemStmt:
			name = "ADMIN";
			class = LOG_ADMIN;
			break;

		default:
			name = "UNKNOWN";
			class = LOG_ALL;
			break;
	}

	/* Is the desired class enabled? */

	if ((pgaudit_log & class) == 0)
		return false;

	*classname = name;
	return true;
}

/*
 * Takes an AuditEvent and, if it should_be_logged(), writes it to the
 * audit log. The AuditEvent is assumed to be completely filled in by
 * the caller (unknown values must be set to "" so that they can be
 * logged without error checking).
 */

static void
log_audit_event(AuditEvent *e)
{
	const char *timestamp;
	const char *username;
	const char *eusername;
	const char *classname;

	if (!should_be_logged(e, &classname))
		return;

	timestamp = timestamptz_to_str(GetCurrentTimestamp());
	username = GetUserNameFromId(GetSessionUserId());
	eusername = GetUserNameFromId(GetUserId());

	/*
	 * For now, we only support logging via ereport(). In future, we may
	 * log to a separate file, or a table.
	 */

	ereport(LOG,
			(errmsg("[AUDIT],%s,%s,%s,%s,%s,%s,%s,%s",
					timestamp, username, eusername, classname,
					e->command_tag, e->object_type, e->object_id,
					e->command_text)));
}

/*
 * A ddl_command_end event trigger to build AuditEvents for commands
 * that we can deparse. This function is called at the end of any DDL
 * command that has event trigger support.
 */

Datum
pgaudit_func_ddl_command_end(PG_FUNCTION_ARGS)
{
	EventTriggerData *trigdata;
	int               ret, row;
	TupleDesc		  spi_tupdesc;
	const char		 *query_get_creation_commands;

	MemoryContext tmpcontext;
	MemoryContext oldcontext;

	if (pgaudit_log == 0)
		PG_RETURN_NULL();

	if (!CALLED_AS_EVENT_TRIGGER(fcinfo))
		elog(ERROR, "not fired by event trigger manager");

	/*
	 * This query returns the objects affected by the DDL, and a JSON
	 * representation of the parsed command. We use SPI to execute it,
	 * and compose one AuditEvent per object in the results.
	 */

	query_get_creation_commands =
		"SELECT classid, objid, objsubid, object_type, schema, identity, command"
		"  FROM pg_event_trigger_get_creation_commands()";

	tmpcontext = AllocSetContextCreate(CurrentMemoryContext,
									   "pgaudit_func_ddl_command_end temporary context",
									   ALLOCSET_DEFAULT_MINSIZE,
									   ALLOCSET_DEFAULT_INITSIZE,
									   ALLOCSET_DEFAULT_MAXSIZE);
	oldcontext = MemoryContextSwitchTo(tmpcontext);

	ret = SPI_connect();
	if (ret < 0)
		elog(ERROR, "pgaudit_func_ddl_command_end: SPI_connect returned %d", ret);

	ret = SPI_execute(query_get_creation_commands, true, 0);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "pgaudit_func_ddl_command_end: SPI_execute returned %d", ret);

	spi_tupdesc = SPI_tuptable->tupdesc;

	trigdata = (EventTriggerData *) fcinfo->context;

	for (row = 0; row < SPI_processed; row++)
	{
		AuditEvent e;
		HeapTuple  spi_tuple;
		Datum	   json;
		Datum	   command;
		bool	   isnull;
		char	  *command_formatted;

		spi_tuple = SPI_tuptable->vals[row];

		/* Temporarily dump the raw JSON rendering for debugging */
		command_formatted = SPI_getvalue(spi_tuple, spi_tupdesc, 7);
		ereport(DEBUG1, (errmsg("%s", command_formatted),
						 errhidestmt(true)));

		/*
		 * pg_event_trigger_expand_command() takes the JSON
		 * representation of a command and deparses it back into a
		 * fully-qualified version of the command.
		 */

		json = SPI_getbinval(spi_tuple, spi_tupdesc, 7, &isnull);
		command = DirectFunctionCall1(pg_event_trigger_expand_command, json);

		e.type = nodeTag(trigdata->parsetree);
		e.object_id = SPI_getvalue(spi_tuple, spi_tupdesc, 6);
		e.object_type = SPI_getvalue(spi_tuple, spi_tupdesc, 4);
		e.command_tag = trigdata->tag;
		e.command_text = TextDatumGetCString(command);

		log_audit_event(&e);
	}

	SPI_finish();
	MemoryContextSwitchTo(oldcontext);
	MemoryContextDelete(tmpcontext);
	PG_RETURN_NULL();
}

/*
 * An sql_drop event trigger to build AuditEvents for dropped objects.
 * At the moment, we do not have the ability to deparse these commands,
 * but once support for the is added upstream, it's easy to implement.
 */

Datum
pgaudit_func_sql_drop(PG_FUNCTION_ARGS)
{
	EventTriggerData *trigdata;
	TupleDesc		  spi_tupdesc;
	int               ret, row;
	const char		 *query_dropped_objects;

	MemoryContext tmpcontext;
	MemoryContext oldcontext;

	if (pgaudit_log == 0)
		PG_RETURN_NULL();

	if (!CALLED_AS_EVENT_TRIGGER(fcinfo))
		elog(ERROR, "not fired by event trigger manager");

	/*
	 * This query returns a list of objects dropped by the command
	 * (which no longer exist, and thus cannot be looked up). With
	 * no support for deparsing the command, the best we can do is
	 * to log the identity of the objects.
	 */

	query_dropped_objects =
		"SELECT classid, objid, objsubid, object_type, schema_name, object_name, object_identity"
		"  FROM pg_event_trigger_dropped_objects()";

	tmpcontext = AllocSetContextCreate(CurrentMemoryContext,
									   "pgaudit_func_sql_drop temporary context",
									   ALLOCSET_DEFAULT_MINSIZE,
									   ALLOCSET_DEFAULT_INITSIZE,
									   ALLOCSET_DEFAULT_MAXSIZE);
	oldcontext = MemoryContextSwitchTo(tmpcontext);

	ret = SPI_connect();
	if (ret < 0)
		elog(ERROR, "pgaudit_func_sql_drop: SPI_connect returned %d", ret);

	ret = SPI_execute(query_dropped_objects, true, 0);
	if (ret != SPI_OK_SELECT)
		elog(ERROR, "pgaudit_func_sql_drop: SPI_execute returned %d", ret);

	spi_tupdesc = SPI_tuptable->tupdesc;

	trigdata = (EventTriggerData *) fcinfo->context;

	for (row = 0; row < SPI_processed; row++)
	{
		AuditEvent e;
		HeapTuple  spi_tuple;

		spi_tuple = SPI_tuptable->vals[row];

		e.type = nodeTag(trigdata->parsetree);
		e.object_id = SPI_getvalue(spi_tuple, spi_tupdesc, 7);
		e.object_type = SPI_getvalue(spi_tuple, spi_tupdesc, 4);
		e.command_tag = trigdata->tag;
		e.command_text = "";

		log_audit_event(&e);
	}

	SPI_finish();
	MemoryContextSwitchTo(oldcontext);
	MemoryContextDelete(tmpcontext);
	PG_RETURN_NULL();
}

/*
 * Create AuditEvents for DML operations via executor permissions
 * checks. We create an AuditEvent for each table in the list of
 * RangeTableEntries from the query.
 */

static void
log_executor_check_perms(List *rangeTabls, bool abort_on_violation)
{
	ListCell *lr;

	foreach (lr, rangeTabls)
	{
		Relation rel;
		AuditEvent e;
		RangeTblEntry *rte = lfirst(lr);
		char *relname;
		const char *tag;
		const char *reltype;
		NodeTag type;

		/* We only care about tables, and can ignore subqueries etc. */
		if (rte->rtekind != RTE_RELATION)
			continue;

		/* Get the fully-qualified name of the relation. */

		rel = relation_open(rte->relid, NoLock);
		relname = quote_qualified_identifier(get_namespace_name(RelationGetNamespace(rel)),
											 RelationGetRelationName(rel));
		relation_close(rel, NoLock);

		/*
		 * We don't have access to the parsetree here, so we have to
		 * generate the node type, object type, and command tag by
		 * decoding rte->requiredPerms and rte->relkind.
		 */

		if (rte->requiredPerms & ACL_INSERT)
		{
			tag = "INSERT";
			type = T_InsertStmt;
		}
		else if (rte->requiredPerms & ACL_UPDATE)
		{
			tag = "UPDATE";
			type = T_UpdateStmt;
		}
		else if (rte->requiredPerms & ACL_DELETE)
		{
			tag = "DELETE";
			type = T_DeleteStmt;
		}
		else if (rte->requiredPerms & ACL_SELECT)
		{
			tag = "SELECT";
			type = T_SelectStmt;
		}
		else
		{
			tag = "UNKNOWN";
			type = T_Invalid;
		}

		switch (rte->relkind)
		{
			case RELKIND_RELATION:
				reltype = "TABLE";
				break;

			case RELKIND_INDEX:
				reltype = "INDEX";
				break;

			case RELKIND_SEQUENCE:
				reltype = "SEQUENCE";
				break;

			case RELKIND_TOASTVALUE:
				reltype = "TOASTVALUE";
				break;

			case RELKIND_VIEW:
				reltype = "VIEW";
				break;

			case RELKIND_COMPOSITE_TYPE:
				reltype = "COMPOSITE_TYPE";
				break;

			case RELKIND_FOREIGN_TABLE:
				reltype = "FOREIGN_TABLE";
				break;

			case RELKIND_MATVIEW:
				reltype = "MATVIEW";
				break;

			default:
				reltype = "UNKNOWN";
				break;
		}

		/*
		 * XXX We could also decode rte->selectedCols and
		 * rte->modifiedCols here.
		 */

		e.type = type;
		e.object_id = relname;
		e.object_type = reltype;
		e.command_tag = tag;
		e.command_text = "";

		log_audit_event(&e);

		pfree(relname);
	}
}

/*
 * Create AuditEvents for utility commands that cannot be handled by
 * event triggers, particularly those which affect global objects.
 */

static void
log_utility_command(Node *parsetree,
					const char *queryString,
					ProcessUtilityContext context,
					ParamListInfo params,
					DestReceiver *dest,
					char *completionTag)
{
	AuditEvent e;
	bool supported_stmt = true;

	/*
	 * If the statement (and, for some statements, the object type) is
	 * supported by event triggers, then we don't need to log anything.
	 * Otherwise, we log the query string.
	 *
	 * The following logic is copied from standard_ProcessUtility in
	 * tcop/utility.c, and will need to be changed if event trigger
	 * support is expanded to other commands (if not, the command
	 * will be logged twice).
	 */

	switch (nodeTag(parsetree))
	{
		/*
		 * The following statements are never supported by event
		 * triggers.
		 */

		case T_TransactionStmt:
		case T_PlannedStmt:
		case T_ClosePortalStmt:
		case T_FetchStmt:
		case T_DoStmt:
		case T_CreateTableSpaceStmt:
		case T_DropTableSpaceStmt:
		case T_AlterTableSpaceOptionsStmt:
		case T_AlterTableSpaceMoveStmt:
		case T_TruncateStmt:
		case T_CommentStmt:
		case T_SecLabelStmt:
		case T_CopyStmt:
		case T_PrepareStmt:
		case T_ExecuteStmt:
		case T_DeallocateStmt:
		case T_GrantStmt:
		case T_GrantRoleStmt:
		case T_CreatedbStmt:
		case T_AlterDatabaseStmt:
		case T_AlterDatabaseSetStmt:
		case T_DropdbStmt:
		case T_NotifyStmt:
		case T_ListenStmt:
		case T_UnlistenStmt:
		case T_LoadStmt:
		case T_ClusterStmt:
		case T_VacuumStmt:
		case T_ExplainStmt:
		case T_AlterSystemStmt:
		case T_VariableSetStmt:
		case T_VariableShowStmt:
		case T_DiscardStmt:
		case T_CreateEventTrigStmt:
		case T_AlterEventTrigStmt:
		case T_CreateRoleStmt:
		case T_AlterRoleStmt:
		case T_AlterRoleSetStmt:
		case T_DropRoleStmt:
		case T_ReassignOwnedStmt:
		case T_LockStmt:
		case T_ConstraintsSetStmt:
		case T_CheckPointStmt:
		case T_ReindexStmt:
			supported_stmt = false;
			break;

		/*
		 * The following statements are supported by event triggers for
		 * certain object types.
		 */

		case T_DropStmt:
			{
				DropStmt   *stmt = (DropStmt *) parsetree;

				if (!EventTriggerSupportsObjectType(stmt->removeType))
					supported_stmt = false;
			}
			break;

		case T_RenameStmt:
			{
				RenameStmt *stmt = (RenameStmt *) parsetree;

				if (!EventTriggerSupportsObjectType(stmt->renameType))
					supported_stmt = false;
			}
			break;

		case T_AlterObjectSchemaStmt:
			{
				AlterObjectSchemaStmt *stmt = (AlterObjectSchemaStmt *) parsetree;

				if (!EventTriggerSupportsObjectType(stmt->objectType))
					supported_stmt = false;
			}
			break;

		case T_AlterOwnerStmt:
			{
				AlterOwnerStmt *stmt = (AlterOwnerStmt *) parsetree;

				if (!EventTriggerSupportsObjectType(stmt->objectType))
					supported_stmt = false;
			}
			break;

		/*
		 * All other statement types have event trigger support
		 */

		default:
			break;
	}

	if (supported_stmt)
		return;

	e.type = nodeTag(parsetree);
	e.object_id = "";
	e.object_type = "";
	e.command_tag = CreateCommandTag(parsetree);
	e.command_text = queryString;

	log_audit_event(&e);
}

/*
 * Log object accesses (which is more about DDL than DML, even though it
 * sounds like the latter).
 */

static void
log_object_access(ObjectAccessType access,
				  Oid classId,
				  Oid objectId,
				  int subId,
				  void *arg)
{
	/*
	 * The event triggers defined above cover most of the cases we
	 * would see here, so we do nothing for now. In future, we may use
	 * this hook to provide limited backwards-compability when event
	 * triggers are not available.
	 */
}

/*
 * Hook functions
 * --------------
 *
 * These functions (which are installed by _PG_init, below) just call
 * pgaudit logging functions before continuing the chain of hooks. We
 * must be careful to not call any logging functions from an aborted
 * transaction.
 */

static ExecutorCheckPerms_hook_type next_ExecutorCheckPerms_hook = NULL;
static ProcessUtility_hook_type next_ProcessUtility_hook = NULL;
static object_access_hook_type next_object_access_hook = NULL;

static bool
pgaudit_ExecutorCheckPerms_hook(List *rangeTabls, bool abort)
{
	if (pgaudit_log != 0 && !IsAbortedTransactionBlockState())
		log_executor_check_perms(rangeTabls, abort);

	if (next_ExecutorCheckPerms_hook &&
		!(*next_ExecutorCheckPerms_hook) (rangeTabls, abort))
		return false;

	return true;
}

static void
pgaudit_ProcessUtility_hook(Node *parsetree,
							const char *queryString,
							ProcessUtilityContext context,
							ParamListInfo params,
							DestReceiver *dest,
							char *completionTag)
{
	if (pgaudit_log != 0 && !IsAbortedTransactionBlockState())
		log_utility_command(parsetree, queryString, context,
							params, dest, completionTag);

	if (next_ProcessUtility_hook)
		(*next_ProcessUtility_hook) (parsetree, queryString, context,
									 params, dest, completionTag);
	else
		standard_ProcessUtility(parsetree, queryString, context,
								params, dest, completionTag);
}

static void
pgaudit_object_access_hook(ObjectAccessType access,
						   Oid classId,
						   Oid objectId,
						   int subId,
						   void *arg)
{
	if (pgaudit_log != 0 && !IsAbortedTransactionBlockState())
		log_object_access(access, classId, objectId, subId, arg);

	if (next_object_access_hook)
		(*next_object_access_hook) (access, classId, objectId, subId, arg);
}

/*
 * Take a pgaudit.log value such as "read, write, user", verify that
 * each of the comma-separated tokens corresponds to a LogClass value,
 * and convert them into a bitmap that log_audit_event can check.
 */

static bool
check_pgaudit_log(char **newval, void **extra, GucSource source)
{
	List *flags;
	char *rawval;
	ListCell *lt;
	uint64 *f;

	/*
	 * Once auditing is enabled, it would be nice to refuse to let it be
	 * disabled, even by superusers. Even if someone were able to obtain
	 * superuser access without authorisation, their actions would still
	 * be logged. Alas, it isn't possible to do this securely.
	 *
	 * Instead, we settle for some minimal protection by refusing
	 * client-level and interactive settings.
	 */

	if (source > PGC_S_DATABASE_USER)
	{
		GUC_check_errmsg("parameter \"pgaudit.log\" cannot be changed now");
		return false;
	}

	/* Make sure we have a comma-separated list of tokens. */

	rawval = pstrdup(*newval);
	if (!SplitIdentifierString(rawval, ',', &flags))
	{
		GUC_check_errdetail("List syntax is invalid");
		list_free(flags);
		pfree(rawval);
		return false;
	}

	/*
	 * Check that we recognise each token, and add it to the bitmap
	 * we're building up in a newly-allocated uint64 *f.
	 */

	f = (uint64 *) malloc(sizeof(uint64));
	if (!f)
		return false;
	*f = 0;

	foreach(lt, flags)
	{
		char *token = (char *)lfirst(lt);

		if (pg_strcasecmp(token, "none") == 0)
			/* Nothing to do. If "none" occurs in combination with other
			 * tokens, it's ignored. */
			;
		else if (pg_strcasecmp(token, "read") == 0)
			*f |= LOG_READ;
		else if (pg_strcasecmp(token, "write") == 0)
			*f |= LOG_WRITE;
		else if (pg_strcasecmp(token, "privilege") == 0)
			*f |= LOG_PRIVILEGE;
		else if (pg_strcasecmp(token, "user") == 0)
			*f |= LOG_USER;
		else if (pg_strcasecmp(token, "definition") == 0)
			*f |= LOG_DEFINITION;
		else if (pg_strcasecmp(token, "config") == 0)
			*f |= LOG_CONFIG;
		else if (pg_strcasecmp(token, "admin") == 0)
			*f |= LOG_ADMIN;
		else if (pg_strcasecmp(token, "all") == 0)
			*f = LOG_ALL;
		else
		{
			free(f);
			pfree(rawval);
			list_free(flags);
			return false;
		}
	}

	pfree(rawval);
	list_free(flags);

	/*
	 * All well, store the bitmap for assign_pgaudit_log.
	 */

	*extra = f;

	return true;
}

/*
 * Set pgaudit_log from extra (ignoring newval, which has already been
 * converted to a bitmap above). Note that extra may not be set if the
 * assignment is to be suppressed.
 */

static void
assign_pgaudit_log(const char *newval, void *extra)
{
	if (extra)
		pgaudit_log = *(uint64 *)extra;
}

/*
 * Define GUC variables and install hooks upon module load.
 */

void
_PG_init(void)
{
	if (IsUnderPostmaster)
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pgaudit must be loaded via shared_preload_libraries")));

	/*
	 * pgaudit.log = "read, write, user"
	 *
	 * This variables controls what classes of commands are logged.
	 */

	DefineCustomStringVariable("pgaudit.log",
							   "Enable auditing for certain classes of commands",
							   NULL,
							   &pgaudit_log_str,
							   "none",
							   PGC_SUSET,
							   GUC_LIST_INPUT | GUC_NOT_IN_SAMPLE,
							   check_pgaudit_log,
							   assign_pgaudit_log,
							   NULL);

	/*
	 * Install our hook functions after saving the existing pointers
	 * to preserve the chain.
	 */

	next_ExecutorCheckPerms_hook = ExecutorCheckPerms_hook;
	ExecutorCheckPerms_hook = pgaudit_ExecutorCheckPerms_hook;

	next_ProcessUtility_hook = ProcessUtility_hook;
	ProcessUtility_hook = pgaudit_ProcessUtility_hook;

	next_object_access_hook = object_access_hook;
	object_access_hook = pgaudit_object_access_hook;
}
