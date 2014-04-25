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

#include <time.h>

#include "access/xact.h"
#include "catalog/objectaccess.h"
#include "commands/event_trigger.h"
#include "executor/executor.h"
#include "executor/spi.h"
#include "miscadmin.h"
#include "libpq/auth.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/ruleutils.h"

PG_MODULE_MAGIC;

void _PG_init(void);

static bool pgaudit_enabled;

Datum pgaudit_func_ddl_command_end(PG_FUNCTION_ARGS);
Datum pgaudit_func_sql_drop(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(pgaudit_func_ddl_command_end);
PG_FUNCTION_INFO_V1(pgaudit_func_sql_drop);

static char *make_timestamp(void);

/*
 * A ddl_command_end event trigger to log commands that we can deparse.
 * This trigger is called at the end of any DDL command that has event
 * trigger support.
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

	if (!pgaudit_enabled)
		PG_RETURN_NULL();

	if (!CALLED_AS_EVENT_TRIGGER(fcinfo))
		elog(ERROR, "not fired by event trigger manager");

	/*
	 * This query returns the objects affected by the DDL, and a JSON
	 * representation of the parsed command. We use SPI to execute it,
	 * and compose one log entry per object in the results.
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
		HeapTuple  spi_tuple;
		char	  *command_text;
		char	  *command_formatted;
		Datum	   json;
		Datum	   command;
		bool	   isnull;

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
		command_text = TextDatumGetCString(command);

		ereport(LOG,
				(errmsg("[AUDIT]:DDL,%s,%s,%s,%s,%s,%s,%s",
						make_timestamp(),
						GetUserNameFromId(GetSessionUserId()),
						GetUserNameFromId(GetUserId()),
						SPI_getvalue(spi_tuple, spi_tupdesc, 6), /* object identity */
						SPI_getvalue(spi_tuple, spi_tupdesc, 4), /* object type */
						trigdata->tag,
						command_text),
				 errhidestmt(true)));
	}

	SPI_finish();
	MemoryContextSwitchTo(oldcontext);
	MemoryContextDelete(tmpcontext);
	PG_RETURN_NULL();
}

/*
 * An sql_drop event trigger to log dropped objects. At the moment, we
 * do not have the ability to deparse these commands, but once support
 * for the is added upstream, it's easy to implement.
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

	if (!pgaudit_enabled)
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
		HeapTuple  spi_tuple;

		spi_tuple = SPI_tuptable->vals[row];

		ereport(LOG,
				(errmsg("[AUDIT]:DDL,%s,%s,%s,%s,%s,%s,",
						make_timestamp(),
						GetUserNameFromId(GetSessionUserId()),
						GetUserNameFromId(GetUserId()),
						SPI_getvalue(spi_tuple, spi_tupdesc, 7), /* object identity */
						SPI_getvalue(spi_tuple, spi_tupdesc, 4), /* object type */
						trigdata->tag),
				 errhidestmt(true)));
	}

	SPI_finish();
	MemoryContextSwitchTo(oldcontext);
	MemoryContextDelete(tmpcontext);
	PG_RETURN_NULL();
}

/*
 * Logging functions
 * -----------------
 */

/*
 * Log DML operations via executor permissions checks. We get a list of
 * RangeTableEntries from the query. We log each fully-qualified table
 * name along with the required access permissions.
 */

static void
log_executor_check_perms(List *rangeTabls, bool abort_on_violation)
{
	ListCell *lr;

	foreach (lr, rangeTabls)
	{
		Relation rel;
		RangeTblEntry *rte = lfirst(lr);
		char *relname;
		char perms[5];
		int ip = 0;

		/* We only care about tables, and can ignore subqueries etc. */
		if (rte->rtekind != RTE_RELATION)
			continue;

		/* Get the fully-qualified name of the relation. */
		rel = relation_open(rte->relid, NoLock);
		relname = quote_qualified_identifier(get_namespace_name(RelationGetNamespace(rel)),
											 RelationGetRelationName(rel));
		relation_close(rel, NoLock);

		/*
		 * Decode the rte->requiredPerms bitmap into an array of
		 * characters. This is just a convenient representation
		 * with some precedent; it may not be the most useful.
		 */

		if (rte->requiredPerms & ACL_SELECT)
			perms[ip++] = ACL_SELECT_CHR;
		if (rte->requiredPerms & ACL_INSERT)
			perms[ip++] = ACL_INSERT_CHR;
		if (rte->requiredPerms & ACL_UPDATE)
			perms[ip++] = ACL_UPDATE_CHR;
		if (rte->requiredPerms & ACL_DELETE)
			perms[ip++] = ACL_DELETE_CHR;
		perms[ip++] = '\0';

		/*
		 * XXX We could decode and log rte->selectedCols and
		 * rte->modifiedCols here too.
		 */

		ereport(LOG, (errmsg("[AUDIT]:DML,%s,%s,%s,%s,%s",
							 make_timestamp(),
							 GetUserNameFromId(GetSessionUserId()),
							 GetUserNameFromId(GetUserId()),
							 relname, perms)));

		pfree(relname);
	}
}

/*
 * Log utility commands which cannot be handled by event triggers,
 * particularly those which affect global objects.
 */

static void
log_utility_command(Node *parsetree,
					const char *queryString,
					ProcessUtilityContext context,
					ParamListInfo params,
					DestReceiver *dest,
					char *completionTag)
{
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

	ereport(LOG, (errmsg("[AUDIT]:STMT_OTHER,%s,%s,%s,other,,%s,",
						 make_timestamp(),
						 GetUserNameFromId(GetSessionUserId()),
						 GetUserNameFromId(GetUserId()),
						 queryString),
				  errhidestmt(true)));
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
 * need to be careful to not call any logging functions inside an
 * aborted transaction.
 */

static ExecutorCheckPerms_hook_type next_ExecutorCheckPerms_hook = NULL;
static ProcessUtility_hook_type next_ProcessUtility_hook = NULL;
static object_access_hook_type next_object_access_hook = NULL;

static bool
pgaudit_ExecutorCheckPerms_hook(List *rangeTabls, bool abort)
{
	if (pgaudit_enabled && !IsAbortedTransactionBlockState())
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
	if (pgaudit_enabled && !IsAbortedTransactionBlockState())
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
	if (pgaudit_enabled && !IsAbortedTransactionBlockState())
		log_object_access(access, classId, objectId, subId, arg);

	if (next_object_access_hook)
		(*next_object_access_hook) (access, classId, objectId, subId, arg);
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
	 * pgaudit.enabled = (on|off)
	 *
	 * This variable controls whether auditing is enabled
	 */
	DefineCustomBoolVariable("pgaudit.enabled",
							 "Enable auditing",
							 NULL,
							 &pgaudit_enabled,
							 false,
							 PGC_SIGHUP,
							 GUC_NOT_IN_SAMPLE,
							 NULL,
							 NULL,
							 NULL);

	next_object_access_hook = object_access_hook;
	object_access_hook = pgaudit_object_access_hook;

	next_ExecutorCheckPerms_hook = ExecutorCheckPerms_hook;
	ExecutorCheckPerms_hook = pgaudit_ExecutorCheckPerms_hook;

	next_ProcessUtility_hook = ProcessUtility_hook;
	ProcessUtility_hook = pgaudit_ProcessUtility_hook;
}

/*
 * Utility functions
 * -----------------
 */

/* Quick'n'dirty timestamp generation */

#define TSBUF_LEN 128
char tsbuf[TSBUF_LEN];

static char *make_timestamp(void)
{
	pg_time_t timestamp = (pg_time_t) time(NULL);

	/* XXX Which time should we report, and in what format? */
	pg_strftime(tsbuf, TSBUF_LEN, "%Y-%m-%d %H:%M:%S %Z",
				pg_localtime(&timestamp, log_timezone));

	return tsbuf;
}
