/*
 * pgaudit/pgaudit.c
 * 		experimental auditing extension
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

#include "catalog/objectaccess.h"
#include "commands/event_trigger.h"
#include "executor/executor.h"
#include "executor/spi.h"
#include "miscadmin.h"
#include "lib/stringinfo.h"
#include "fmgr.h"
#include "libpq/auth.h"
#include "pgtime.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "utils/guc.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/ruleutils.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"

#define TSBUF_LEN 128

PG_MODULE_MAGIC;

void _PG_init(void);

static bool pgaudit_enabled;

char tsbuf[TSBUF_LEN];

Datum pgaudit_func_ddl_command_end(PG_FUNCTION_ARGS);
Datum pgaudit_func_sql_drop(PG_FUNCTION_ARGS);
static char *make_timestamp(void);

PG_FUNCTION_INFO_V1(pgaudit_func_ddl_command_end);
PG_FUNCTION_INFO_V1(pgaudit_func_sql_drop);

/*
 * A ddl_command_end event trigger to log commands that we can deparse.
 */

Datum
pgaudit_func_ddl_command_end(PG_FUNCTION_ARGS)
{
	EventTriggerData *trigdata;
	int               ret, row;
	TupleDesc		  spi_tupdesc;

	MemoryContext tmpcontext;
	MemoryContext oldcontext;

	const char *query_get_creation_commands =
		"SELECT classid, objid, objsubid, object_type, schema, identity, command"
		"  FROM pg_event_trigger_get_creation_commands()";

	if (!pgaudit_enabled)
		PG_RETURN_NULL();

	if (!CALLED_AS_EVENT_TRIGGER(fcinfo))
		elog(ERROR, "not fired by event trigger manager");

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
 * An sql_drop event trigger to log commands that we can deparse.
 */

Datum
pgaudit_func_sql_drop(PG_FUNCTION_ARGS)
{
	EventTriggerData *trigdata;
	TupleDesc		  spi_tupdesc;
	int               ret, row;

	MemoryContext tmpcontext;
	MemoryContext oldcontext;

	const char *query_dropped_objects =
		"SELECT classid, objid, objsubid, object_type, schema_name, object_name, object_identity"
		"  FROM pg_event_trigger_dropped_objects()";

	if (!pgaudit_enabled)
		PG_RETURN_NULL();

	if (!CALLED_AS_EVENT_TRIGGER(fcinfo))
		elog(ERROR, "not fired by event trigger manager");

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

/* Log authentication events
 *
 * -2/STATUS_EOF: authentication initiated but no credentials supplied
 * -1/STATUS_ERROR: credentials supplied, authentication failed
 *  0/STATUS_OK: credentials supplied, authentication succeeded
 *
 * Note that ClientAuthentication() [libfq/auth.c] sometimes calls
 * 'ereport(FATAL)' before calling the hook, so we can't log all
 * authentication errors here.
 */

static void
log_client_authentication(Port *port, int status)
{
	const char *auth_method = NULL;

	switch(port->hba->auth_method)
	{
		case uaReject:
		case uaImplicitReject:
			auth_method = "reject";
			break;
		case uaTrust:
			auth_method = "trust";
			break;
		case uaIdent:
			auth_method = "ident";
			break;
		case uaPassword:
			auth_method = "password";
			break;
		case uaMD5:
			auth_method = "md5";
			break;
		case uaGSS:
			auth_method = "gss";
			break;
		case uaSSPI:
			auth_method = "sspi";
			break;
		case uaPAM:
			auth_method = "pam";
			break;
		case uaLDAP:
			auth_method = "ldap";
			break;
		case uaCert:
			auth_method = "cert";
			break;
		case uaRADIUS:
			auth_method = "radius";
			break;
		case uaPeer:
			auth_method = "peer";
			break;
		default:
			/* Just in case a new method gets added... */
			auth_method = "unknown";
	}

	/* TODO: can we get the role's OID? It might be useful to
	 * log that (e.g. to help identify roles even if the name
	 * was changed), however at this point in the authentication
	 * process GetUserId() returns 0
	 */

	ereport(LOG, (errmsg("[AUDIT]:LOGIN,%s,%s,%s,%s,%s,%i",
						 make_timestamp(),
						 port->user_name,
						 port->remote_host,
						 auth_method,
						 port->database_name,
						 status)));
}

/*
 * Log DML operations via executor permissions checks.
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

		if (rte->rtekind != RTE_RELATION)
			continue;

		rel = relation_open(rte->relid, NoLock);
		relname = quote_qualified_identifier(get_namespace_name(RelationGetNamespace(rel)),
											 RelationGetRelationName(rel));
		relation_close(rel, NoLock);

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
			/* These statements are not supported by event triggers. */
			supported_stmt = false;
			break;

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

		default:
			/* All other statement types have event trigger support */
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
	 * would see here, so we do nothing for now.
	 */
}

/*
 * Hook functions
 * --------------
 *
 * These functions (which are installed by _PG_init, below) just call
 * pgaudit logging functions before continuing the chain of hooks.
 */

static ClientAuthentication_hook_type next_ClientAuthentication_hook = NULL;
static ExecutorCheckPerms_hook_type next_ExecutorCheckPerms_hook = NULL;
static ProcessUtility_hook_type next_ProcessUtility_hook = NULL;
static object_access_hook_type next_object_access_hook = NULL;

static void
pgaudit_ClientAuthentication_hook(Port *port, int status)
{
	if (pgaudit_enabled)
		log_client_authentication(port, status);

	if (next_ClientAuthentication_hook)
		(*next_ClientAuthentication_hook) (port, status);
}

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

	next_ClientAuthentication_hook = ClientAuthentication_hook;
	ClientAuthentication_hook = pgaudit_ClientAuthentication_hook;

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

static char *make_timestamp(void)
{
	pg_time_t timestamp = (pg_time_t) time(NULL);

	/* XXX Which time should we report, and in what format? */
	pg_strftime(tsbuf, TSBUF_LEN, "%Y-%m-%d %H:%M:%S %Z",
				pg_localtime(&timestamp, log_timezone));

	return tsbuf;
}
