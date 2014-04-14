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

#define TSBUF_LEN 128

PG_MODULE_MAGIC;

void _PG_init(void);

/*
 * GUC: pgaudit.enabled = (on|off)
 */
static bool pgaudit_enabled;

char tsbuf[TSBUF_LEN];

Datum pgaudit_func_ddl_command_end(PG_FUNCTION_ARGS);
Datum pgaudit_func_sql_drop(PG_FUNCTION_ARGS);
static char *make_timestamp(void);

PG_FUNCTION_INFO_V1(pgaudit_func_ddl_command_end);
PG_FUNCTION_INFO_V1(pgaudit_func_sql_drop);

Datum
pgaudit_func_ddl_command_end(PG_FUNCTION_ARGS)
{
	EventTriggerData *trigdata;
	StringInfoData	  buf;
	int				  ret;
	int				  proc;
	SPITupleTable	 *spi_tuptable;
	TupleDesc		  spi_tupdesc;
	int				  row;

	MemoryContext tmpcontext;
	MemoryContext oldcontext;

	if(pgaudit_enabled == false)
		PG_RETURN_NULL();

	tmpcontext = AllocSetContextCreate(CurrentMemoryContext,
									   "pgaudit_func_ddl_command_end temporary context",
									   ALLOCSET_DEFAULT_MINSIZE,
									   ALLOCSET_DEFAULT_INITSIZE,
									   ALLOCSET_DEFAULT_MAXSIZE);
	oldcontext = MemoryContextSwitchTo(tmpcontext);

	if (!CALLED_AS_EVENT_TRIGGER(fcinfo))  /* internal error */
		elog(ERROR, "not fired by event trigger manager");

	trigdata = (EventTriggerData *) fcinfo->context;

	/* Connect to SPI manager */
	if ((ret = SPI_connect()) < 0)
		/* internal error */
		elog(ERROR, "pgaudit_func_ddl_command_end: SPI_connect returned %d", ret);


	initStringInfo(&buf);
	appendStringInfo(
		&buf,
		"SELECT classid, objid, objsubid, object_type, schema, identity, command"\
		"  FROM pg_event_trigger_get_creation_commands()"
		);

	/* XXX check return value */
	ret = SPI_execute(buf.data, true, 0);
	proc = SPI_processed;

	/* XXX Not sure if this should ever happen */
	if(proc == 0)
	{
		SPI_finish();
		MemoryContextSwitchTo(oldcontext);
		MemoryContextDelete(tmpcontext);
		PG_RETURN_NULL();
	}

	spi_tuptable = SPI_tuptable;
	spi_tupdesc = spi_tuptable->tupdesc;

	for (row = 0; row < proc; row++)
	{
		HeapTuple  spi_tuple;
		char	  *command_text;
		char	  *command_formatted;
		Datum	   json;
		Datum	   command;
		bool	   isnull;

		spi_tuple = spi_tuptable->vals[row];

		ereport(LOG,
				(errmsg(
					"%s,%s,%s,%s,%s",
					make_timestamp(),
					GetUserNameFromId(GetSessionUserId()),
					GetUserNameFromId(GetUserId()),
					SPI_getvalue(spi_tuple, spi_tupdesc, 4),
					trigdata->tag
					),
				 errhidestmt(true)
					)
			);

		json = SPI_getbinval(spi_tuple, spi_tupdesc, 7, &isnull);

		command_formatted = SPI_getvalue(spi_tuple, spi_tupdesc, 7);
		ereport(LOG,
				(errmsg("%s", command_formatted),
				 errhidestmt(true)
					)
			);

		command = DirectFunctionCall1(pg_event_trigger_expand_command,
									  json);

		command_text = TextDatumGetCString(command);
		ereport(LOG,
				(errmsg("%s", command_text),
				 errhidestmt(true)
					)
			);

	}

	SPI_finish();
	MemoryContextSwitchTo(oldcontext);
	MemoryContextDelete(tmpcontext);
	PG_RETURN_NULL();
}


Datum
pgaudit_func_sql_drop(PG_FUNCTION_ARGS)
{
	EventTriggerData *trigdata;
	SPITupleTable	 *spi_tuptable;
	TupleDesc		  spi_tupdesc;
	int               ret, row, proc;

	const char *query_dropped_objects =
		"SELECT classid, objid, objsubid, object_type, schema_name, object_name, object_identity" \
		"  FROM pg_event_trigger_dropped_objects()";

	if(pgaudit_enabled == false)
		PG_RETURN_NULL();

	elog(DEBUG1, "pgaudit_func_sql_drop");

	trigdata = (EventTriggerData *) fcinfo->context;

	/* Connect to SPI manager */
	if ((ret = SPI_connect()) < 0)
		/* internal error */
		elog(ERROR, "pgaudit_func_sql_drop: SPI_connect returned %d", ret);

	/* XXX check return value */
	ret = SPI_execute(query_dropped_objects, true, 0);
	proc = SPI_processed;

	/* XXX Not sure if this should ever happen */
	if(proc == 0)
	{
		elog(DEBUG1, "pgaudit_func_sql_drop() spi err");
		SPI_finish();
		PG_RETURN_NULL();
	}

	spi_tuptable = SPI_tuptable;
	spi_tupdesc = spi_tuptable->tupdesc;

	for (row = 0; row < proc; row++)
	{
		HeapTuple  spi_tuple;

		elog(INFO, "row %i", row);
		spi_tuple = spi_tuptable->vals[row];

		ereport(LOG,
				(errmsg(
					"%s,%s,%s,%s,%s",
					make_timestamp(),
					GetUserNameFromId(GetSessionUserId()),
					GetUserNameFromId(GetUserId()),
					SPI_getvalue(spi_tuple, spi_tupdesc, 7),
					trigdata->tag
					),
				 errhidestmt(true)
					)
			);

	}

	SPI_finish();
	PG_RETURN_NULL();
}


/* Quick'n'dirty timestamp generation */

static char *make_timestamp(void)
{

	pg_time_t timestamp = (pg_time_t) time(NULL);

	/* XXX what time / output format do we want?
	   I.e. do we want to report the report time, or the
	   statement timestamp, etc.?
	 */
	pg_strftime(tsbuf, TSBUF_LEN, "%Y-%m-%d %H:%M:%S %Z",
				pg_localtime(&timestamp, log_timezone));

	return tsbuf;
}


static ExecutorCheckPerms_hook_type next_exec_check_perms_hook = NULL;
static ProcessUtility_hook_type next_ProcessUtility_hook = NULL;
static ClientAuthentication_hook_type next_client_auth_hook = NULL;
static object_access_hook_type next_object_access_hook = NULL;



static void
pgaudit_object_access(ObjectAccessType access,
					  Oid classId,
					  Oid objectId,
					  int subId,
					  void *arg)
{
	if (next_object_access_hook)
		(*next_object_access_hook) (access, classId, objectId, subId, arg);
}

static bool
pgaudit_exec_check_perms(List *rangeTabls, bool abort)
{
	if (next_exec_check_perms_hook &&
		!(*next_exec_check_perms_hook) (rangeTabls, abort))
		return false;

	return true;
}


/* Log authentication events
 *
 * Notes:
 *  - for some authentication types, ClientAuthentication() [libfq/auth.c]
 *    issues an 'ereport(FATAL)' before the hook is called, meaning
 *    certain authentication errors in some circumstances can't be handled here
 *  - status = -2 [STATUS_EOF]: authentication initiated but no credentials supplied
 *  - status = -1 [STATUS_ERROR]: credentials supplied, authentication failed
 *  - status =  0 [STATUS_OK]: credentials supplied, authentication succeeded
 */

static void
pgaudit_client_auth(Port *port, int status)
{
	const char *auth_method = NULL;

	if(pgaudit_enabled == false)
	{
		if (next_client_auth_hook)
			(*next_client_auth_hook) (port, status);
		return;
	}

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
	}

	ereport(LOG,
			(errmsg(
				"%s,%s,%s,%s,%i",
				port->user_name,
				port->remote_host,
				auth_method,
				port->database_name,
				status
				)
				)
		);
}


/* Log utility commands which cannot handled by event triggers,
 * particularly those which affect global objects
 */

static void
pgaudit_utility_command(Node *parsetree,
						const char *queryString,
						ProcessUtilityContext context,
						ParamListInfo params,
						DestReceiver *dest,
						char *completionTag)
{
	bool audit_command = false;

	if(pgaudit_enabled == false)
	{
		PG_TRY();
		{
			if (next_ProcessUtility_hook)
				(*next_ProcessUtility_hook) (parsetree, queryString,
											 context, params,
											 dest, completionTag);
			else
				standard_ProcessUtility(parsetree, queryString,
										context, params,
										dest, completionTag);
		}
		PG_CATCH();
		{
			PG_RE_THROW();
		}
		PG_END_TRY();
		return;
	}

	switch (nodeTag(parsetree))
	{
		case T_GrantStmt:
		case T_GrantRoleStmt:
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
			audit_command = true;
			break;

			/*
			 * The following statements are supported by Event Triggers only
			 * in some cases
			 */

		case T_DropStmt:
			{
				DropStmt   *stmt = (DropStmt *) parsetree;

				if (!EventTriggerSupportsObjectType(stmt->removeType))
					audit_command = true;
			}
			break;
		case T_RenameStmt:
			{
				RenameStmt *stmt = (RenameStmt *) parsetree;

				if (!EventTriggerSupportsObjectType(stmt->renameType))
					audit_command = true;
			}
		case T_AlterObjectSchemaStmt:
			{
				AlterObjectSchemaStmt *stmt = (AlterObjectSchemaStmt *) parsetree;

				if (!EventTriggerSupportsObjectType(stmt->objectType))
					audit_command = true;
			}
		case T_AlterOwnerStmt:
			{
				AlterOwnerStmt *stmt = (AlterOwnerStmt *) parsetree;

				if (!EventTriggerSupportsObjectType(stmt->objectType))
					audit_command = true;
			}
			break;
		default:
			elog(DEBUG1, "Not handling node type: %d",
					 (int) nodeTag(parsetree));
				break;
	}

	if(audit_command == true)
		ereport(LOG,
				(errmsg(
					"pgaudit_utility_command(): %s,%s,%s,%s",
					make_timestamp(),
					GetUserNameFromId(GetSessionUserId()),
					GetUserNameFromId(GetUserId()),
					queryString
					),
				 errhidestmt(true)
					)
			);

	PG_TRY();
	{
		if (next_ProcessUtility_hook)
			(*next_ProcessUtility_hook) (parsetree, queryString,
										 context, params,
										 dest, completionTag);
		else
			standard_ProcessUtility(parsetree, queryString,
									context, params,
									dest, completionTag);
	}
	PG_CATCH();
	{
		PG_RE_THROW();
	}
	PG_END_TRY();
}


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

	next_client_auth_hook = ClientAuthentication_hook;
	ClientAuthentication_hook = pgaudit_client_auth;

	next_object_access_hook = object_access_hook;
	object_access_hook = pgaudit_object_access;

	next_exec_check_perms_hook = ExecutorCheckPerms_hook;
	ExecutorCheckPerms_hook = pgaudit_exec_check_perms;

	next_ProcessUtility_hook = ProcessUtility_hook;
	ProcessUtility_hook = pgaudit_utility_command;
}
