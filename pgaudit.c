/*-------------------------------------------------------------------------
 *
 * pgaudit.c
 *		  experimental auditing extension
 *
 * Configuration:
 *   pgaudit.enabled = (on|off)
 *
 * Output:
 *   Logged audit events are currently dumped to the default log file
 *   in an adhoc, pseudo-CSV format prefixed with '[AUDIT]:'.
 *
 *   [AUDIT]:event,timestamp,user,effective_user,object_identity,object_type,trigger_tag,command_text
 *   [AUDIT]:LOGIN,timestamp,user_name,remote_host,auth_method,database_name,status
 *
 *   Example:
 *   [AUDIT]:DDL_CREATE,2014-04-17 15:39:21 JST,ibarwick,ibarwick,public.foo,table,CREATE TABLE,CREATE  TABLE  public.foo (id pg_catalog.int4   )   WITH (oids=OFF)
 *
 *   'event' is one of:
 *      - DDL_CREATE: CREATE or ALTER DDL event
 *      - DDL_DROP:   DROP event
 *      - STMT_OTHER: command not handled by an event trigger
 *      - LOGIN:      user authentication
 *
 *   !! the current output format is very arbitrary and subject to change !!
 *
 * Caveats:
 *   - deparsed query text only available for 'DDL_CREATE' events
 *   - currently 'ALTER TABLE ... DROP ...' is logged both as 'DDL_CREATE' and 'DDL_DROP'
 *
 *-------------------------------------------------------------------------
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

#define TSBUF_LEN 128

PG_MODULE_MAGIC;

void _PG_init(void);

static ClientAuthentication_hook_type next_ClientAuthentication_hook = NULL;
static ExecutorCheckPerms_hook_type next_ExecutorCheckPerms_hook = NULL;
static ProcessUtility_hook_type next_ProcessUtility_hook = NULL;
static object_access_hook_type next_object_access_hook = NULL;

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
	int               ret, row, proc;
	SPITupleTable	 *spi_tuptable;
	TupleDesc		  spi_tupdesc;

	MemoryContext tmpcontext;
	MemoryContext oldcontext;

	const char *query_get_creation_commands = \
		"SELECT classid, objid, objsubid, object_type, schema, identity, command" \
		"  FROM pg_event_trigger_get_creation_commands()";

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


	/* XXX check return value */
	ret = SPI_execute(query_get_creation_commands, true, 0);
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


		/* Temporarily dump the raw JSON rendering for debugging */
		command_formatted = SPI_getvalue(spi_tuple, spi_tupdesc, 7);

		ereport(DEBUG1,
				(errmsg("%s", command_formatted),
				 errhidestmt(true)
					)
			);

		json = SPI_getbinval(spi_tuple, spi_tupdesc, 7, &isnull);
		command = DirectFunctionCall1(pg_event_trigger_expand_command,
									  json);

		command_text = TextDatumGetCString(command);

		ereport(LOG,
				(errmsg(
					"[AUDIT]:DDL_CREATE,%s,%s,%s,%s,%s,%s,%s",
					make_timestamp(),
					GetUserNameFromId(GetSessionUserId()),
					GetUserNameFromId(GetUserId()),
					SPI_getvalue(spi_tuple, spi_tupdesc, 6), /* object identity */
					SPI_getvalue(spi_tuple, spi_tupdesc, 4), /* object type */
					trigdata->tag,
					command_text
					),
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

	MemoryContext tmpcontext;
	MemoryContext oldcontext;

	const char *query_dropped_objects =
		"SELECT classid, objid, objsubid, object_type, schema_name, object_name, object_identity" \
		"  FROM pg_event_trigger_dropped_objects()";

	if(pgaudit_enabled == false)
		PG_RETURN_NULL();

	tmpcontext = AllocSetContextCreate(CurrentMemoryContext,
									   "pgaudit_func_sql_drop temporary context",
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
		elog(ERROR, "pgaudit_func_sql_drop: SPI_connect returned %d", ret);

	/* XXX check return value */
	ret = SPI_execute(query_dropped_objects, true, 0);
	proc = SPI_processed;

	/* XXX Not sure if this should ever happen */
	if(proc == 0)
	{
		elog(DEBUG1, "pgaudit_func_sql_drop(): SPI error");
		MemoryContextSwitchTo(oldcontext);
		MemoryContextDelete(tmpcontext);
		SPI_finish();
		PG_RETURN_NULL();
	}

	spi_tuptable = SPI_tuptable;
	spi_tupdesc = spi_tuptable->tupdesc;

	for (row = 0; row < proc; row++)
	{
		HeapTuple  spi_tuple;

		spi_tuple = spi_tuptable->vals[row];

		ereport(LOG,
				(errmsg(
					"[AUDIT]:DDL_DROP,%s,%s,%s,%s,%s,%s,",
					make_timestamp(),
					GetUserNameFromId(GetSessionUserId()),
					GetUserNameFromId(GetUserId()),
					SPI_getvalue(spi_tuple, spi_tupdesc, 7), /* object identity */
					SPI_getvalue(spi_tuple, spi_tupdesc, 4), /* object type */
					trigdata->tag
					),
				 errhidestmt(true)
					)
			);

	}

	SPI_finish();
	MemoryContextSwitchTo(oldcontext);
	MemoryContextDelete(tmpcontext);
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
 * Log object accesses.
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
 * Log executor permissions checks.
 */

static void
log_executor_check_perms(List *rangeTabls, bool abort)
{
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
	ObjectType objType;

	/*
	 * If both the statement type and its object type are supported by
	 * event triggers, then we don't need to log anything. Otherwise,
	 * we log the query string.
	 */

	switch (nodeTag(parsetree)) {
		case T_DropStmt:
			{
				DropStmt *stmt = (DropStmt *) parsetree;
				objType = stmt->removeType;
			}
			break;

		case T_RenameStmt:
			{
				RenameStmt *stmt = (RenameStmt *) parsetree;
				objType = stmt->renameType;
			}
			break;

		case T_AlterObjectSchemaStmt:
			{
				AlterObjectSchemaStmt *stmt = (AlterObjectSchemaStmt *) parsetree;
				objType = stmt->objectType;
			}
			break;

		case T_AlterOwnerStmt:
			{
				AlterOwnerStmt *stmt = (AlterOwnerStmt *) parsetree;
				objType = stmt->objectType;
			}
			break;

		default:
			supported_stmt = false;
			break;
	}

	if (supported_stmt && EventTriggerSupportsObjectType(objType))
		return;

	ereport(LOG, (errmsg("[AUDIT]:STMT_OTHER,%s,%s,%s,other,,%s,",
	 					 make_timestamp(),
		 				 GetUserNameFromId(GetSessionUserId()),
			 			 GetUserNameFromId(GetUserId()),
				 		 queryString),
				  errhidestmt(true)));
}

/*
 * Hook functions
 * --------------
 *
 * These functions (which are installed by _PG_init, below) just call
 * pgaudit logging functions before continuing the chain of hooks.
 */

static void
pgaudit_ClientAuthentication_hook(Port *port, int status)
{
	if (pgaudit_enabled)
		log_client_authentication(port, status);

	if (next_ClientAuthentication_hook)
		(*next_ClientAuthentication_hook) (port, status);
}

static void
pgaudit_object_access_hook(ObjectAccessType access,
						   Oid classId,
						   Oid objectId,
						   int subId,
						   void *arg)
{
	if (pgaudit_enabled)
		log_object_access(access, classId, objectId, subId, arg);

	if (next_object_access_hook)
		(*next_object_access_hook) (access, classId, objectId, subId, arg);
}

static bool
pgaudit_ExecutorCheckPerms_hook(List *rangeTabls, bool abort)
{
	if (pgaudit_enabled)
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
	if (pgaudit_enabled)
		log_utility_command(parsetree, queryString, context,
							params, dest, completionTag);

	if (next_ProcessUtility_hook)
		(*next_ProcessUtility_hook) (parsetree, queryString, context,
									 params, dest, completionTag);
	else
		standard_ProcessUtility(parsetree, queryString, context,
								params, dest, completionTag);
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
