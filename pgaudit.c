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

Datum pgaudit_func_ddl_command_end(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(pgaudit_func_ddl_command_end);
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

	char			  tsbuf[TSBUF_LEN];
	pg_time_t timestamp = (pg_time_t) time(NULL);

	MemoryContext tmpcontext;
	MemoryContext oldcontext;

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

	/* XXX what time / output format do we want?
	   I.e. do we want to report the report time, or the
	   statement timestamp, etc.?
	 */
	pg_strftime(tsbuf, TSBUF_LEN, "%Y-%m-%d %H:%M:%S %Z",
				pg_localtime(&timestamp, log_timezone));

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
					tsbuf,
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

static ExecutorCheckPerms_hook_type next_exec_check_perms_hook = NULL;
static ProcessUtility_hook_type next_ProcessUtility_hook = NULL;
static ClientAuthentication_hook_type next_client_auth_hook = NULL;
static object_access_hook_type next_object_access_hook = NULL;

/*
 * GUC: pgaudit.enabled = (on|off)
 */
static bool pgaudit_enabled;

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

static void
pgaudit_client_auth(Port *port, int status)
{
	if (next_client_auth_hook)
		(*next_client_auth_hook) (port, status);
}

static void
pgaudit_utility_command(Node *parsetree,
						const char *queryString,
						ProcessUtilityContext context,
						ParamListInfo params,
						DestReceiver *dest,
						char *completionTag)
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
