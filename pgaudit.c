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

#include "access/htup_details.h"
#include "access/sysattr.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/objectaccess.h"
#include "catalog/pg_class.h"
#include "catalog/pg_proc.h"
#include "commands/dbcommands.h"
#include "commands/event_trigger.h"
#include "executor/executor.h"
#include "executor/spi.h"
#include "libpq/auth.h"
#include "miscadmin.h"
#include "nodes/nodes.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/syscache.h"
#include "utils/timestamp.h"

PG_MODULE_MAGIC;

void _PG_init(void);

Datum pgaudit_func_ddl_command_end(PG_FUNCTION_ARGS);
Datum pgaudit_func_sql_drop(PG_FUNCTION_ARGS);

PG_FUNCTION_INFO_V1(pgaudit_func_ddl_command_end);
PG_FUNCTION_INFO_V1(pgaudit_func_sql_drop);

/*
 * pgaudit_roles_str is the string value of the pgaudit.roles
 * configuration variable, which is a list of role names.
 */

char *pgaudit_roles_str = NULL;

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

	/* Function execution */
	LOG_FUNCTION = (1 << 7),

	/* Absolutely everything; not available via pgaudit.log */
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
	uint32 es_processed;
	bool granted;
} AuditEvent;

#define ES_Processed_Invalid (-1)

static AuditEvent previous_event;

/*
 * Returns the oid of the hardcoded "audit" role.
 */

static Oid
audit_role_oid()
{
	HeapTuple roleTup;
	Oid oid = InvalidOid;

	roleTup = SearchSysCache1(AUTHNAME, PointerGetDatum("audit"));
	if (HeapTupleIsValid(roleTup)) {
		oid = HeapTupleGetOid(roleTup);
		ReleaseSysCache(roleTup);
	}

	return oid;
}

/* Returns true if either pgaudit.roles or pgaudit.log is set. */

static inline bool
pgaudit_configured()
{
	return (pgaudit_roles_str && *pgaudit_roles_str) || pgaudit_log != 0;
}

/*
 * Takes a role OID and returns true if the role is mentioned in
 * pgaudit.roles or if it inherits from a role mentioned therein;
 * returns false otherwise.
 */

static bool
role_is_audited(Oid roleid)
{
	List *roles;
	ListCell *lt;

	if (!pgaudit_roles_str || !*pgaudit_roles_str)
		return false;

	if (!SplitIdentifierString(pgaudit_roles_str, ',', &roles))
		return false;

	foreach(lt, roles)
	{
		char *name = (char *)lfirst(lt);
		HeapTuple roleTup;

		roleTup = SearchSysCache1(AUTHNAME, PointerGetDatum(name));
		if (HeapTupleIsValid(roleTup))
		{
			Oid parentrole = HeapTupleGetOid(roleTup);

			ReleaseSysCache(roleTup);
			if (is_member_of_role_nosuper(roleid, parentrole))
				return true;
		}
	}

	return false;
}

/*
 * Takes a role OID and an AuditEvent and returns true or false
 * depending on whether the event should be logged according to the
 * pgaudit.roles/log settings. If it returns true, it also fills in the
 * name of the LogClass which it is to be logged under.
 */

static bool
should_be_logged(Oid userid, AuditEvent *e, const char **classname)
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
		case T_RefreshMatViewStmt:
		case T_CreateForeignTableStmt:
		case T_CompositeTypeStmt:
			name = "DEFINITION";
			class = LOG_DEFINITION;
			break;

		case T_CreatePLangStmt:
		case T_CreateConversionStmt:
		case T_CreateCastStmt:
		case T_CreateOpClassStmt:
		case T_CreateOpFamilyStmt:
		case T_AlterOpFamilyStmt:
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
		case T_SecLabelStmt:
		case T_CreateExtensionStmt:
		case T_AlterExtensionStmt:
		case T_AlterExtensionContentsStmt:
		case T_CreateEventTrigStmt:
		case T_AlterEventTrigStmt:
#if PG_VERSION_NUM >= 90400
		case T_AlterTableMoveAllStmt:
		case T_AlterSystemStmt:
#endif
			name = "ADMIN";
			class = LOG_ADMIN;
			break;

		case T_ExecuteStmt:
			name = "FUNCTION";
			class = LOG_FUNCTION;
			break;

			/*
			 * Anything that's left out of the list above is just noise,
			 * and not very interesting from an auditing perspective. So
			 * there's intentionally no way to enable LOG_ALL.
			 */

		default:
			name = "UNKNOWN";
			class = LOG_ALL;
			break;
	}

	*classname = name;

	/*
	 * We log audit events under the following conditions:
	 *
	 * 1. If the audit role has been explicitly granted permission for
	 *    an operation.
	 */

	if (e->granted)
		return true;

	/* 2. If the current user is covered by pgaudit.roles. */
	if (role_is_audited(userid))
		return true;

	/* 3. If the event belongs to a class covered by pgaudit.log. */
	if ((pgaudit_log & class) != class)
		return false;

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
	Oid userid;
	const char *timestamp;
	const char *database;
	const char *username;
	const char *eusername;
	const char *classname;

	userid = GetSessionUserId();

	if (!should_be_logged(userid, e, &classname))
		return;

	timestamp = timestamptz_to_str(GetCurrentTimestamp());
	database = get_database_name(MyDatabaseId);

#if PG_VERSION_NUM >= 90500 && !defined(USE_DEPARSE_FUNCTIONS)
	username = GetUserNameFromId(userid, true);
	eusername = GetUserNameFromId(GetUserId(), true);
#else
	username = GetUserNameFromId(userid);
	eusername = GetUserNameFromId(GetUserId());
#endif
	/*
	 * XXX We only support logging via ereport(). In future, we may log
	 * to a separate file or a table.
	 */

	if (e->es_processed == ES_Processed_Invalid)
		ereport(LOG,
				(errmsg("AUDIT,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s",
						timestamp, database,
						username, eusername, application_name, classname,
						e->command_tag, e->object_type, e->object_id,
						e->command_text),
				 errhidestmt(true)));
	else
		ereport(LOG,
				(errmsg("AUDIT,%s,%s,%s,%s,%s,%s,%s,%s,%d,%s",
						timestamp, database,
						username, eusername, application_name, classname,
						e->command_tag, e->object_type,
						e->es_processed,
						e->command_text),
				 errhidestmt(true)));
}

#if PG_VERSION_NUM >= 90500 && !defined(USE_DEPARSE_FUNCTIONS)
/* This code is adapted from ExecCheckRTEPermsModified */
static bool
check_perms_modified(Oid relOid, Oid userid, Bitmapset *modifiedCols,
					AclMode requiredPerms)
{
int			col = -1;

	/*
	 * When the query doesn't explicitly update any columns, allow the query
	 * if we have permission on any column of the rel.  This is to handle
	 * SELECT FOR UPDATE as well as possible corner cases in UPDATE.
	 */
	if (bms_is_empty(modifiedCols))
	{
		if (pg_attribute_aclcheck_all(relOid, userid, requiredPerms,
									  ACLMASK_ANY) != ACLCHECK_OK)
			return false;
	}

	while ((col = bms_next_member(modifiedCols, col)) >= 0)
	{
		/* bit #s are offset by FirstLowInvalidHeapAttributeNumber */
		AttrNumber	attno = col + FirstLowInvalidHeapAttributeNumber;

		if (attno == InvalidAttrNumber)
		{
			/* whole-row reference can't happen here */
			elog(ERROR, "whole-row update is not implemented");
		}
		else
		{
			if (pg_attribute_aclcheck(relOid, attno, userid,
									  requiredPerms) != ACLCHECK_OK)
				return false;
		}
	}
	return true;

}
#endif

/*
 * Create AuditEvents for DML operations via executor permissions
 * checks. We create an AuditEvent for each table in the list of
 * RangeTableEntries from the query.
 */

static void
log_executor_check_perms(Oid auditOid, List *rangeTabls, bool abort_on_violation)
{
	ListCell *lr;

	foreach(lr, rangeTabls)
	{
		Oid relOid;
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

		/*
		 * Get the fully-qualified name of the relation.
		 *
		 * User queries against catalog tables (e.g. "\dt") are logged
		 * here. Should we filter them out, as we do for functions in
		 * pg_catalog?
		 */

		relOid = rte->relid;
		rel = relation_open(relOid, NoLock);
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

		e.type = type;
		e.object_id = relname;
		e.object_type = reltype;
		e.command_tag = tag;
		if (debug_query_string)
			e.command_text = debug_query_string;
		else
			e.command_text = "";
		e.granted = false;

		/*
		 * If a role named "audit" exists, we check if it has been
		 * granted permission to perform the operation identified above.
		 * If so, we must log the event regardless of the static pgaudit
		 * settings.
		 */

		if (auditOid != InvalidOid)
		{
			AclMode		relPerms;
			AclMode		remainingPerms;

			relPerms = pg_class_aclmask(relOid, auditOid,
										rte->requiredPerms, ACLMASK_ALL);

			remainingPerms = rte->requiredPerms & ~relPerms;
			if (remainingPerms == 0)
				e.granted = true;

			/*
			 * If the audit role doesn't have the necessary permissions
			 * on the relation, but could have the required permissions
			 * through column-level grants, we check rte->selectedCols
			 * and rte->modifiedCols to make sure.
			 */

			else if ((remainingPerms & ~(ACL_SELECT | ACL_INSERT | ACL_UPDATE)) == 0)
			{
				AttrNumber col;
				Bitmapset *tmpset;

				/* This code is adapted from ExecCheckRTEPerms */

				if (remainingPerms & ACL_SELECT)
				{
					if (bms_is_empty(rte->selectedCols))
					{
						if (pg_attribute_aclcheck_all(relOid, auditOid, ACL_SELECT,
													  ACLMASK_ANY) == ACLCHECK_OK)
							e.granted = true;
					}

					tmpset = bms_copy(rte->selectedCols);
					while ((col = bms_first_member(tmpset)) >= 0)
					{
						col += FirstLowInvalidHeapAttributeNumber;

						if (col == InvalidAttrNumber)
						{
							if (pg_attribute_aclcheck_all(relOid, auditOid, ACL_SELECT,
														  ACLMASK_ALL) == ACLCHECK_OK)
								e.granted = true;
						}
						else
						{
							if (pg_attribute_aclcheck(relOid, col, auditOid,
													  ACL_SELECT) == ACLCHECK_OK)
								e.granted = true;
						}
					}
					bms_free(tmpset);
				}

#if PG_VERSION_NUM >= 90500 && !defined(USE_DEPARSE_FUNCTIONS)
				if (remainingPerms & ACL_INSERT && !check_perms_modified(relOid,
																		 auditOid,
																		 rte->insertedCols,
																		 ACL_INSERT))
				{
					e.granted = true;
				}

				if (remainingPerms & ACL_UPDATE && !check_perms_modified(relOid,
																		 auditOid,
																		 rte->updatedCols,
																		 ACL_UPDATE))
				{
					e.granted = true;
				}
#else
				remainingPerms &= ~ACL_SELECT;
				if (remainingPerms != 0)
				{
					if (bms_is_empty(rte->modifiedCols))
					{
						if (pg_attribute_aclcheck_all(relOid, auditOid,
													  remainingPerms,
													  ACLMASK_ANY) != ACLCHECK_OK)
							e.granted = true;
					}

					tmpset = bms_copy(rte->modifiedCols);
					while ((col = bms_first_member(tmpset)) >= 0)
					{
						col += FirstLowInvalidHeapAttributeNumber;

						if (col != InvalidAttrNumber)
						{
							if (pg_attribute_aclcheck(relOid, col, auditOid,
													  remainingPerms) == ACLCHECK_OK)
								e.granted = true;
						}
					}
					bms_free(tmpset);
				}
#endif
			}
		}

		e.es_processed = ES_Processed_Invalid;
		log_audit_event(&e);
		previous_event = e;

		pfree(relname);
	}
}

/*
 * Create AuditEvents for utility commands that are not supported by
 * event triggers, particularly those which affect global objects.
 *
 * Exactly what commands are supported by event triggers depends on the
 * version of Postgres in use. In versions 9.3 and 9.4, we can use only
 * the sql_drop event trigger, because our ddl_command_end trigger needs
 * pg_event_trigger_{get_creation_commands,expand_command}. Therefore we
 * must handle all DDL commands other than DROP here.
 *
 * In 9.5 (as represented by the latest deparse branch), we can use the
 * ddl_command_end trigger, which handles CREATE/ALTER for a variety of
 * objects. Therefore we can skip those cases.
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

		case T_DoStmt:
		case T_CreateTableSpaceStmt:
		case T_DropTableSpaceStmt:
		case T_AlterTableSpaceOptionsStmt:
		case T_TruncateStmt:
		case T_CommentStmt:
		case T_SecLabelStmt:
		case T_GrantStmt:
		case T_GrantRoleStmt:
		case T_CreatedbStmt:
		case T_AlterDatabaseStmt:
		case T_AlterDatabaseSetStmt:
		case T_DropdbStmt:
		case T_LoadStmt:
		case T_ClusterStmt:
		case T_VacuumStmt:
		case T_ExplainStmt:
		case T_VariableSetStmt:
		case T_DiscardStmt:
		case T_CreateEventTrigStmt:
		case T_AlterEventTrigStmt:
		case T_CreateRoleStmt:
		case T_AlterRoleStmt:
		case T_AlterRoleSetStmt:
		case T_DropRoleStmt:
		case T_ReassignOwnedStmt:
		case T_LockStmt:
		case T_CheckPointStmt:
		case T_ReindexStmt:
#if PG_VERSION_NUM >= 90400
		case T_AlterTableMoveAllStmt:
		case T_AlterSystemStmt:
#endif

		/*
		 * The following statements are supported only by the
		 * ddl_command_end event trigger. (This list is from
		 * ProcessUtilitySlow.)
		 */

#ifndef USE_DEPARSE_FUNCTIONS
		case T_CreateSchemaStmt:
		case T_AlterDomainStmt:
		case T_DefineStmt:
		case T_CreateExtensionStmt:
		case T_AlterExtensionStmt:
		case T_AlterExtensionContentsStmt:
		case T_CreateFdwStmt:
		case T_AlterFdwStmt:
		case T_CreateForeignServerStmt:
		case T_AlterForeignServerStmt:
		case T_CreateUserMappingStmt:
		case T_AlterUserMappingStmt:
		case T_DropUserMappingStmt:
		case T_CreateEnumStmt:
		case T_CreateRangeStmt:
		case T_AlterEnumStmt:
		case T_CreateFunctionStmt:
		case T_AlterFunctionStmt:
		case T_RuleStmt:
		case T_CreateTrigStmt:
		case T_CreatePLangStmt:
		case T_CreateDomainStmt:
		case T_CreateConversionStmt:
		case T_CreateCastStmt:
		case T_CreateOpClassStmt:
		case T_CreateOpFamilyStmt:
		case T_AlterOpFamilyStmt:
		case T_AlterTSDictionaryStmt:
		case T_AlterTSConfigurationStmt:
		case T_RenameStmt:
		case T_AlterOwnerStmt:
		case T_DropOwnedStmt:
		case T_AlterDefaultPrivilegesStmt:
#endif
			supported_stmt = false;
			break;

#ifndef USE_DEPARSE_FUNCTIONS
		/*
		 * Exclude any ALTER <object> SET SCHEMA statements which
		 * will be handled by log_object_access() in 9.3 and 9.4
		 */
		case  T_AlterObjectSchemaStmt:
			{
				AlterObjectSchemaStmt *stmt = (AlterObjectSchemaStmt *) parsetree;
				switch(stmt->objectType)
				{
					case OBJECT_FOREIGN_TABLE:
					case OBJECT_INDEX:
					case OBJECT_MATVIEW:
					case OBJECT_SEQUENCE:
					case OBJECT_TABLE:
					case OBJECT_TYPE:
					case OBJECT_VIEW:
						break;
					default:
						supported_stmt = false;
				}
			}
			break;
#endif

		/*
		 * The following statements are supported by event triggers for
		 * certain object types. We can always use DROP support, but the
		 * others are dependent on the ddl_command_end trigger.
		 */

		case T_DropStmt:
			{
				DropStmt   *stmt = (DropStmt *) parsetree;

				if (!EventTriggerSupportsObjectType(stmt->removeType))
					supported_stmt = false;
			}
			break;

#ifdef USE_DEPARSE_FUNCTIONS
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
#endif

		/*
		 * All other statement types have event trigger support, or we
		 * don't care about them at all.
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
	e.granted = false;

	e.es_processed = ES_Processed_Invalid;
	log_audit_event(&e);
	previous_event = e;
}

/*
 * Create AuditEvents for certain kinds of CREATE and ALTER statements,
 * as detected by log_object_access() in lieu of event trigger support
 * for them.
 */

#ifndef USE_DEPARSE_FUNCTIONS
static void
log_create_or_alter(bool create,
					Oid classId,
					Oid objectId,
					int subId)
{
	AuditEvent e;
	NodeTag type;
	const char *tag;
	const char *name;
	const char *objtype;

	switch (classId)
	{
		case RelationRelationId:
			{
				Relation rel;
				Form_pg_class class;
				char *relnsp;
				char *relname;

				rel = relation_open(objectId, NoLock);
				class = RelationGetForm(rel);
				relnsp = get_namespace_name(RelationGetNamespace(rel));
				relname = RelationGetRelationName(rel);
				name = quote_qualified_identifier(relnsp, relname);

				switch (class->relkind)
				{
					case RELKIND_RELATION:
						objtype = "TABLE";
						type = create ? T_CreateStmt : T_AlterTableStmt;
						tag = create ? "CREATE TABLE" : "ALTER TABLE";
						break;

					case RELKIND_INDEX:
						objtype = "INDEX";
						type = T_IndexStmt;
						tag = create ? "CREATE INDEX" : "ALTER INDEX";
						break;

					case RELKIND_SEQUENCE:
						objtype = "SEQUENCE";
						type = create ? T_CreateStmt : T_AlterSeqStmt;
						tag = create ? "CREATE SEQUENCE" : "ALTER SEQUENCE";
						break;

					case RELKIND_VIEW:
						objtype = "VIEW";
						/* T_ViewStmt covers both CREATE and ALTER */
						type = T_ViewStmt;
						tag = create ? "CREATE VIEW" : "ALTER VIEW";
						break;

					case RELKIND_COMPOSITE_TYPE:
						objtype = "TYPE";
						/* T_CompositeTypeStmt covers both CREATE and ALTER */
						type = T_CompositeTypeStmt;
						tag = create ? "CREATE TYPE" : "ALTER TYPE";
						break;

					case RELKIND_FOREIGN_TABLE:
						objtype = "FOREIGN TABLE";
						/* There is no T_AlterForeignTableStmt */
						type = T_CreateForeignTableStmt;
						tag = create ? "CREATE FOREIGN TABLE" : "ALTER FOREIGN TABLE";
						break;

					case RELKIND_MATVIEW:
						objtype = "MATERIALIZED VIEW";
						/* Pretend that materialized views are a kind of table */
						type = create ? T_CreateStmt : T_AlterTableStmt;
						tag = create ? "CREATE MATERIALIZED VIEW" : "ALTER MATERIALIZED VIEW";
						break;

					/*
					 * XXX Are there any other RELKIND_xxx cases that we
					 * need to handle here?
					 */

					default:
						objtype = "UNKNOWN";
						type = T_Invalid;
						tag = "";
						break;
				}

				relation_close(rel, NoLock);
			}
			break;

		/*
		 * We leave it to the ProcessUtility_hook to handle all other
		 * commands. There's not much we can do to improve on "create
		 * database foo", for example.
		 */

		default:
			return;
			break;
	}

	e.type = type;
	e.object_id = name;
	e.object_type = objtype;
	e.command_tag = tag;
	if (debug_query_string)
		e.command_text = debug_query_string;
	else
		e.command_text = "";
	e.granted = false;

	e.es_processed = ES_Processed_Invalid;
	log_audit_event(&e);
	previous_event = e;
}
#endif

/*
 * Create AuditEvents for non-catalog function execution, as detected by
 * log_object_access() below.
 */

static void
log_function_execution(Oid objectId)
{
	HeapTuple proctup;
	Form_pg_proc proc;
	const char *name;
	AuditEvent e;

	proctup = SearchSysCache1(PROCOID, ObjectIdGetDatum(objectId));
	if (!proctup)
		elog(ERROR, "cache lookup failed for function %u", objectId);
	proc = (Form_pg_proc) GETSTRUCT(proctup);

	/*
	 * Logging execution of all pg_catalog functions would
	 * make the log unusably noisy.
	 */

	if (IsSystemNamespace(proc->pronamespace))
	{
		ReleaseSysCache(proctup);
		return;
	}

	name = quote_qualified_identifier(get_namespace_name(proc->pronamespace),
									  NameStr(proc->proname));
	ReleaseSysCache(proctup);

	e.type = T_ExecuteStmt;
	e.object_id = name;
	e.object_type = "FUNCTION";
	e.command_tag = "EXECUTE";
	if (debug_query_string)
		e.command_text = debug_query_string;
	else
		e.command_text = "";
	e.granted = false;

	e.es_processed = ES_Processed_Invalid;
	log_audit_event(&e);
	previous_event = e;
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
	switch (access)
	{
		case OAT_FUNCTION_EXECUTE:
			log_function_execution(objectId);
			break;

		/*
		 * We use OAT_POST_{CREATE,ALTER} only to provide limited
		 * support for certain CREATE/ALTER commands in the absence of
		 * usable event trigger support.
		 */

#ifndef USE_DEPARSE_FUNCTIONS
		case OAT_POST_CREATE:
			{
				ObjectAccessPostCreate *pc = arg;

				if (pc->is_internal)
					return;

				log_create_or_alter(access == OAT_POST_CREATE, classId,
									objectId, subId);
			}
			break;

		case OAT_POST_ALTER:
			{
				ObjectAccessPostAlter *pa = arg;

				if (pa->is_internal)
					return;

				log_create_or_alter(access == OAT_POST_CREATE, classId,
									objectId, subId);
			}
			break;
#endif

		default:
		case OAT_DROP:
		case OAT_NAMESPACE_SEARCH:
			/* Not relevant to our purposes. */
			break;
	}
}

/*
 * Event trigger functions
 */

/*
 * A ddl_command_end event trigger to build AuditEvents for commands
 * that we can deparse. This function is called at the end of any DDL
 * command that has event trigger support.
 */

Datum
pgaudit_func_ddl_command_end(PG_FUNCTION_ARGS)
{
#ifdef USE_DEPARSE_FUNCTIONS

	EventTriggerData *trigdata;
	int               ret, row;
	TupleDesc		  spi_tupdesc;
	const char		 *query_get_creation_commands;

	MemoryContext tmpcontext;
	MemoryContext oldcontext;

	if (!pgaudit_configured())
		PG_RETURN_NULL();

	if (!CALLED_AS_EVENT_TRIGGER(fcinfo))
		elog(ERROR, "not fired by event trigger manager");

	/*
	 * This query returns the objects affected by the DDL, and a JSON
	 * representation of the parsed command. We use SPI to execute it,
	 * and compose one AuditEvent per object in the results.
	 */

	/*
	 * XXX 'identity' and 'schema' will be changed to 'object_identity'
	 * and 'schema_name' in an upcoming change to the deparse branch,
	 * for consistency with the existing 'pg_event_trigger_dropped_objects()'
	 * function
	 */
	query_get_creation_commands =
		"SELECT classid, objid, objsubid, UPPER(object_type), schema,"
		" identity, command"
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
		e.granted = false;

		e.es_processed = ES_Processed_Invalid;
		log_audit_event(&e);
		previous_event = e;
	}

	SPI_finish();
	MemoryContextSwitchTo(oldcontext);
	MemoryContextDelete(tmpcontext);
#endif

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

	if (!pgaudit_configured())
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
		"SELECT classid, objid, objsubid, UPPER(object_type), schema_name, "
		" object_name, object_identity"
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
		e.granted = false;

		e.es_processed = ES_Processed_Invalid;
		log_audit_event(&e);
		previous_event = e;
	}

	SPI_finish();
	MemoryContextSwitchTo(oldcontext);
	MemoryContextDelete(tmpcontext);
	PG_RETURN_NULL();
}

/*
 * Hook functions
 * --------------
 *
 * These functions (which are installed by _PG_init, below) just call
 * pgaudit logging functions before continuing the chain of hooks. We
 * must not call any logging functions from an aborted transaction.
 */

static ExecutorEnd_hook_type next_ExecutorEnd_hook= NULL;
static ExecutorCheckPerms_hook_type next_ExecutorCheckPerms_hook = NULL;
static ProcessUtility_hook_type next_ProcessUtility_hook = NULL;
static object_access_hook_type next_object_access_hook = NULL;

static void
pgaudit_ExecutorEnd_hook(QueryDesc *queryDesc)
{
	elog(LOG, "pgaudit_ExecutorEnd_hook");

	previous_event.es_processed = queryDesc->estate->es_processed;
	log_audit_event(&previous_event);

	if (next_ExecutorEnd_hook)
	{
		(*next_ExecutorEnd_hook) (queryDesc);
	}
	else
	{
		standard_ExecutorEnd(queryDesc);
	}
}

static bool
pgaudit_ExecutorCheckPerms_hook(List *rangeTabls, bool abort)
{
	Oid auditOid = audit_role_oid();

	if (!IsAbortedTransactionBlockState() &&
		(auditOid != InvalidOid || pgaudit_configured()))
		log_executor_check_perms(auditOid, rangeTabls, abort);

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
	if (!IsAbortedTransactionBlockState() && pgaudit_configured())
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
	if (!IsAbortedTransactionBlockState() && pgaudit_configured())
		log_object_access(access, classId, objectId, subId, arg);

	if (next_object_access_hook)
		(*next_object_access_hook) (access, classId, objectId, subId, arg);
}

/*
 * Take a pgaudit.roles value such as "role1, role2" and verify that
 * the string consists of comma-separated tokens.
 */

static bool
check_pgaudit_roles(char **newval, void **extra, GucSource source)
{
	List *roles;
	char *rawval;

	/* Make sure we have a comma-separated list of tokens. */

	rawval = pstrdup(*newval);
	if (!SplitIdentifierString(rawval, ',', &roles))
	{
		GUC_check_errdetail("List syntax is invalid");
		list_free(roles);
		pfree(rawval);
		return false;
	}
	pfree(rawval);

	return true;
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
		else if (pg_strcasecmp(token, "function") == 0)
			*f |= LOG_FUNCTION;
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
	 * pgaudit.roles = "role1, role2"
	 *
	 * This variable defines a list of roles for which auditing is
	 * enabled.
	 */

	DefineCustomStringVariable("pgaudit.roles",
							   "Enable auditing for certain roles",
							   NULL,
							   &pgaudit_roles_str,
							   "",
							   PGC_SUSET,
							   GUC_LIST_INPUT | GUC_NOT_IN_SAMPLE,
							   check_pgaudit_roles,
							   NULL, NULL);

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

	next_ExecutorEnd_hook = ExecutorEnd_hook;
	ExecutorEnd_hook = pgaudit_ExecutorEnd_hook;

	next_ExecutorCheckPerms_hook = ExecutorCheckPerms_hook;
	ExecutorCheckPerms_hook = pgaudit_ExecutorCheckPerms_hook;

	next_ProcessUtility_hook = ProcessUtility_hook;
	ProcessUtility_hook = pgaudit_ProcessUtility_hook;

	next_object_access_hook = object_access_hook;
	object_access_hook = pgaudit_object_access_hook;
}
