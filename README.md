pgaudit
=======

Experimental auditing module based on event triggers.

Requires the deparse branch.

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
 *   [AUDIT]:DDL,2014-04-17 15:39:21 JST,ibarwick,ibarwick,public.foo,table,CREATE TABLE,CREATE  TABLE  public.foo (id pg_catalog.int4   )   WITH (oids=OFF)
 *
 *   'event' is one of:
 *      - DDL:        DDL event
 *      - DML:        DML event
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
