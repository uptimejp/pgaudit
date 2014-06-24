/* pgaudit/pgaudit--1.0.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pgaudit" to load this file.\quit



CREATE FUNCTION pgaudit_func_ddl_command_end()
  RETURNS event_trigger
  LANGUAGE C
AS 'MODULE_PATHNAME', 'pgaudit_func_ddl_command_end';


CREATE EVENT TRIGGER pgaudit_trg_ddl_command_end
  ON ddl_command_end
  EXECUTE PROCEDURE pgaudit_func_ddl_command_end();



CREATE FUNCTION pgaudit_func_sql_drop()
  RETURNS event_trigger
  LANGUAGE C
AS 'MODULE_PATHNAME', 'pgaudit_func_sql_drop';

CREATE EVENT TRIGGER pgaudit_trg_sql_drop
  ON sql_drop
  EXECUTE PROCEDURE pgaudit_func_sql_drop();
