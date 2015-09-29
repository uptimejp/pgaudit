pgaudit
=======

This is the initial version of an auditing module for Postgres.

It collects audit events from various sources and logs them in CSV
format including a timestamp, user information, details of objects
affected (if any), and the fully-qualified command text (whenever
available).

All DDL, DML (including SELECT), and utility commands are supported.
These are categorised as described below, and audit logging for each
group of commands may be enabled or disabled by the superuser. Once
enabled, however, audit logging may not be disabled by a user.

The categories of commands are defined as follows:

	read		Commands that read database objects (SELECT)
	write		DML commands that modify database objects (e.g. INSERT)
	privilege	DCL commands that are related to access privileges
				(e.g. GRANT/REVOKE)
	user		DDL commands that are related to database users
				(e.g. CREATE/DROP/ALTER ROLE)
	definition	User-level DDL commands (e.g. CREATE TABLE)
	config		Administrator-level commands that change the database
				configuration (e.g. CREATE LANGUAGE, CREATE OPERATOR
				CLASS)
	admin		Administrator-level commands that are not configuration
				related (e.g. CLUSTER, VACUUM, REINDEX)
	function	Function execution

This code is released under the PostgreSQL licence, as given at
http://www.postgresql.org/about/licence/

Copyright is novated to the PostgreSQL Global Development Group.

What about log_statement = 'all'?
---------------------------------

1. pgaudit logs fully-qualified names

	A query like «delete from x» in the log file can be interpreted only
	with reference to the current search_path setting. In contrast, this
	module always logs fully-qualified object names, e.g. "public.x".

	For DDL commands that have appropriate event trigger support, we log
	an unambigous representation of the command text, not just the query
	string as supplied by the user.

2. pgaudit creates a log entry for each affected object

	A query that refers to multiple objects results in a log entry for
	each object involved, so the effects of «select * from some_view»
	can be seen rather than inferred. Searching for all accesses to a
	particular table is also straightforward.

3. pgaudit provides finer-grained control over what events are logged

	With log_statement, one may select none, ddl, mod, or all. With
	pgaudit, individual groups of commands may be selected for logging.
	Want to log only GRANT/REVOKE operations? You can.

Installation
------------

The latest pgaudit code is available at
https://github.com/2ndQuadrant/pgaudit

This module will work with Postgres 9.3 and 9.4, but it needs updated event
trigger code in order to log a complete, unambiguous representation of DDL
commands.

We hope that the necessary event trigger code will be available in 9.5,
but until then you will have to build your own Postgres to see pgaudit
at its best. The necessary code is available in the dev/deparse branch of
git://git.postgresql.org/git/2ndquadrant_bdr.git

First, build and install Postgres as usual from the deparse branch. Copy
pgaudit into contrib/pgaudit and edit the Makefile to uncomment the line
that defines "USE_DEPARSE_FUNCTIONS". Then run "make install".

If you want to use it against an earlier version of Postgres, just run
"make USE_PGXS=1 install" in the pgaudit directory.

Once the module is installed, edit postgresql.conf and set:

	shared_preload_libraries = 'pgaudit'

Then start the server and run:

	CREATE EXTENSION pgaudit;

Configuration
-------------

Audit logging is controlled by the pgaudit.log configuration variable,
which may be set to a comma-separated list of tokens identifying what
classes of commands to log. For example,

	pgaudit.log = 'read, write, user'

pgaudit.log may be set to an empty string or "none" to disable logging,
or to any combination of the following logging classes:

	read, write, privilege, user, definition, config, admin, function

These classes are defined above. See the "CLASSES" file for a complete
list of commands corresponding to each logging class.

pgaudit.log may be set in postgresql.conf (to apply globally), or as a
per-database or per-user setting:

	ALTER DATABASE xxx SET pgaudit.log = '…'

or:

	ALTER ROLE xxx SET pgaudit.log = '…'

Log format
----------

We log audit events in CSV format with the following fields:

	[AUDIT],<timestamp>,<database>,<username>,<effective username>,
		<application_name>,<class>,<tag>,<object type>,<object id>,
		<command text>

*class* is the name of a logging class (READ, WRITE, etc.)

*tag* is the command tag (e.g. SELECT)

*object type* is the type of object affected, if any (e.g. TABLE)

*object id* is some way to identify the affected object, usually a
fully-qualified name

*command text* is the full text of the command.

Note that not all fields are always available.

Here are some examples of log output:

	LOG:  [AUDIT],2014-04-30 17:13:55.202854+09,auditdb,ianb,ianb,psql,DEFINITION,CREATE TABLE,TABLE,public.x,CREATE  TABLE  public.x (a pg_catalog.int4   , b pg_catalog.int4   )   WITH (oids=OFF)
	LOG:  [AUDIT],2014-04-30 17:14:06.548923+09,auditdb,ianb,ianb,psql,WRITE,INSERT,TABLE,public.x,INSERT INTO x VALUES(1,1);
	LOG:  [AUDIT],2014-04-30 17:14:21.221879+09,auditdb,ianb,ianb,psql,READ,SELECT,TABLE,public.x,SELECT * FROM x;
	LOG:  [AUDIT],2014-04-30 17:15:25.620213+09,auditdb,ianb,ianb,psql,READ,SELECT,VIEW,public.v_x,SELECT * from v_x;
	LOG:  [AUDIT],2014-04-30 17:15:25.620262+09,auditdb,ianb,ianb,psql,READ,SELECT,TABLE,public.x,SELECT * from v_x;
	LOG:  [AUDIT],2014-04-30 17:16:00.849868+09,auditdb,ianb,ianb,psql,WRITE,UPDATE,TABLE,public.x,UPDATE x SET a=a+1;
	LOG:  [AUDIT],2014-04-30 17:16:18.291452+09,auditdb,ianb,ianb,psql,ADMIN,VACUUM,,,VACUUM x;
	LOG:  [AUDIT],2014-04-30 17:18:01.08291+09,auditdb,ianb,ianb,psql,DEFINITION,CREATE FUNCTION,FUNCTION,public.func_x(),CREATE  FUNCTION public.func_x() RETURNS  pg_catalog.int4 LANGUAGE sql  VOLATILE  CALLED ON NULL INPUT SECURITY INVOKER COST 100.000000   AS $dprs_$SELECT a FROM x LIMIT 1;$dprs_$
	LOG:  [AUDIT],2014-04-30 17:18:09.694755+09,auditdb,ianb,ianb,psql,FUNCTION,EXECUTE,FUNCTION,public.func_x,SELECT * FROM func_x();
	LOG:  [AUDIT],2014-04-30 17:18:09.694865+09,auditdb,ianb,ianb,psql,READ,SELECT,TABLE,public.x,SELECT * FROM func_x();
	LOG:  [AUDIT],2014-04-30 17:18:33.703007+09,auditdb,ianb,ianb,psql,WRITE,DELETE,VIEW,public.v_x,DELETE FROM v_x;
	LOG:  [AUDIT],2014-04-30 17:18:33.703051+09,auditdb,ianb,ianb,psql,WRITE,DELETE,TABLE,public.x,DELETE FROM v_x;
	LOG:  [AUDIT],2014-04-30 17:19:54.811244+09,auditdb,ianb,ianb,psql,ADMIN,SET,,,set role ams;
	LOG:  [AUDIT],2014-04-30 17:19:57.039979+09,auditdb,ianb,ams,psql,WRITE,INSERT,VIEW,public.v_x,INSERT INTO v_x VALUES(1,2);
	LOG:  [AUDIT],2014-04-30 17:19:57.040014+09,auditdb,ianb,ams,psql,WRITE,INSERT,TABLE,public.x,INSERT INTO v_x VALUES(1,2);
	LOG:  [AUDIT],2014-04-30 17:20:02.059415+09,auditdb,ianb,ams,psql,ADMIN,SET,,,SET role ianb;
	LOG:  [AUDIT],2014-04-30 17:20:09.840261+09,auditdb,ianb,ianb,psql,DEFINITION,ALTER TABLE,TABLE,public.x,ALTER TABLE public.x ADD COLUMN c pg_catalog.int4
	LOG:  [AUDIT],2014-04-30 17:23:58.920342+09,auditdb,ianb,ianb,psql,ADMIN,ALTER ROLE,,,ALTER USER ams SET search_path = 'foo';

Design overview
---------------

We collect audit events from event triggers for any operations with
event trigger support. (For some commands, this also gives us the
unambiguous deparsed command representation.) Other DDL and utility
commands are collected by a utility hook, and DML and SELECT events
are collected by an executor hook.

See DESIGN for more details and future improvements.

Known problems
--------------

Statements are audit-logged even if the transaction they're in is later
rolled back. This is sometimes desirable (e.g. with SELECT), but makes
it more difficult to tell what happened.

Some utility statements are audit-logged even though they subsequently
fail (e.g. «set shared_buffers = '32MB'»).

Deparsed query text is not yet available for DROP events.

Some bugs of varying severity in the deparse code have been reported
upstream. Some have been fixed already, but the code is under active
development, and other bugs still await fixes.

Bug reports and other feedback are welcome.

Authors
-------

Ian Barwick <ian@2ndQuadrant.com>

Abhijit Menon-Sen <ams@2ndQuadrant.com>

The research leading to these results has received funding from the
European Union's Seventh Framework Programme (FP7/2007-2013) under
grant agreement n° 318633. http://axleproject.eu
