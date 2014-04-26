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
enabled, however, audit logging may not be disabled.

What about log_statement = 'all'?
---------------------------------

1. pgaudit logs fully-qualified names

A query like «delete from x» in the log file can be interpreted only
with reference to the current search_path setting. In contrast, this
module always logs fully-qualified object names, e.g. "public.x".

For DDL commands that have appropriate event trigger support, we log an
unambigous representation of the command text, not just the query string
as supplied by the user.

2. pgaudit creates a log entry for each affected object

A query that refers to multiple objects results in a log entry for each
object involved, so the effects of «select * from some_view» can be seen
rather than inferred. Searching for all accesses to a particular table
is also straightforward.

3. pgaudit provides finer-grained control over what events are logged

With log_statement, one may select none, ddl, mod, or all. With pgaudit,
individual groups of commands may be selected for logging. Want to log
only GRANT/REVOKE operations? You can.

4. pgaudit cannot be turned off

…pending…

On the other hand, pgaudit does not currently log the names or values of
columns read or written by a query, nor does it have access to the query
text. (But see "Future improvements" below.)

Installation
------------

(Note: for the moment, using pgaudit means building your own Postgres.
If you are not already comfortable with this procedure, this extension
is not yet ready for your use. We apologise for the inconvenience.)

The latest pgaudit code is available at
https://github.com/2ndQuadrant/pgaudit

It depends on the latest unreleased event trigger code available in the
deparse branch of git://git.postgresql.org/git/2ndquadrant_bdr.git

The easiest way to install pgaudit is to copy it into contrib/pgaudit in
the checked-out deparse source tree. Build Postgres as usual, then:

	cd contrib/pgaudit && make install

Edit postgresql.conf and set:

	shared_preload_libraries = 'pgaudit'

Then start the server and run:

	CREATE EXTENSION pgaudit;

Configuration
-------------

…pending…

Log format
----------

We log audit events in CSV format with the following fields:

	[AUDIT],<timestamp>,<username>,<effective username>,
		<event>,<tag>,<object type>,<object id>,
		<command text>

<event> is DDL, DML, or UTIL.

<tag> is the command tag (e.g. SELECT)

<object type> is the type of object affected, if any (e.g. TABLE)

<object id> is some way to identify the affected object, usually a
fully-qualified name

<command text> is the full text of the command.

Note that not all fields are always available.

Here are some examples of log output:

LOG:  [AUDIT],2014-04-25 22:27:23.658128+05:30,ams,ams,DML,SELECT,TABLE,pg_catalog.pg_class,
LOG:  [AUDIT],2014-04-25 22:27:23.658189+05:30,ams,ams,DML,SELECT,TABLE,pg_catalog.pg_namespace,
LOG:  [AUDIT],2014-04-25 22:27:41.149732+05:30,ams,ams,DDL,CREATE TABLE,table,public.a,CREATE  TABLE  public.a (a pg_catalog.int4   , b pg_catalog.text   COLLATE pg_catalog."default")   WITH (oids=OFF) 
LOG:  [AUDIT],2014-04-25 22:27:41.163687+05:30,ams,ams,DML,INSERT,TABLE,public.a,

Design overview
---------------

We collect audit events from event triggers for any operations with
event trigger support. (For some commands, this also gives us the
unambiguous deparsed command representation.) Other DDL and utility
commands are collected by a utility hook, and DML and SELECT events
are collected by an executor hook.

See DESIGN for more details.

Known problems
--------------

Statements are audit-logged even if the transaction they're in is later
rolled back. This is sometimes desirable (e.g. with SELECT), but makes
it more difficult to tell what happened.

Some utility statements are audit-logged even though they subsequently
fail (e.g. «set shared_buffers = '32MB'»).

Deparsed query text is only available for CREATE, not DROP.

'ALTER TABLE … DROP …' is logged twice (as a CREATE, then a DROP).

Some bugs of varying severity in the deparse code have been reported
upstream. Some have been fixed already, but the code is under active
development, and other bugs still await fixes.

Future improvements
-------------------

The only audit log target currently available is the server logfile. We
plan to support other log targets in future.

It is possible to display the list of column names read or written by a
query in the executor hook.

At the moment, the code depends on the latest unreleased event triggers
code. It may be possible to provide a subset of the auditing features
without using event triggers.

It is possible to get column values for DML statements using a logical
decoding output plugin. With row-level security, it may even be possible
to record query results seen by a particular user.

We also hope to allow per-object auditing configuration someday.

Bug reports and other feedback are welcome.

Authors
-------
Ian Barwick <ian@2ndQuadrant.com>
Abhijit Menon-Sen <ams@2ndQuadrant.com>

The research leading to these results has received funding from the
European Union's Seventh Framework Programme (FP7/2007-2013) under
grant agreement n° 318633. http://axleproject.eu
