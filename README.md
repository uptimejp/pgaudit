pgaudit
=======

This is the initial version of an auditing module for Postgres. It
depends on event triggers, and can log DDL and DML (including read-only
access to tables via SELECT).

Installation
------------

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

Now you can set pgaudit.enabled = on in postgresql.conf and reload.
Auditing will then be globally enabled.

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

LOG:  [AUDIT],2014-04-25 22:27:09.167245+05:30,ams,ams,UTIL,,,,show pgaudit.enabled;
LOG:  [AUDIT],2014-04-25 22:27:23.658128+05:30,ams,ams,DML,SELECT,TABLE,pg_catalog.pg_class,
LOG:  [AUDIT],2014-04-25 22:27:23.658189+05:30,ams,ams,DML,SELECT,TABLE,pg_catalog.pg_namespace,
LOG:  [AUDIT],2014-04-25 22:27:41.149732+05:30,ams,ams,DDL,CREATE TABLE,table,public.a,CREATE  TABLE  public.a (a pg_catalog.int4   , b pg_catalog.text   COLLATE pg_catalog."default")   WITH (oids=OFF) 
LOG:  [AUDIT],2014-04-25 22:27:41.163687+05:30,ams,ams,DML,INSERT,TABLE,public.a,

Design overview
---------------

This extension uses event triggers for any commands that support them,
and a utility hook for other commands. DML is logged via an executor
hook, and login events via a client authentication hook.

See DESIGN for more.

Known problems
--------------

Deparsed query text is only available for CREATE, not DROP.

'ALTER TABLE … DROP …' is logged twice (as a CREATE, then a DROP).

Bug reports and other feedback are welcome.

Authors
-------
Ian Barwick <ian@2ndQuadrant.com>
Abhijit Menon-Sen <ams@2ndQuadrant.com>

The research leading to these results has received funding from the
European Union's Seventh Framework Programme (FP7/2007-2013) under
grant agreement n° 318633. http://axleproject.eu
