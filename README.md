pgaudit
=======

This is an experimental auditing module for Postgres. It depends on
event triggers, and can log DDL and DML (including read-only access
to tables via SELECT).

Installation
------------

The latest pgaudit code is available at
https://github.com/2ndQuadrant/pgaudit

It depends on the latest unreleased event trigger code available in the
deparse branch of git://git.postgresql.org/git/2ndquadrant_bdr.git

The easiest way to install pgaudit is to copy it into contrib/pgaudit in
the checked-out deparse source tree. Build Postgres as usual, then:

	cd contrib/pgaudit && make install

Enabling the module is slightly cumbersome. First,

	CREATE EXTENSION pgaudit;

Then, edit postgresql.conf and set the following:

	shared_preload_libraries = 'pgaudit'
	pgaudit.enabled = on

Auditing will then be globally enabled once the server is restarted. In
future, there will be more fine-grained control over what is audited,
and when. For the moment, there's only a big red switch.

Here's an example of some log output:

[AUDIT]:DDL,2014-04-17 15:39:21 JST,ibarwick,ibarwick,public.foo,table,CREATE TABLE,CREATE  TABLE  public.foo (id pg_catalog.int4   )   WITH (oids=OFF)

The log format is still fairly arbitrary and subject to change.

[AUDIT]:event,timestamp,user,effective_user,object_identity,object_type,trigger_tag,command_text
[AUDIT]:LOGIN,timestamp,user_name,remote_host,auth_method,database_name,status

'event' is 'DDL', 'DML', 'STMT_OTHER' (for utility commands not handled
by event triggers), or 'LOGIN'.

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
