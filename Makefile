# pgaudit/Makefile

# Uncomment the following line if you are building against a server with
# the latest event trigger code (pg_event_trigger_get_creation_commands
# and pg_event_trigger_expand_command). See README for details.

# PG_CPPFLAGS = -DUSE_DEPARSE_FUNCTIONS

MODULE = pgaudit
MODULE_big = pgaudit
OBJS = pgaudit.o

EXTENSION = pgaudit

DATA = pgaudit--1.0.0.sql

ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/pgaudit
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
