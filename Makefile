# pgaudit/Makefile

MODULES = pgaudit
EXTENSION = pgaudit

DATA = pgaudit--0.1.sql

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)