MODULE_big = edb_stat_statements
OBJS = \
	$(WIN32RES) \
	edb_stat_statements.o

EXTENSION = edb_stat_statements
DATA = edb_stat_statements--1.0.sql
PGFILEDESC = "edb_stat_statements - execution statistics of EdgeDB queries"

LDFLAGS_SL += $(filter -lm, $(LIBS))

PG_CONFIG ?= pg_config

PG_MAJOR = $(shell $(PG_CONFIG) --version | grep -oE '[0-9]+' | head -1)

# Pick the newest of the given PostgreSQL major versions that is not newer
# than the one we build against, to select version-specific expected output.
pg_variant = $(lastword $(firstword $(1)) $(foreach v,$(1),$(if $(shell test $(PG_MAJOR) -ge $(v) && echo y),$(v))))

ifeq ($(call pg_variant,17 18),18)
	REGRESS_EXTENDED = extended
endif

# extended must run before cleanup, which drops the extension
REGRESS = select dml cursors utility level_tracking planning \
	user_activity wal entry_timestamp privileges $(REGRESS_EXTENDED) \
	parallel cleanup oldextversions

TAP_TESTS = 1

all:

expected/cursors.out: expected/cursors.out.$(call pg_variant,17 19) FORCE
	cp $< $@

expected/dml.out: expected/dml.out.$(call pg_variant,17 18) FORCE
	cp $< $@

expected/level_tracking.out: expected/level_tracking.out.$(call pg_variant,17 18 19) FORCE
	cp $< $@

expected/parallel.out: expected/parallel.out.$(call pg_variant,17 18) FORCE
	cp $< $@

expected/utility.out: expected/utility.out.$(call pg_variant,16 17 18 19) FORCE
	cp $< $@

expected/wal.out: expected/wal.out.$(call pg_variant,17 18) FORCE
	cp $< $@

installcheck: \
	expected/cursors.out \
	expected/dml.out \
	expected/level_tracking.out \
	expected/parallel.out \
	expected/utility.out \
	expected/wal.out

# Always recopy, the PostgreSQL version may have changed since the last run.
FORCE:
.PHONY: FORCE

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
