# use the following command:
# make PG_CONFIG=$pgdir/bin/pg_config.exe install


MODULE_big = superextension
EXTENSION  = superextension
PGFILEDESC = superextension
DATA = superextension--1.0.sql superextension.control
OBJS = superextension.o
PG_CONFIG = pg_config


PGXS     := $(shell $(PG_CONFIG) --pgxs)
bindir   := $(shell $(PG_CONFIG) --bindir)
include $(PGXS)

