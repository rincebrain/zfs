clonefile_CPPFLAGS = $(AM_CPPFLAGS) -Wno-error
clonefile_CFLAGS = $(AM_CFLAGS) -Wno-error

sbin_PROGRAMS += clonefile

clonefile_SOURCES = %D%/clonefile.c

clonefile_LDADD = \
	libzpool.la \
	libzfs_core.la \
	libnvpair.la


#zdb_LDADD

