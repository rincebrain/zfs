include $(top_srcdir)/config/Rules.am

AM_CFLAGS += -Wno-error

sbin_PROGRAMS = clonefile

clonefile_SOURCES = clonefile.c

clonefile_LDADD = \
	$(abs_top_builddir)/lib/libzfs/libzfs.la \
	$(abs_top_builddir)/lib/libzfs_core/libzfs_core.la \
	$(abs_top_builddir)/lib/libnvpair/libnvpair.la


#zdb_LDADD

include $(top_srcdir)/config/CppCheck.am
