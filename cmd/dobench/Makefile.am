include $(top_srcdir)/config/Rules.am
include $(top_srcdir)/config/Shellcheck.am

AM_CFLAGS += $(LIBBLKID_CFLAGS) $(LIBUUID_CFLAGS)

DEFAULT_INCLUDES += -I$(srcdir)

SHELLCHECK_OPTS = --enable=all

sbin_PROGRAMS = dobench

dobench_SOURCES = \
	dobench.c

dobench_LDADD = \
	$(abs_top_builddir)/lib/libzfs/libzfs.la \
	$(abs_top_builddir)/lib/libzfs_core/libzfs_core.la \
	$(abs_top_builddir)/lib/libnvpair/libnvpair.la \
	$(abs_top_builddir)/lib/libuutil/libuutil.la \
	$(abs_top_builddir)/lib/libzutil/libzutil.la \
	$(abs_top_builddir)/lib/libzpool/libzpool.la

dobench_LDADD += $(LTLIBINTL)

if BUILD_FREEBSD
dobench_LDADD += -lgeom
endif
dobench_LDADD += -lm $(LIBBLKID_LIBS) $(LIBUUID_LIBS)

include $(top_srcdir)/config/CppCheck.am

