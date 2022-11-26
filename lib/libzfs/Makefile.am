include $(top_srcdir)/config/Rules.am

VPATH = \
	$(top_srcdir)/module/icp \
	$(top_srcdir)/module/zcommon \
	$(top_srcdir)/lib/libzfs

# Suppress unused but set variable warnings often due to ASSERTs
AM_CFLAGS += $(NO_UNUSED_BUT_SET_VARIABLE)
AM_CFLAGS += $(LIBCRYPTO_CFLAGS) $(ZLIB_CFLAGS)
AM_CFLAGS += -fvisibility=hidden

pkgconfig_DATA = libzfs.pc

lib_LTLIBRARIES = libzfs.la

include $(top_srcdir)/config/Abigail.am

USER_C = \
	libzfs_impl.h \
	libzfs_changelist.c \
	libzfs_config.c \
	libzfs_crypto.c \
	libzfs_dataset.c \
	libzfs_diff.c \
	libzfs_import.c \
	libzfs_iter.c \
	libzfs_mount.c \
	libzfs_pool.c \
	libzfs_sendrecv.c \
	libzfs_status.c \
	libzfs_util.c


if BUILD_FREEBSD
USER_C += \
	os/freebsd/libzfs_compat.c \
	os/freebsd/libzfs_zmount.c
endif

if BUILD_LINUX
USER_C += \
	os/linux/libzfs_mount_os.c \
	os/linux/libzfs_pool_os.c \
	os/linux/libzfs_sendrecv_os.c \
	os/linux/libzfs_util_os.c
endif

KERNEL_C = \
	algs/sha2/sha2.c \
	cityhash.c \
	zfeature_common.c \
	zfs_comutil.c \
	zfs_deleg.c \
	zfs_fletcher.c \
	zfs_fletcher_aarch64_neon.c \
	zfs_fletcher_aarch64_neon_unsafe.c \
	zfs_fletcher_avx512.c \
	zfs_fletcher_intel.c \
	zfs_fletcher_intel_comedy.c \
	zfs_fletcher_intel_intrin.c \
	zfs_fletcher_sse.c \
	zfs_fletcher_sse_intrin.c \
	zfs_fletcher_sse_intrin_unsafe.c \
	zfs_fletcher_superscalar.c \
	zfs_fletcher_superscalar4.c \
	zfs_fletcher_superscalar4_simd.c \
	zfs_namecheck.c \
	zfs_prop.c \
	zpool_prop.c \
	zprop_common.c

zfs_fletcher_superscalar4_simd.$(OBJEXT): CFLAGS += -march=native -mtune=native -ffast-math -DSIMD_MOED=1
zfs_fletcher_superscalar4_simd.l$(OBJEXT): CFLAGS += -march=native -mtune=native -ffast-math -DSIMD_MOED=1

zfs_fletcher_sse_intrin_unsafe.$(OBJEXT): CFLAGS += -march=native -mtune=native -ffast-math
zfs_fletcher_sse_intrin_unsafe.l$(OBJEXT): CFLAGS += -march=native -mtune=native -ffast-math

zfs_fletcher_intel_intrin.$(OBJEXT): CFLAGS += -march=native -mtune=native -ffast-math
zfs_fletcher_intel_intrin.l$(OBJEXT): CFLAGS += -march=native -mtune=native -ffast-math

if TARGET_CPU_AARCH64
zfs_fletcher.$(OBJEXT): CFLAGS += -DSIMD_MOED=1 -DHAVE_SSE2 -I/home/rich/simde/simde/x86/ -I/home/rich/simde/simde/ -DSIMDE_ENABLE_NATIVE_ALIASES -DZFS_SSE2_INTRIN
zfs_fletcher.l$(OBJEXT): CFLAGS += -DSIMD_MOED=1 -DHAVE_SSE2 -I/home/rich/simde/simde/x86/ -I/home/rich/simde/simde/ -DSIMDE_ENABLE_NATIVE_ALIASES -DZFS_SSE2_INTRIN
zfs_fletcher_sse_intrin.$(OBJEXT): CFLAGS += -DHAVE_SSE2 -I/home/rich/simde/simde/x86/ -I/home/rich/simde/simde/ -DSIMDE_ENABLE_NATIVE_ALIASES 
zfs_fletcher_sse_intrin.l$(OBJEXT): CFLAGS += -DHAVE_SSE2 -I/home/rich/simde/simde/x86/ -I/home/rich/simde/simde/ -DSIMDE_ENABLE_NATIVE_ALIASES
zfs_fletcher_sse_intrin_unsafe.$(OBJEXT): CFLAGS += -DHAVE_SSE2 -I/home/rich/simde/simde/x86/ -I/home/rich/simde/simde/ -DSIMDE_ENABLE_NATIVE_ALIASES -march=native -mtune=native -ffast-math
zfs_fletcher_sse_intrin_unsafe.l$(OBJEXT): CFLAGS += -DHAVE_SSE2 -I/home/rich/simde/simde/x86/ -I/home/rich/simde/simde/ -DSIMDE_ENABLE_NATIVE_ALIASES -march=native -mtune=native -ffast-math
else
zfs_fletcher.$(OBJEXT): CFLAGS += -DSIMD_MOED=1
zfs_fletcher.l$(OBJEXT): CFLAGS += -DSIMD_MOED=1
endif

dist_libzfs_la_SOURCES = \
	$(USER_C)

nodist_libzfs_la_SOURCES = \
	$(KERNEL_C)

libzfs_la_LIBADD = \
	$(abs_top_builddir)/lib/libshare/libshare.la \
	$(abs_top_builddir)/lib/libzfs_core/libzfs_core.la \
	$(abs_top_builddir)/lib/libnvpair/libnvpair.la \
	$(abs_top_builddir)/lib/libzutil/libzutil.la \
	$(abs_top_builddir)/lib/libuutil/libuutil.la

libzfs_la_LIBADD += -lm $(LIBCRYPTO_LIBS) $(ZLIB_LIBS) $(LIBFETCH_LIBS) $(LTLIBINTL)

libzfs_la_LDFLAGS = -pthread

if !ASAN_ENABLED
libzfs_la_LDFLAGS += -Wl,-z,defs
endif

if BUILD_FREEBSD
libzfs_la_LIBADD += -lutil -lgeom
endif

libzfs_la_LDFLAGS += -version-info 5:0:1

include $(top_srcdir)/config/CppCheck.am

# Library ABI
EXTRA_DIST = libzfs.abi libzfs.suppr

# Licensing data
EXTRA_DIST += THIRDPARTYLICENSE.openssl THIRDPARTYLICENSE.openssl.descrip
