/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or https://opensource.org/licenses/CDDL-1.0.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */



#include <sys/debug.h>
#include <sys/types.h>
#include <sys/qat.h>
#include <sys/zio_compress.h>

extern size_t zfs_zstd_compress(void *s_start, void *d_start, size_t s_len,
    size_t d_len, int level);

#ifdef _KERNEL

#include <sys/zmod.h>
typedef size_t zlen_t;
#define	compress_func	z_compress_level
#define	uncompress_func	z_uncompress

#else /* _KERNEL */

#include <zlib.h>
typedef uLongf zlen_t;
#define	compress_func	compress2
#define	uncompress_func	uncompress

#endif

enum gzip_levels {
	ZIO_GZIP_LEVEL_1 = 1,
	ZIO_GZIP_LEVEL_2,
	ZIO_GZIP_LEVEL_3,
	ZIO_GZIP_LEVEL_4,
	ZIO_GZIP_LEVEL_5,
	ZIO_GZIP_LEVEL_6,
	ZIO_GZIP_LEVEL_7,
	ZIO_GZIP_LEVEL_8,
	ZIO_GZIP_LEVEL_9,
};

static uint_t gzip_earlyabort_pass = 1;
static uint_t gzip_earlyabort_secondpass = 1;
static uint_t gzip_earlyabort_lz4accel = 1;
static int gzip_cutoff_level = ZIO_GZIP_LEVEL_5;
static unsigned int gzip_abort_size = (128 * 1024);

static kstat_t *gzip_ksp = NULL;

#define	GZIPSTAT(stat)		(gzip_stats.stat.value.ui64)
#define	GZIPSTAT_ZERO(stat)	\
	atomic_store_64(&gzip_stats.stat.value.ui64, 0)
#define	GZIPSTAT_ADD(stat, val) \
	atomic_add_64(&gzip_stats.stat.value.ui64, (val))
#define	GZIPSTAT_SUB(stat, val) \
	atomic_sub_64(&gzip_stats.stat.value.ui64, (val))
#define	GZIPSTAT_BUMP(stat)	GZIPSTAT_ADD(stat, 1)

typedef struct gzip_stats {
	kstat_named_t	gzip_stat_com_inval;
	kstat_named_t	gzip_stat_dec_inval;
	kstat_named_t	gzip_stat_dec_header_inval;
	kstat_named_t	gzip_stat_qatcom_fail;
	kstat_named_t	gzip_stat_qatdec_fail;
	kstat_named_t	gzip_stat_com_fail;
	kstat_named_t	gzip_stat_dec_fail;
	/*
	 * LZ4 first-pass early abort verdict
	 */
	kstat_named_t	gzip_stat_lz4pass_allowed;
	kstat_named_t	gzip_stat_lz4pass_rejected;
	/*
	 * zstd-1 second-pass early abort verdict
	 */
	kstat_named_t	gzip_stat_zstdpass_allowed;
	kstat_named_t	gzip_stat_zstdpass_rejected;
	/*
	 * We excluded this from early abort for some reason
	 */
	kstat_named_t	gzip_stat_passignored;
	kstat_named_t	gzip_stat_passignored_size;
	kstat_named_t	gzip_stat_buffers;
	kstat_named_t	gzip_stat_size;
} gzip_stats_t;

static gzip_stats_t gzip_stats = {
	{ "compress_level_invalid",	KSTAT_DATA_UINT64 },
	{ "decompress_level_invalid",	KSTAT_DATA_UINT64 },
	{ "decompress_header_invalid",	KSTAT_DATA_UINT64 },
	{ "qatcompress_failed",		KSTAT_DATA_UINT64 },
	{ "qatdecompress_failed",	KSTAT_DATA_UINT64 },
	{ "compress_failed",		KSTAT_DATA_UINT64 },
	{ "decompress_failed",		KSTAT_DATA_UINT64 },
	{ "lz4pass_allowed",		KSTAT_DATA_UINT64 },
	{ "lz4pass_rejected",		KSTAT_DATA_UINT64 },
	{ "zstdpass_allowed",		KSTAT_DATA_UINT64 },
	{ "zstdpass_rejected",		KSTAT_DATA_UINT64 },
	{ "passignored",		KSTAT_DATA_UINT64 },
	{ "passignored_size",		KSTAT_DATA_UINT64 },
	{ "buffers",			KSTAT_DATA_UINT64 },
	{ "size",			KSTAT_DATA_UINT64 },
};

#ifdef _KERNEL
static int
kstat_gzip_update(kstat_t *ksp, int rw)
{
	ASSERT(ksp != NULL);

	if (rw == KSTAT_WRITE && ksp == gzip_ksp) {
		GZIPSTAT_ZERO(gzip_stat_com_inval);
		GZIPSTAT_ZERO(gzip_stat_dec_inval);
		GZIPSTAT_ZERO(gzip_stat_dec_header_inval);
		GZIPSTAT_ZERO(gzip_stat_qatcom_fail);
		GZIPSTAT_ZERO(gzip_stat_qatdec_fail);
		GZIPSTAT_ZERO(gzip_stat_com_fail);
		GZIPSTAT_ZERO(gzip_stat_dec_fail);
		GZIPSTAT_ZERO(gzip_stat_lz4pass_allowed);
		GZIPSTAT_ZERO(gzip_stat_lz4pass_rejected);
		GZIPSTAT_ZERO(gzip_stat_zstdpass_allowed);
		GZIPSTAT_ZERO(gzip_stat_zstdpass_rejected);
		GZIPSTAT_ZERO(gzip_stat_passignored);
		GZIPSTAT_ZERO(gzip_stat_passignored_size);
	}

	return (0);
}
#endif

size_t
gzip_compress_wrap(void *s_start, void *d_start, size_t s_len, size_t d_len,
    int level)
{
	
	/*
	 * Go read the early abort explanation in zfs_zstd.c, but s/zstd/gzip/ and
	 * s/level 3/level 5/
	 */
	size_t actual_abort_size = gzip_abort_size;
	if (gzip_earlyabort_pass > 0 && level >= gzip_cutoff_level &&
	    s_len >= actual_abort_size) {
		int pass_len = 1;
		pass_len = lz4_compress_zfs(s_start, d_start, s_len, d_len, gzip_earlyabort_lz4accel);
		if (pass_len < d_len) {
			GZIPSTAT_BUMP(gzip_stat_lz4pass_allowed);
			goto keep_trying;
		}
		GZIPSTAT_BUMP(gzip_stat_lz4pass_rejected);

		if (gzip_earlyabort_secondpass) {
			pass_len = zfs_zstd_compress(s_start, d_start, s_len, d_len,
			    1);
		if (pass_len == s_len || pass_len <= 0 || pass_len > d_len) {
			GZIPSTAT_BUMP(gzip_stat_zstdpass_rejected);
			return (s_len);
		}
		GZIPSTAT_BUMP(gzip_stat_zstdpass_allowed);
		} else {
			return (s_len);
		}
		
	} else {
		GZIPSTAT_BUMP(gzip_stat_passignored);
		if (s_len < actual_abort_size) {
			GZIPSTAT_BUMP(gzip_stat_passignored_size);
		}
	}
keep_trying:
	return (gzip_compress(s_start, d_start, s_len, d_len, level));

}


size_t
gzip_compress(void *s_start, void *d_start, size_t s_len, size_t d_len, int n)
{
	int ret;
	zlen_t dstlen = d_len;

	ASSERT(d_len <= s_len);

	/* check if hardware accelerator can be used */
	if (qat_dc_use_accel(s_len)) {
		ret = qat_compress(QAT_COMPRESS, s_start, s_len, d_start,
		    d_len, &dstlen);
		if (ret == CPA_STATUS_SUCCESS) {
			return ((size_t)dstlen);
		} else if (ret == CPA_STATUS_INCOMPRESSIBLE) {
			if (d_len != s_len)
				return (s_len);

			memcpy(d_start, s_start, s_len);
			return (s_len);
		}
		GZIPSTAT_BUMP(gzip_stat_qatcom_fail);
		/* if hardware compression fails, do it again with software */
	}

	if (compress_func(d_start, &dstlen, s_start, s_len, n) != Z_OK) {
		GZIPSTAT_BUMP(gzip_stat_com_fail);
		if (d_len != s_len)
			return (s_len);

		memcpy(d_start, s_start, s_len);
		return (s_len);
	}

	return ((size_t)dstlen);
}



int
gzip_decompress(void *s_start, void *d_start, size_t s_len, size_t d_len, int n)
{
	(void) n;
	zlen_t dstlen = d_len;

	ASSERT(d_len >= s_len);

	/* check if hardware accelerator can be used */
	if (qat_dc_use_accel(d_len)) {
		if (qat_compress(QAT_DECOMPRESS, s_start, s_len,
		    d_start, d_len, &dstlen) == CPA_STATUS_SUCCESS)
			return (0);
		GZIPSTAT_BUMP(gzip_stat_qatdec_fail);
		/* if hardware de-compress fail, do it again with software */
	}

	if (uncompress_func(d_start, &dstlen, s_start, s_len) != Z_OK) {
		GZIPSTAT_BUMP(gzip_stat_dec_fail);
		return (-1);
	}

	return (0);
}

extern int __init
gzip_init(void)
{
	/* Initialize kstat */
	gzip_ksp = kstat_create("zfs", 0, "gzip", "misc",
	    KSTAT_TYPE_NAMED, sizeof (gzip_stats) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);
	if (gzip_ksp != NULL) {
		gzip_ksp->ks_data = &gzip_stats;
		kstat_install(gzip_ksp);
#ifdef _KERNEL
		gzip_ksp->ks_update = kstat_gzip_update;
#endif
	}

	return (0);
}

extern void
gzip_fini(void)
{
	/* Deinitialize kstat */
	if (gzip_ksp != NULL) {
		kstat_delete(gzip_ksp);
		gzip_ksp = NULL;
	}

}

#if defined(_KERNEL)
#ifdef __FreeBSD__
module_init(gzip_init);
module_exit(gzip_fini);
#endif

ZFS_MODULE_PARAM(zfs, gzip_, earlyabort_pass, UINT, ZMOD_RW,
	"Enable early abort attempts when using gzip");
ZFS_MODULE_PARAM(zfs, gzip_, earlyabort_secondpass, UINT, ZMOD_RW,
	"Enable early abort attempts when using gzip");
ZFS_MODULE_PARAM(zfs, gzip_, earlyabort_lz4accel, UINT, ZMOD_RW,
	"Bees bees bees");
ZFS_MODULE_PARAM(zfs, gzip_, cutoff_level, UINT, ZMOD_RW,
	"Compression level to check against early abort");
ZFS_MODULE_PARAM(zfs, gzip_, abort_size, UINT, ZMOD_RW,
	"Minimal size of block to attempt early abort");
#endif
