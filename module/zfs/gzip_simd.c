/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
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
#include <sys/strings.h>
#include <sys/qat.h>
#include <sys/spa.h>
#include <sys/simd.h>
#include <sys/zio_compress.h>

#if 0
int x86_cpu_enable_simd = 1;
int x86_cpu_enable_sse2 = 1;
int x86_cpu_enable_ssse3 = 1;
#endif

#include "zlib-ng/zlib.h"
typedef uLongf zlen_t;
#define	compress_func	compress2
#define	uncompress_func	uncompress

typedef struct gzip_info {
	size_t nbytes;
	int16_t fromcache;
} gzip_info_t;

extern kmem_cache_t	*zio_data_buf_cache[];

z_const char * const z_errmsg[10] = {
    (z_const char *)"need dictionary",     /* Z_NEED_DICT       2  */
    (z_const char *)"stream end",          /* Z_STREAM_END      1  */
    (z_const char *)"",                    /* Z_OK              0  */
    (z_const char *)"file error",          /* Z_ERRNO         (-1) */
    (z_const char *)"stream error",        /* Z_STREAM_ERROR  (-2) */
    (z_const char *)"data error",          /* Z_DATA_ERROR    (-3) */
    (z_const char *)"insufficient memory", /* Z_MEM_ERROR     (-4) */
    (z_const char *)"buffer error",        /* Z_BUF_ERROR     (-5) */
    (z_const char *)"incompatible version",/* Z_VERSION_ERROR (-6) */
    (z_const char *)""
};

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

			bcopy(s_start, d_start, s_len);
			return (s_len);
		}
		/* if hardware compression fails, do it again with software */
	}
	kfpu_begin();
	if (compress_func(d_start, &dstlen, s_start, s_len, n) != Z_OK) {
		if (d_len != s_len)
			return (s_len);

		bcopy(s_start, d_start, s_len);
		kfpu_end();
		return (s_len);
	}
	kfpu_end();
	return ((size_t)dstlen);
}

int
gzip_decompress(void *s_start, void *d_start, size_t s_len, size_t d_len, int n)
{
	(void) n;
	int ret = 0;
	zlen_t dstlen = d_len;

	ASSERT(d_len >= s_len);

	/* check if hardware accelerator can be used */
	if (qat_dc_use_accel(d_len)) {
		if (qat_compress(QAT_DECOMPRESS, s_start, s_len,
		    d_start, d_len, &dstlen) == CPA_STATUS_SUCCESS)
			return (0);
		/* if hardware de-compress fail, do it again with software */
	}
	kfpu_begin();
	if (uncompress_func(d_start, &dstlen, s_start, s_len) != Z_OK)
		ret = -1;

	kfpu_end();
	return (ret);
}

void* z_zcalloc(void *opaque, int nitems, int sz) {
	uint64_t nbytes = (nitems * sz) + sizeof(gzip_info_t);
	gzip_info_t *ret = NULL;
	if (nbytes <= SPA_MAXBLOCKSIZE) {
		size_t c = (nbytes - 1) >> SPA_MINBLOCKSHIFT;

		VERIFY3U(c, <, SPA_MAXBLOCKSIZE >> SPA_MINBLOCKSHIFT);
		ret = kmem_cache_alloc(zio_data_buf_cache[c], KM_PUSHPAGE);
		if (ret) {
			#if defined(ZFS_DEBUG) && !defined(_KERNEL)
			// if we're using combined bufs, this should increment
			// too...
			if ((zio_buf_cache[c] == zio_data_buf_cache[c]))
				atomic_add_64(&zio_buf_cache_allocs[c], 1);
			#endif
			ret->nbytes = nbytes;
			ret->fromcache = c;
		}
	}
	if (ret == NULL) {
		ret = vmem_zalloc(nbytes, KM_SLEEP);
		if (ret) {
			ret->nbytes = nbytes;
			ret->fromcache = -1;
		}
	}
	if (ret == NULL)
		return (NULL);
//	zfs_dbgmsg("DBG zcalloc: %px %px %llu %d %d", ret, (((uint64_t *)ret)+sizeof(uint64_t)), (u_longlong_t) retsz, nitems, sz);
	return (((uintptr_t)ret)+sizeof(gzip_info_t));
}

void z_zcfree(void *opaque, void *ptr) {
	gzip_info_t *actual_ptr = (ptr - sizeof(gzip_info_t));
	if (actual_ptr->fromcache != -1)
		kmem_cache_free(zio_data_buf_cache[actual_ptr->fromcache], actual_ptr);
	else
		vmem_free(actual_ptr, actual_ptr->nbytes);
}
