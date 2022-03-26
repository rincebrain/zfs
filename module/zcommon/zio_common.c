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

#include <sys/types.h>
#include <sys/zio.h>

#ifndef _KERNEL
/* set with ZFS_DEBUG=watch, to enable watchpoints on frozen buffers */
extern boolean_t arc_watch;
#endif

#ifdef ZFS_DEBUG
static const int zio_buf_debug_limit = 16384;
#else
static const int zio_buf_debug_limit = 0;
#endif

/*
 * Enable smaller cores by excluding metadata
 * allocations as well.
 */
int zio_exclude_metadata = 0;

static int zio_inited = 0;

kmem_cache_t *zio_cache;
kmem_cache_t *zio_link_cache;
kmem_cache_t *zio_buf_cache[SPA_MAXBLOCKSIZE >> SPA_MINBLOCKSHIFT];
kmem_cache_t *zio_data_buf_cache[SPA_MAXBLOCKSIZE >> SPA_MINBLOCKSHIFT];
#if defined(ZFS_DEBUG) && !defined(_KERNEL)
uint64_t zio_buf_cache_allocs[SPA_MAXBLOCKSIZE >> SPA_MINBLOCKSHIFT];
uint64_t zio_buf_cache_frees[SPA_MAXBLOCKSIZE >> SPA_MINBLOCKSHIFT];
#endif

void
zio_data_init(void) {
//	dprintf("DBG: Did I run, pa?\n");
	if (!zio_inited) {
	zio_inited = 1;
	size_t c;

	zio_cache = kmem_cache_create("zio_cache",
	    sizeof (zio_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
	zio_link_cache = kmem_cache_create("zio_link_cache",
	    sizeof (zio_link_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	/*
	 * For small buffers, we want a cache for each multiple of
	 * SPA_MINBLOCKSIZE.  For larger buffers, we want a cache
	 * for each quarter-power of 2.
	 */
	for (c = 0; c < SPA_MAXBLOCKSIZE >> SPA_MINBLOCKSHIFT; c++) {
		size_t size = (c + 1) << SPA_MINBLOCKSHIFT;
		size_t p2 = size;
		size_t align = 0;
		size_t data_cflags, cflags;

		data_cflags = KMC_NODEBUG;
		cflags = (zio_exclude_metadata || size > zio_buf_debug_limit) ?
		    KMC_NODEBUG : 0;

#if defined(_ILP32) && defined(_KERNEL)
		/*
		 * Cache size limited to 1M on 32-bit platforms until ARC
		 * buffers no longer require virtual address space.
		 */
		if (size > zfs_max_recordsize)
			break;
#endif

		while (!ISP2(p2))
			p2 &= p2 - 1;

#ifndef _KERNEL
		/*
		 * If we are using watchpoints, put each buffer on its own page,
		 * to eliminate the performance overhead of trapping to the
		 * kernel when modifying a non-watched buffer that shares the
		 * page with a watched buffer.
		 */
		if (arc_watch && !IS_P2ALIGNED(size, PAGESIZE))
			continue;
		/*
		 * Here's the problem - on 4K native devices in userland on
		 * Linux using O_DIRECT, buffers must be 4K aligned or I/O
		 * will fail with EINVAL, causing zdb (and others) to coredump.
		 * Since userland probably doesn't need optimized buffer caches,
		 * we just force 4K alignment on everything.
		 */
		align = 8 * SPA_MINBLOCKSIZE;
#else
		if (size < PAGESIZE) {
			align = SPA_MINBLOCKSIZE;
		} else if (IS_P2ALIGNED(size, p2 >> 2)) {
			align = PAGESIZE;
		}
#endif

		if (align != 0) {
			char name[36];
			if (cflags == data_cflags) {
				/*
				 * Resulting kmem caches would be identical.
				 * Save memory by creating only one.
				 */
				(void) snprintf(name, sizeof (name),
				    "zio_buf_comb_%lu", (ulong_t)size);
				zio_buf_cache[c] = kmem_cache_create(name,
				    size, align, NULL, NULL, NULL, NULL, NULL,
				    cflags);
				zio_data_buf_cache[c] = zio_buf_cache[c];
				continue;
			}
			(void) snprintf(name, sizeof (name), "zio_buf_%lu",
			    (ulong_t)size);
			zio_buf_cache[c] = kmem_cache_create(name, size,
			    align, NULL, NULL, NULL, NULL, NULL, cflags);

			(void) snprintf(name, sizeof (name), "zio_data_buf_%lu",
			    (ulong_t)size);
			zio_data_buf_cache[c] = kmem_cache_create(name, size,
			    align, NULL, NULL, NULL, NULL, NULL, data_cflags);
		}
	}

	while (--c != 0) {
		ASSERT(zio_buf_cache[c] != NULL);
		if (zio_buf_cache[c - 1] == NULL)
			zio_buf_cache[c - 1] = zio_buf_cache[c];

		ASSERT(zio_data_buf_cache[c] != NULL);
		if (zio_data_buf_cache[c - 1] == NULL)
			zio_data_buf_cache[c - 1] = zio_data_buf_cache[c];
	}
	}

}
void
zio_data_fini(void) {
//	dprintf("DBG: Yeah I did, pa!\n");
	if (zio_inited == 1) {
	zio_inited = 2;
	size_t n = SPA_MAXBLOCKSIZE >> SPA_MINBLOCKSHIFT;

#if defined(ZFS_DEBUG) && !defined(_KERNEL)
	for (size_t i = 0; i < n; i++) {
		if (zio_buf_cache_allocs[i] != zio_buf_cache_frees[i])
			(void) printf("zio_fini: [%d] %llu != %llu\n",
			    (int)((i + 1) << SPA_MINBLOCKSHIFT),
			    (long long unsigned)zio_buf_cache_allocs[i],
			    (long long unsigned)zio_buf_cache_frees[i]);
	}
#endif

	/*
	 * The same kmem cache can show up multiple times in both zio_buf_cache
	 * and zio_data_buf_cache. Do a wasteful but trivially correct scan to
	 * sort it out.
	 */
	for (size_t i = 0; i < n; i++) {
		kmem_cache_t *cache = zio_buf_cache[i];
		if (cache == NULL)
			continue;
		for (size_t j = i; j < n; j++) {
			if (cache == zio_buf_cache[j])
				zio_buf_cache[j] = NULL;
			if (cache == zio_data_buf_cache[j])
				zio_data_buf_cache[j] = NULL;
		}
		kmem_cache_destroy(cache);
	}

	for (size_t i = 0; i < n; i++) {
		kmem_cache_t *cache = zio_data_buf_cache[i];
		if (cache == NULL)
			continue;
		for (size_t j = i; j < n; j++) {
			if (cache == zio_data_buf_cache[j])
				zio_data_buf_cache[j] = NULL;
		}
		kmem_cache_destroy(cache);
	}

	for (size_t i = 0; i < n; i++) {
		VERIFY3P(zio_buf_cache[i], ==, NULL);
		VERIFY3P(zio_data_buf_cache[i], ==, NULL);
	}

	kmem_cache_destroy(zio_link_cache);
	kmem_cache_destroy(zio_cache);
	zio_inited = 0;
	}

}

/*
 * ==========================================================================
 * Allocate and free I/O buffers
 * ==========================================================================
 */

/*
 * Use zio_buf_alloc to allocate ZFS metadata.  This data will appear in a
 * crashdump if the kernel panics, so use it judiciously.  Obviously, it's
 * useful to inspect ZFS metadata, but if possible, we should avoid keeping
 * excess / transient data in-core during a crashdump.
 */
void *
zio_buf_alloc(size_t size)
{
	size_t c = (size - 1) >> SPA_MINBLOCKSHIFT;

	VERIFY3U(c, <, SPA_MAXBLOCKSIZE >> SPA_MINBLOCKSHIFT);
#if defined(ZFS_DEBUG) && !defined(_KERNEL)
	atomic_add_64(&zio_buf_cache_allocs[c], 1);
#endif

	return (kmem_cache_alloc(zio_buf_cache[c], KM_PUSHPAGE));
}

/*
 * Use zio_data_buf_alloc to allocate data.  The data will not appear in a
 * crashdump if the kernel panics.  This exists so that we will limit the amount
 * of ZFS data that shows up in a kernel crashdump.  (Thus reducing the amount
 * of kernel heap dumped to disk when the kernel panics)
 */
void *
zio_data_buf_alloc(size_t size)
{
	size_t c = (size - 1) >> SPA_MINBLOCKSHIFT;

	VERIFY3U(c, <, SPA_MAXBLOCKSIZE >> SPA_MINBLOCKSHIFT);
	#if defined(ZFS_DEBUG) && !defined(_KERNEL)
	// if we're using combined bufs, this should increment too...
	if (zio_buf_cache[c] == zio_data_buf_cache[c])
		atomic_add_64(&zio_buf_cache_allocs[c], 1);
	#endif

	return (kmem_cache_alloc(zio_data_buf_cache[c], KM_PUSHPAGE));
}

void
zio_buf_free(void *buf, size_t size)
{
	size_t c = (size - 1) >> SPA_MINBLOCKSHIFT;

	VERIFY3U(c, <, SPA_MAXBLOCKSIZE >> SPA_MINBLOCKSHIFT);
#if defined(ZFS_DEBUG) && !defined(_KERNEL)
	atomic_add_64(&zio_buf_cache_frees[c], 1);
#endif

	kmem_cache_free(zio_buf_cache[c], buf);
}

void
zio_data_buf_free(void *buf, size_t size)
{
	size_t c = (size - 1) >> SPA_MINBLOCKSHIFT;

	VERIFY3U(c, <, SPA_MAXBLOCKSIZE >> SPA_MINBLOCKSHIFT);
#if defined(ZFS_DEBUG) && !defined(_KERNEL)
	// if we're using combined bufs, this should increment too...
	if (zio_buf_cache[c] == zio_data_buf_cache[c])
		atomic_add_64(&zio_buf_cache_frees[c], 1);
#endif

	kmem_cache_free(zio_data_buf_cache[c], buf);
}


EXPORT_SYMBOL(zio_data_fini);
EXPORT_SYMBOL(zio_data_init);
EXPORT_SYMBOL(zio_cache);
EXPORT_SYMBOL(zio_link_cache);
EXPORT_SYMBOL(zio_buf_cache);
EXPORT_SYMBOL(zio_data_buf_cache);
EXPORT_SYMBOL(zio_buf_alloc);
EXPORT_SYMBOL(zio_data_buf_alloc);
EXPORT_SYMBOL(zio_buf_free);
EXPORT_SYMBOL(zio_data_buf_free);

