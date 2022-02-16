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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012, 2016 by Delphix. All rights reserved.
 * Copyright (c) 2020, 2021, 2022, Pawel Jakub Dawidek <pawel@dawidek.net>. All rights reserved.
 */

#include <sys/zfs_context.h>
#include <sys/spa.h>
#include <sys/spa_impl.h>
#include <sys/zio.h>
#include <sys/brt.h>
#include <sys/ddt.h>
#include <sys/bitmap.h>
#include <sys/zap.h>
#include <sys/dmu_tx.h>
#include <sys/arc.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_scan.h>
#include <sys/vdev_impl.h>

#define	ZFS_BRT_DEBUG

/*
 * BRT - Block Reference Table.
 */
#define	BRT_OBJECT_VDEV_PREFIX	"net.dawidek:brt:vdev:"

/*
 * We divide each VDEV into 1GB chunks. Each chunk is represented in memory
 * by a 64bit counter, thus 1TB VDEV requires 8kB of memory.
 */
#define	BRT_RANGE_CHUNK	(1024 * 1024 * 1024)
/*
 * We don't want to update the whole structure every time. Maintain bitmap
 * of dirty blocks within the regions, so that a single bit represents a
 * block size of refcounts. For example if we have a 64TB vdev then all
 * refcounts take 512kB of memory. If the block size is 4kB then we want to
 * have 128 separate dirty bits. Each bit will represent change in one
 * of 512 refcounts (4kB / sizeof(uint64_t)).
 */
#define	BRT_RANGE_SIZE_TO_NBLOCKS(size, blocksize)			\
	(((size) - 1) / (blocksize) / sizeof(uint64_t) + 1)

typedef struct brt_vdev_phys {
	uint64_t	bvp_mos_entries;
	uint64_t	bvp_size;
	uint64_t	bvp_totalcount;
	uint64_t	bvp_drefsize;
	uint64_t	bvp_dsize;
} brt_vdev_phys_t;

typedef struct brt_vdev {
	/*
	 * VDEV id.
	 */
	uint64_t	bv_vdevid;
	/*
	 * If the structure intitiated? (bv_tree, bv_refcount are allocated?)
	 */
	boolean_t	bv_initiated;
	/*
	 * Object number in the MOS for the refcount array and brt_vdev_phys.
	 */
	uint64_t	bv_mos_brtvdev;
	/*
	 * Object number in the MOS for the entries table.
	 */
	uint64_t	bv_mos_entries;
	/*
	 * Entries to sync.
	 */
	avl_tree_t	*bv_tree;
	/*
	 * Number of entries in the bv_refcount[] array.
	 */
	uint64_t	bv_size;
	/*
	 * This is the array with all the refcounts
	 * (one refcount per BRT_RANGE_CHUNK).
	 */
	uint64_t	*bv_refcount;
	/*
	 * Sum of all bv_refcount[]s.
	 */
	uint64_t	bv_totalcount;
	/*
	 * Disk space savings thanks to BRT.
	 */
	uint64_t	bv_drefsize;
	uint64_t	bv_dsize;
	/*
	 * bv_refcount[] potentially can be a bit too big to sychronize it all
	 * when we just changed few refcounts. The fields below allow us to
	 * track updates to bv_refcount[] array since the last sync.
	 * A single bit in the bv_bitmap represents as many refcounts as can
	 * fit into a single brt_blocksize, where brt_blocksize is
	 * (1 << spa->spa_min_ashift).
	 * For example we have 65536 refcounts in the bv_refcount array
	 * (so the whole array is 512kB). We updated bv_refcount[2] and
	 * bv_refcount[5]. In that case only first bit in the bv_bitmap will
	 * be set and we will write only first 4kB out of 512kB (assuming
	 * ashift is 12).
	 */
	boolean_t	bv_dirty;
	ulong_t		*bv_bitmap;
	uint64_t	bv_nblocks;
} brt_vdev_t;

/*
 * In-core brt
 */
typedef struct brt {
	kmutex_t	brt_lock;
	spa_t		*brt_spa;
#define	brt_mos		brt_spa->spa_meta_objset
	uint64_t	brt_blocksize;
	uint64_t	brt_drefsize;
	uint64_t	brt_dsize;
	avl_tree_t	brt_pending_tree[TXG_SIZE];
	kmutex_t	brt_pending_lock[TXG_SIZE];
	uint64_t	brt_nentries;
	brt_vdev_t	*brt_vdevs;
	uint64_t	brt_nvdevs;
} brt_t;

/* Size of bre_offset / sizeof (uint64_t). */
#define	BRT_KEY_WORDS	(1)

/*
 * In-core brt entry.
 * On-disk we use bre_offset as the key and bre_refcount as the value.
 */
typedef struct brt_entry {
	uint64_t	bre_vdevid;
	uint64_t	bre_offset;
	uint64_t	bre_refcount;
	avl_node_t	bre_node;
} brt_entry_t;

typedef struct brt_pending_entry {
	blkptr_t	bpe_bp;
	int		bpe_count;
	avl_node_t	bpe_node;
} brt_pending_entry_t;

static kmem_cache_t *brt_entry_cache;
static kmem_cache_t *brt_pending_entry_cache;

/*
 * Enable/disable prefetching of BRT entries that we are going to modify.
 */
int zfs_brt_prefetch = 0;

static int zfs_brt_debug = 1;
#define	BRT_DEBUG(...)	do {						\
	if (zfs_brt_debug) {						\
		printf("%s:%u: ", __func__, __LINE__);			\
		printf(__VA_ARGS__);					\
		printf("\n");						\
	}								\
} while (0)

int brt_zap_leaf_blockshift = 12;
int brt_zap_indirect_blockshift = 12;

kstat_t	*brt_ksp = NULL;

typedef struct brt_stats {
	kstat_named_t brt_addref_entry_in_memory;
	kstat_named_t brt_addref_entry_not_on_disk;
	kstat_named_t brt_addref_entry_on_disk;
	kstat_named_t brt_addref_entry_read_lost_race;
	kstat_named_t brt_decref_entry_in_memory;
	kstat_named_t brt_decref_entry_loaded_from_disk;
	kstat_named_t brt_decref_entry_not_in_memory;
	kstat_named_t brt_decref_entry_not_on_disk;
	kstat_named_t brt_decref_entry_read_lost_race;
	kstat_named_t brt_decref_entry_still_referenced;
	kstat_named_t brt_decref_free_data_later;
	kstat_named_t brt_decref_free_data_now;
	kstat_named_t brt_decref_no_entry;
} brt_stats_t;

static brt_stats_t brt_stats = {
	{ "addref_entry_in_memory",		KSTAT_DATA_UINT64 },
	{ "addref_entry_not_on_disk",		KSTAT_DATA_UINT64 },
	{ "addref_entry_on_disk",		KSTAT_DATA_UINT64 },
	{ "addref_entry_read_lost_race",	KSTAT_DATA_UINT64 },
	{ "decref_entry_in_memory",		KSTAT_DATA_UINT64 },
	{ "decref_entry_loaded_from_disk",	KSTAT_DATA_UINT64 },
	{ "decref_entry_not_in_memory",		KSTAT_DATA_UINT64 },
	{ "decref_entry_not_on_disk",		KSTAT_DATA_UINT64 },
	{ "decref_entry_read_lost_race",	KSTAT_DATA_UINT64 },
	{ "decref_entry_still_referenced",	KSTAT_DATA_UINT64 },
	{ "decref_free_data_later",		KSTAT_DATA_UINT64 },
	{ "decref_free_data_now",		KSTAT_DATA_UINT64 },
	{ "decref_no_entry",			KSTAT_DATA_UINT64 }
};

#define	BRTSTAT_BUMP(stat)	atomic_inc_64(&brt_stats.stat.value.ui64)

static int brt_entry_compare(const void *x1, const void *x2);
static int brt_pending_entry_compare(const void *x1, const void *x2);

static void
brt_enter(brt_t *brt)
{
	mutex_enter(&brt->brt_lock);
}

static void
brt_exit(brt_t *brt)
{
	mutex_exit(&brt->brt_lock);
}

#ifdef ZFS_BRT_DEBUG
static void
brt_vdev_dump(brt_t *brt)
{
	brt_vdev_t *brtvd;
	uint64_t vdevid;

	if (brt->brt_nvdevs == 0) {
		printf("BRT empty\n");
		return;
	}

	printf("BRT vdev dump:\n");
	for (vdevid = 0; vdevid < brt->brt_nvdevs; vdevid++) {
		uint64_t idx;

		brtvd = &brt->brt_vdevs[vdevid];
		printf("  vdevid=%ju/%ju dirty=%d size=%ju totalcount=%ju nblocks=%ju bitmapsize=%ju\n",
		    (uintmax_t)vdevid, (uintmax_t)brtvd->bv_vdevid,
		    brtvd->bv_dirty, (uintmax_t)brtvd->bv_size,
		    (uintmax_t)brtvd->bv_totalcount,
		    (uintmax_t)brtvd->bv_nblocks,
		    (uintmax_t)BT_SIZEOFMAP(brtvd->bv_nblocks));
		if (brtvd->bv_totalcount > 0) {
			printf("    refcounts:\n");
			for (idx = 0; idx < brtvd->bv_size; idx++) {
				if (brtvd->bv_refcount[idx] > 0) {
					printf("      [%04ju] %ju\n",
					    (uintmax_t)idx,
					    (uintmax_t)brtvd->bv_refcount[idx]);
				}
			}
		}
		if (brtvd->bv_dirty) {
			printf("    bitmap: ");
			for (idx = 0; idx < brtvd->bv_nblocks; idx++) {
				printf("%d", BT_TEST(brtvd->bv_bitmap, idx));
			}
			printf("\n");
		}
	}
}
#endif

static brt_vdev_t *
brt_vdev(brt_t *brt, brt_entry_t *bre)
{
	brt_vdev_t *brtvd;
	uint64_t vdevid;

	ASSERT(MUTEX_HELD(&brt->brt_lock));

	vdevid = bre->bre_vdevid;
	if (vdevid < brt->brt_nvdevs) {
		brtvd = &brt->brt_vdevs[vdevid];
	} else {
		brtvd = NULL;
	}

	return (brtvd);
}

static void
brt_vdev_create(brt_t *brt, brt_vdev_t *brtvd, dmu_tx_t *tx)
{
	char name[64];

	ASSERT(MUTEX_HELD(&brt->brt_lock));
	ASSERT0(brtvd->bv_mos_brtvdev);
	ASSERT0(brtvd->bv_mos_entries);
	ASSERT(brtvd->bv_refcount != NULL);
	ASSERT(brtvd->bv_size > 0);
	ASSERT(brtvd->bv_bitmap != NULL);
	ASSERT(brtvd->bv_nblocks > 0);

	brtvd->bv_mos_entries = zap_create_flags(brt->brt_mos, 0,
	    ZAP_FLAG_HASH64 | ZAP_FLAG_UINT64_KEY, DMU_OTN_ZAP_METADATA,
	    brt_zap_leaf_blockshift, brt_zap_indirect_blockshift, DMU_OT_NONE,
	    0, tx);
	ASSERT(brtvd->bv_mos_entries != 0);
	BRT_DEBUG("MOS entries created, object=%lu", brtvd->bv_mos_entries);

	/*
	 * We allocate DMU buffer to store the bv_refcount[] array.
	 * We will keep array size (bv_size) and cummulative count for all
	 * bv_refcount[]s (bv_totalcount) in the bonus buffer.
	 */
	brtvd->bv_mos_brtvdev = dmu_object_alloc(brt->brt_mos,
	    DMU_OTN_UINT64_METADATA, brt->brt_blocksize,
	    DMU_OTN_UINT64_METADATA, sizeof (brt_vdev_phys_t), tx);
	ASSERT(brtvd->bv_mos_brtvdev != 0);
	BRT_DEBUG("MOS BRT VDEV created, object=%lu", brtvd->bv_mos_brtvdev);

	snprintf(name, sizeof(name), "%s%ju", BRT_OBJECT_VDEV_PREFIX,
	    (uintmax_t)brtvd->bv_vdevid);
	VERIFY0(zap_add(brt->brt_mos, DMU_POOL_DIRECTORY_OBJECT, name,
	    sizeof (uint64_t), 1, &brtvd->bv_mos_brtvdev, tx));
	BRT_DEBUG("Pool directory object created, object=%s", name);

	spa_feature_incr(brt->brt_spa, SPA_FEATURE_BLOCK_CLONING, tx);
}

static void
brt_vdev_realloc(brt_t *brt, brt_vdev_t *brtvd)
{
	vdev_t *vd;
	uint64_t *refcount;
	ulong_t *bitmap;
	uint64_t nblocks, size;

	ASSERT(MUTEX_HELD(&brt->brt_lock));

	spa_config_enter(brt->brt_spa, SCL_VDEV, FTAG, RW_READER);
	vd = vdev_lookup_top(brt->brt_spa, brtvd->bv_vdevid);
	size = vdev_get_min_asize(vd) / BRT_RANGE_CHUNK + 1;
	spa_config_exit(brt->brt_spa, SCL_VDEV, FTAG);

	refcount = kmem_zalloc(sizeof(uint64_t) * size, KM_SLEEP);
	nblocks = BRT_RANGE_SIZE_TO_NBLOCKS(size, brt->brt_blocksize);
	bitmap = kmem_zalloc(BT_SIZEOFMAP(nblocks), KM_SLEEP);

	if (!brtvd->bv_initiated) {
		ASSERT0(brtvd->bv_size);
		ASSERT(brtvd->bv_refcount == NULL);
		ASSERT(brtvd->bv_bitmap == NULL);
		ASSERT0(brtvd->bv_nblocks);

		brtvd->bv_tree = kmem_zalloc(sizeof(*brtvd->bv_tree), KM_SLEEP);
		avl_create(brtvd->bv_tree, brt_entry_compare,
		    sizeof (brt_entry_t), offsetof(brt_entry_t, bre_node));
	} else {
		ASSERT(brtvd->bv_size > 0);
		ASSERT(brtvd->bv_refcount != NULL);
		ASSERT(brtvd->bv_bitmap != NULL);
		ASSERT(brtvd->bv_nblocks > 0);
		ASSERT(brtvd->bv_tree != NULL);
		/*
		 * TODO: Allow vdev shrinking. We only need to implement
		 * shrinking the on-disk BRT VDEV object.
		 * dmu_free_range(brt->brt_mos, brtvd->bv_mos_brtvdev, offset, size, tx);
		 */
		ASSERT3U(brtvd->bv_size, <=, size);

		bcopy(brtvd->bv_refcount, refcount,
		    sizeof(uint64_t) * MIN(size, brtvd->bv_size));
		bcopy(brtvd->bv_bitmap, bitmap,
		    MIN(BT_SIZEOFMAP(nblocks), BT_SIZEOFMAP(brtvd->bv_nblocks)));
		kmem_free(brtvd->bv_refcount,
		    sizeof(uint64_t) * brtvd->bv_size);
		kmem_free(brtvd->bv_bitmap, BT_SIZEOFMAP(brtvd->bv_nblocks));
	}

	brtvd->bv_size = size;
	brtvd->bv_refcount = refcount;
	brtvd->bv_bitmap = bitmap;
	brtvd->bv_nblocks = nblocks;
	if (!brtvd->bv_initiated) {
		brtvd->bv_initiated = TRUE;
		BRT_DEBUG("BRT VDEV %lu initiated.", brtvd->bv_vdevid);
	}
}

static void
brt_vdev_load(brt_t *brt, brt_vdev_t *brtvd)
{
	char name[64];
	dmu_buf_t *db;
	brt_vdev_phys_t *bvphys;
	int error;

	snprintf(name, sizeof(name), "%s%ju", BRT_OBJECT_VDEV_PREFIX,
	    (uintmax_t)brtvd->bv_vdevid);
	error = zap_lookup(brt->brt_mos, DMU_POOL_DIRECTORY_OBJECT, name,
	    sizeof (uint64_t), 1, &brtvd->bv_mos_brtvdev);
	ASSERT(error == 0 || error == ENOENT);
	if (error != 0)
		return;
	ASSERT(brtvd->bv_mos_brtvdev != 0);

	ASSERT(!brtvd->bv_initiated);
	brt_vdev_realloc(brt, brtvd);

	error = dmu_bonus_hold(brt->brt_mos, brtvd->bv_mos_brtvdev, FTAG, &db);
	ASSERT0(error);
	if (error != 0)
		return;

	bvphys = db->db_data;
	/* TODO: We don't support VDEV shrinking. */
	ASSERT3U(bvphys->bvp_size, <=, brtvd->bv_size);

	/*
	 * If VDEV grew, we will leave new bv_refcount[] entries zeroed out.
	 */
	error = dmu_read(brt->brt_mos, brtvd->bv_mos_brtvdev, 0,
	    MIN(brtvd->bv_size, bvphys->bvp_size) * sizeof (uint64_t),
	    brtvd->bv_refcount, DMU_READ_NO_PREFETCH);
	ASSERT0(error);

	brtvd->bv_mos_entries = bvphys->bvp_mos_entries;
	ASSERT(brtvd->bv_mos_entries != 0);
	brtvd->bv_totalcount = bvphys->bvp_totalcount;
	brtvd->bv_drefsize = bvphys->bvp_drefsize;
	brtvd->bv_dsize = bvphys->bvp_dsize;
	brt->brt_drefsize += brtvd->bv_drefsize;
	brt->brt_dsize += brtvd->bv_dsize;

	dmu_buf_rele(db, FTAG);

	BRT_DEBUG("MOS BRT VDEV %s loaded: mos_brtvdev=%lu, mos_entries=%lu",
	    name, brtvd->bv_mos_brtvdev, brtvd->bv_mos_entries);
}

static void
brt_vdev_dealloc(brt_t *brt, brt_vdev_t *brtvd)
{

	ASSERT(MUTEX_HELD(&brt->brt_lock));
	ASSERT(brtvd->bv_initiated);

	kmem_free(brtvd->bv_refcount, sizeof (uint64_t) * brtvd->bv_size);
	brtvd->bv_refcount = NULL;
	kmem_free(brtvd->bv_bitmap, BT_SIZEOFMAP(brtvd->bv_nblocks));
	brtvd->bv_bitmap = NULL;
	ASSERT0(avl_numnodes(brtvd->bv_tree));
	avl_destroy(brtvd->bv_tree);
	kmem_free(brtvd->bv_tree, sizeof(*brtvd->bv_tree));
	brtvd->bv_tree = NULL;

	brtvd->bv_size = 0;
	brtvd->bv_nblocks = 0;

	brtvd->bv_initiated = FALSE;
	BRT_DEBUG("BRT VDEV %lu deallocated.", brtvd->bv_vdevid);
}

static void
brt_vdev_destroy(brt_t *brt, brt_vdev_t *brtvd, dmu_tx_t *tx)
{
	char name[64];
	uint64_t count;
	dmu_buf_t *db;
	brt_vdev_phys_t *bvphys;

	ASSERT(MUTEX_HELD(&brt->brt_lock));
	ASSERT(brtvd->bv_mos_brtvdev != 0);
	ASSERT(brtvd->bv_mos_entries != 0);

	VERIFY0(zap_count(brt->brt_mos, brtvd->bv_mos_entries, &count));
	VERIFY0(count);
	VERIFY0(zap_destroy(brt->brt_mos, brtvd->bv_mos_entries, tx));
	BRT_DEBUG("MOS entries destroyed, object=%lu", brtvd->bv_mos_entries);
	brtvd->bv_mos_entries = 0;

	VERIFY0(dmu_bonus_hold(brt->brt_mos, brtvd->bv_mos_brtvdev, FTAG, &db));
	bvphys = db->db_data;
	ASSERT0(bvphys->bvp_totalcount);
	ASSERT0(bvphys->bvp_drefsize);
	ASSERT0(bvphys->bvp_dsize);
	dmu_buf_rele(db, FTAG);

	VERIFY0(dmu_object_free(brt->brt_mos, brtvd->bv_mos_brtvdev, tx));
	BRT_DEBUG("MOS BRT VDEV destroyed, object=%lu", brtvd->bv_mos_brtvdev);
	brtvd->bv_mos_brtvdev = 0;

	snprintf(name, sizeof(name), "%s%ju", BRT_OBJECT_VDEV_PREFIX,
	    (uintmax_t)brtvd->bv_vdevid);
	VERIFY0(zap_remove(brt->brt_mos, DMU_POOL_DIRECTORY_OBJECT, name, tx));
	BRT_DEBUG("Pool directory object removed, object=%s", name);

	brt_vdev_dealloc(brt, brtvd);

	spa_feature_decr(brt->brt_spa, SPA_FEATURE_BLOCK_CLONING, tx);
}

static void
brt_vdevs_expand(brt_t *brt, uint64_t nvdevs)
{
	brt_vdev_t *brtvd, *vdevs;
	uint64_t vdevid;

	ASSERT(MUTEX_HELD(&brt->brt_lock));
	ASSERT3U(nvdevs, >, brt->brt_nvdevs);

	vdevs = kmem_zalloc(sizeof(vdevs[0]) * nvdevs, KM_SLEEP);
	if (brt->brt_nvdevs > 0) {
		ASSERT(brt->brt_vdevs != NULL);

		bcopy(brt->brt_vdevs, vdevs,
		    sizeof(brt_vdev_t) * brt->brt_nvdevs);
		kmem_free(brt->brt_vdevs,
		    sizeof(brt_vdev_t) * brt->brt_nvdevs);
	}
	for (vdevid = brt->brt_nvdevs; vdevid < nvdevs; vdevid++) {
		brtvd = &vdevs[vdevid];

		brtvd->bv_vdevid = vdevid;
		brtvd->bv_initiated = FALSE;
	}

	BRT_DEBUG("BRT VDEVs expanded from %lu to %lu.", brt->brt_nvdevs,
	    nvdevs);

	brt->brt_vdevs = vdevs;
	brt->brt_nvdevs = nvdevs;
}

static boolean_t
brt_vdev_lookup(brt_t *brt, brt_vdev_t *brtvd, const brt_entry_t *bre)
{
	boolean_t found, unlock;
	uint64_t idx;

	if (!MUTEX_HELD(&brt->brt_lock)) {
		unlock = TRUE;
		brt_enter(brt);
	} else {
		unlock = FALSE;
	}

	idx = bre->bre_offset / BRT_RANGE_CHUNK;
	if (brtvd->bv_refcount != NULL && idx < brtvd->bv_size) {
		/* VDEV wasn't expanded. */
		found = brtvd->bv_refcount[idx] > 0;
	} else {
		found = FALSE;
	}

	if (unlock)
		brt_exit(brt);

	return (found);
}

static void
brt_vdev_addref(brt_t *brt, brt_vdev_t *brtvd, const brt_entry_t *bre,
    uint64_t dsize)
{
	uint64_t idx;

	ASSERT(MUTEX_HELD(&brt->brt_lock));
	ASSERT(brtvd != NULL);
	ASSERT(brtvd->bv_refcount != NULL);

	idx = bre->bre_offset / BRT_RANGE_CHUNK;
	if (idx >= brtvd->bv_size) {
		/* VDEV has been expanded. */
		brt_vdev_realloc(brt, brtvd);
	}

	ASSERT3U(idx, <, brtvd->bv_size);

	brtvd->bv_totalcount++;
	brtvd->bv_refcount[idx]++;
	brtvd->bv_dirty = TRUE;
	idx = idx / brt->brt_blocksize / 8;
	BT_SET(brtvd->bv_bitmap, idx);

	brtvd->bv_dsize += dsize;
	brt->brt_dsize += dsize;
	if (bre->bre_refcount == 1) {
		brtvd->bv_drefsize += dsize;
		brt->brt_drefsize += dsize;
	}
#ifdef ZFS_BRT_DEBUG
	brt_vdev_dump(brt);
#endif
}

static void
brt_vdev_decref(brt_t *brt, brt_vdev_t *brtvd, const brt_entry_t *bre,
    uint64_t dsize)
{
	uint64_t idx;

	ASSERT(MUTEX_HELD(&brt->brt_lock));
	ASSERT(brtvd != NULL);
	ASSERT(brtvd->bv_refcount != NULL);

	idx = bre->bre_offset / BRT_RANGE_CHUNK;
	ASSERT3U(idx, <, brtvd->bv_size);

	ASSERT(brtvd->bv_totalcount > 0);
	brtvd->bv_totalcount--;
	ASSERT(brtvd->bv_refcount[idx] > 0);
	brtvd->bv_refcount[idx]--;
	brtvd->bv_dirty = TRUE;
	idx = idx / brt->brt_blocksize / 8;
	BT_SET(brtvd->bv_bitmap, idx);

	brtvd->bv_dsize -= dsize;
	brt->brt_dsize -= dsize;
	if (bre->bre_refcount == 0) {
		brtvd->bv_drefsize -= dsize;
		brt->brt_drefsize -= dsize;
	}
#ifdef ZFS_BRT_DEBUG
	brt_vdev_dump(brt);
#endif
}

static void
brt_vdev_sync(brt_t *brt, brt_vdev_t *brtvd, dmu_tx_t *tx)
{
	dmu_buf_t *db;
	brt_vdev_phys_t *bvphys;

	ASSERT(brtvd->bv_dirty);
	ASSERT(brtvd->bv_mos_brtvdev != 0);
	ASSERT(dmu_tx_is_syncing(tx));

	VERIFY0(dmu_bonus_hold(brt->brt_mos, brtvd->bv_mos_brtvdev, FTAG, &db));

	/*
	 * TODO: Walk through brtvd->bv_bitmap and write only dirty parts.
	 */
	dmu_write(brt->brt_mos, brtvd->bv_mos_brtvdev, 0,
	    brtvd->bv_size * sizeof (brtvd->bv_refcount[0]),
	    brtvd->bv_refcount, tx);

	dmu_buf_will_dirty(db, tx);
	bvphys = db->db_data;
	bvphys->bvp_mos_entries = brtvd->bv_mos_entries;
	bvphys->bvp_size = brtvd->bv_size;
	bvphys->bvp_totalcount = brtvd->bv_totalcount;
	bvphys->bvp_drefsize = brtvd->bv_drefsize;
	bvphys->bvp_dsize = brtvd->bv_dsize;
	dmu_buf_rele(db, FTAG);

	bzero(brtvd->bv_bitmap, BT_SIZEOFMAP(brtvd->bv_nblocks));
	brtvd->bv_dirty = FALSE;
}

static void
brt_vdevs_load(brt_t *brt)
{
	brt_vdev_t *brtvd;
	uint64_t vdevid;

	brt_enter(brt);

	brt_vdevs_expand(brt, brt->brt_spa->spa_root_vdev->vdev_children);
	for (vdevid = 0; vdevid < brt->brt_nvdevs; vdevid++) {
		brtvd = &brt->brt_vdevs[vdevid];
		ASSERT(brtvd->bv_refcount == NULL);

		brt_vdev_load(brt, brtvd);
	}

	brt_exit(brt);
}

static void
brt_vdevs_free(brt_t *brt)
{
	brt_vdev_t *brtvd;
	uint64_t vdevid;

	brt_enter(brt);

	for (vdevid = 0; vdevid < brt->brt_nvdevs; vdevid++) {
		brtvd = &brt->brt_vdevs[vdevid];
		if (brtvd->bv_initiated)
			brt_vdev_dealloc(brt, brtvd);
	}
	kmem_free(brt->brt_vdevs, sizeof (brt_vdev_t) * brt->brt_nvdevs);

	brt_exit(brt);
}

static void
brt_entry_fill(brt_entry_t *bre, const blkptr_t *bp)
{

	bre->bre_vdevid = DVA_GET_VDEV(&bp->blk_dva[0]);
	bre->bre_offset = DVA_GET_OFFSET(&bp->blk_dva[0]);
}

static int
brt_entry_compare(const void *x1, const void *x2)
{
	const brt_entry_t *bre1 = x1;
	const brt_entry_t *bre2 = x2;

	if (bre1->bre_vdevid < bre2->bre_vdevid)
		return (-1);
	else if (bre1->bre_vdevid > bre2->bre_vdevid)
		return (1);

	if (bre1->bre_offset < bre2->bre_offset)
		return (-1);
	else if (bre1->bre_offset > bre2->bre_offset)
		return (1);

	return (0);
}

static int
brt_entry_lookup(brt_t *brt, brt_vdev_t *brtvd, brt_entry_t *bre)
{
	uint64_t mos_entries;
	uint64_t one, physsize;
	int error;

	ASSERT(MUTEX_HELD(&brt->brt_lock));

	if (!brt_vdev_lookup(brt, brtvd, bre))
		return (SET_ERROR(ENOENT));

	/*
	 * Remember mos_entries object number. After we reacquire the BRT lock,
	 * the brtvd pointer may be invalid.
	 */
	mos_entries = brtvd->bv_mos_entries;
	if (mos_entries == 0)
		return (SET_ERROR(ENOENT));

	brt_exit(brt);

	error = zap_length_uint64(brt->brt_mos, mos_entries,
	    (uint64_t *)&bre->bre_offset, BRT_KEY_WORDS, &one, &physsize);
	if (error == 0) {
		ASSERT3U(one, ==, 1);
		ASSERT3U(physsize, ==, sizeof(bre->bre_refcount));

		error = zap_lookup_uint64(brt->brt_mos, mos_entries,
		    (uint64_t *)&bre->bre_offset, BRT_KEY_WORDS, 1,
		    sizeof(bre->bre_refcount), &bre->bre_refcount);
		BRT_DEBUG("ZAP lookup: object=%lu vdev=%lu offset=%lu count=%lu error=%d",
		    mos_entries, bre->bre_vdevid, bre->bre_offset,
		    error == 0 ? bre->bre_refcount : 0, error);
	}

	brt_enter(brt);

	return (error);
}

static void
brt_entry_prefetch(brt_t *brt, brt_entry_t *bre)
{
	brt_vdev_t *brtvd;
	uint64_t mos_entries = 0;

	brt_enter(brt);	/* read lock */
	brtvd = brt_vdev(brt, bre);
	if (brtvd != NULL)
		mos_entries = brtvd->bv_mos_entries;
	brt_exit(brt);

	if (mos_entries == 0)
		return;

	BRT_DEBUG("ZAP prefetch: object=%lu vdev=%lu offset=%lu",
	    mos_entries, bre->bre_vdevid, bre->bre_offset);
	(void) zap_prefetch_uint64(brt->brt_mos, mos_entries,
	    (uint64_t *)&bre->bre_offset, BRT_KEY_WORDS);
}

static int
brt_entry_update(brt_t *brt, brt_vdev_t *brtvd, brt_entry_t *bre, dmu_tx_t *tx)
{
	int error;

	ASSERT(MUTEX_HELD(&brt->brt_lock));
	ASSERT(brtvd->bv_mos_entries != 0);
	ASSERT(bre->bre_refcount > 0);

	error = zap_update_uint64(brt->brt_mos, brtvd->bv_mos_entries,
	    (uint64_t *)&bre->bre_offset, BRT_KEY_WORDS, 1,
	    sizeof(bre->bre_refcount), &bre->bre_refcount, tx);
	BRT_DEBUG("ZAP update: object=%lu vdev=%lu offset=%lu count=%lu error=%d",
	    brtvd->bv_mos_entries, bre->bre_vdevid, bre->bre_offset,
	    bre->bre_refcount, error);

	return (error);
}

static int
brt_entry_remove(brt_t *brt, brt_vdev_t *brtvd, brt_entry_t *bre, dmu_tx_t *tx)
{
	int error;

	ASSERT(MUTEX_HELD(&brt->brt_lock));
	ASSERT(brtvd->bv_mos_entries != 0);
	ASSERT0(bre->bre_refcount);

	error = zap_remove_uint64(brt->brt_mos, brtvd->bv_mos_entries,
	    (uint64_t *)&bre->bre_offset, BRT_KEY_WORDS, tx);
	BRT_DEBUG("ZAP remove: object=%lu vdev=%lu offset=%lu count=%lu error=%d",
	    brtvd->bv_mos_entries, bre->bre_vdevid, bre->bre_offset,
	    bre->bre_refcount, error);

	return (error);
}

/*
 * Return TRUE if we _can_ have BRT entry for this bp. It might be false
 * positive, but gives us quick answer if we should look into BRT, which
 * may require reads and thus will be more expensive.
 */
boolean_t
brt_may_exists(spa_t *spa, const blkptr_t *bp)
{
	brt_t *brt = spa->spa_brt;
	brt_vdev_t *brtvd;
	brt_entry_t bre_search;
	boolean_t mayexists = FALSE;

	brt_entry_fill(&bre_search, bp);

	brt_enter(brt);

	brtvd = brt_vdev(brt, &bre_search);
	if (brtvd != NULL && brtvd->bv_initiated) {
		if (!avl_is_empty(brtvd->bv_tree) ||
		    brt_vdev_lookup(brt, brtvd, &bre_search)) {
			mayexists = TRUE;
		}
	}

	brt_exit(brt);

	return (mayexists);
}

uint64_t
brt_get_dspace(spa_t *spa)
{

	if (spa->spa_brt == NULL)
		return (0);

	return (spa->spa_brt->brt_dsize);
}

uint64_t
brt_get_pool_ratio(spa_t *spa)
{
	brt_t *brt = spa->spa_brt;

	if (brt->brt_dsize == 0)
		return (100);

	return ((brt->brt_drefsize + brt->brt_dsize) * 100 / brt->brt_drefsize);
}

static void
brt_stat_init(void)
{
	brt_ksp = kstat_create("zfs", 0, "brt", "misc", KSTAT_TYPE_NAMED,
	    sizeof (brt_stats) / sizeof (kstat_named_t), KSTAT_FLAG_VIRTUAL);
	if (brt_ksp != NULL) {
		brt_ksp->ks_data = &brt_stats;
		kstat_install(brt_ksp);
	}
}

static void
brt_stat_fini(void)
{
	if (brt_ksp != NULL) {
		kstat_delete(brt_ksp);
		brt_ksp = NULL;
	}
}

void
brt_init(void)
{
	brt_entry_cache = kmem_cache_create("brt_entry_cache",
	    sizeof (brt_entry_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
	brt_pending_entry_cache = kmem_cache_create("brt_pending_entry_cache",
	    sizeof (brt_pending_entry_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	brt_stat_init();
}

void
brt_fini(void)
{
	brt_stat_fini();

	kmem_cache_destroy(brt_entry_cache);
}

static brt_entry_t *
brt_entry_alloc(const brt_entry_t *bre_init)
{
	brt_entry_t *bre;

	bre = kmem_cache_alloc(brt_entry_cache, KM_SLEEP);
	bzero(bre, sizeof (brt_entry_t));

	bre->bre_vdevid = bre_init->bre_vdevid;
	bre->bre_offset = bre_init->bre_offset;

	return (bre);
}

static void
brt_entry_free(brt_entry_t *bre)
{

	kmem_cache_free(brt_entry_cache, bre);
}

static void
brt_entry_addref(brt_t *brt, const blkptr_t *bp)
{
	brt_vdev_t *brtvd;
	brt_entry_t *bre, *racebre;
	brt_entry_t bre_search;
	avl_index_t where;
	int error;

	ASSERT(!MUTEX_HELD(&brt->brt_lock));

	brt_entry_fill(&bre_search, bp);

	brt_enter(brt);

	brtvd = brt_vdev(brt, &bre_search);
	if (brtvd == NULL) {
		uint64_t vdevid = bre_search.bre_vdevid;

		ASSERT3U(vdevid, >=, brt->brt_nvdevs);

		/* New VDEV was added. */
		brt_vdevs_expand(brt, vdevid + 1);
		brtvd = brt_vdev(brt, &bre_search);
	}
	ASSERT(brtvd != NULL);
	if (!brtvd->bv_initiated)
		brt_vdev_realloc(brt, brtvd);

	bre = avl_find(brtvd->bv_tree, &bre_search, NULL);
	if (bre != NULL) {
		BRTSTAT_BUMP(brt_addref_entry_in_memory);
	} else {
		bre = brt_entry_alloc(&bre_search);

		/* brt_entry_lookup() may drop the BRT lock. */
		error = brt_entry_lookup(brt, brtvd, bre);
		ASSERT(error == 0 || error == ENOENT);
		if (error == 0)
			BRTSTAT_BUMP(brt_addref_entry_on_disk);
		else
			BRTSTAT_BUMP(brt_addref_entry_not_on_disk);
		/*
		 * When the BRT lock was dropped, brt_vdevs[] may have been
		 * expanded and reallocated, we need to update brtvd's pointer.
		 */
		brtvd = brt_vdev(brt, bre);
		ASSERT(brtvd != NULL);

		racebre = avl_find(brtvd->bv_tree, &bre_search, &where);
		if (racebre == NULL) {
			avl_insert(brtvd->bv_tree, bre, where);
			brt->brt_nentries++;
		} else {
			/*
			 * The entry was added when the BRT lock was dropped in
			 * brt_entry_lookup().
			 */
			BRTSTAT_BUMP(brt_addref_entry_read_lost_race);
			brt_entry_free(bre);
			bre = racebre;
		}
	}
	bre->bre_refcount++;
	brt_vdev_addref(brt, brtvd, bre, bp_get_dsize(brt->brt_spa, bp));

	brt_exit(brt);
}

/* Return TRUE if block should be freed immediately. */
boolean_t
brt_entry_decref(spa_t *spa, const blkptr_t *bp)
{
	brt_t *brt = spa->spa_brt;
	brt_vdev_t *brtvd;
	brt_entry_t *bre, *racebre;
	brt_entry_t bre_search;
	avl_index_t where;
	int error;

	ASSERT(!MUTEX_HELD(&brt->brt_lock));

	brt_entry_fill(&bre_search, bp);

	brt_enter(brt);

	brtvd = brt_vdev(brt, &bre_search);
	ASSERT(brtvd != NULL);

	bre = avl_find(brtvd->bv_tree, &bre_search, NULL);
	if (bre != NULL) {
		BRTSTAT_BUMP(brt_decref_entry_in_memory);
		goto out;
	} else {
		BRTSTAT_BUMP(brt_decref_entry_not_in_memory);
	}

	bre = brt_entry_alloc(&bre_search);

	/* brt_entry_lookup() may drop the BRT lock. */
	error = brt_entry_lookup(brt, brtvd, bre);
	ASSERT(error == 0 || error == ENOENT);
	/*
	 * When the BRT lock was dropped, brt_vdevs[] may have been expanded
	 * and reallocated, we need to update brtvd's pointer.
	 */
	brtvd = brt_vdev(brt, bre);
	ASSERT(brtvd != NULL);

	if (error == ENOENT) {
		BRTSTAT_BUMP(brt_decref_entry_not_on_disk);
		brt_entry_free(bre);
		bre = NULL;
		goto out;
	}

	racebre = avl_find(brtvd->bv_tree, &bre_search, &where);
	if (racebre != NULL) {
		/*
		 * The entry was added when the BRT lock was dropped in
		 * brt_entry_lookup().
		 */
		BRTSTAT_BUMP(brt_decref_entry_read_lost_race);
		brt_entry_free(bre);
		bre = racebre;
		goto out;
	}

	BRTSTAT_BUMP(brt_decref_entry_loaded_from_disk);
	avl_insert(brtvd->bv_tree, bre, where);
	brt->brt_nentries++;

out:
	if (bre == NULL) {
		/*
		 * This is a free of a regular (not cloned) block.
		 */
		brt_exit(brt);
		BRTSTAT_BUMP(brt_decref_no_entry);
		return (B_TRUE);
	}
	if (bre->bre_refcount == 0) {
		brt_exit(brt);
		BRTSTAT_BUMP(brt_decref_free_data_now);
		return (B_TRUE);
	}

	ASSERT(bre->bre_refcount > 0);
	bre->bre_refcount--;
	if (bre->bre_refcount == 0)
		BRTSTAT_BUMP(brt_decref_free_data_later);
	else
		BRTSTAT_BUMP(brt_decref_entry_still_referenced);
	brt_vdev_decref(brt, brtvd, bre, bp_get_dsize(brt->brt_spa, bp));

	brt_exit(brt);

	return (B_FALSE);
}

static void
brt_prefetch(brt_t *brt, const blkptr_t *bp)
{
	brt_entry_t bre;

	ASSERT(bp != NULL);

	if (!zfs_brt_prefetch)
		return;

	brt_entry_fill(&bre, bp);

	brt_entry_prefetch(brt, &bre);
}

static int
brt_pending_entry_compare(const void *x1, const void *x2)
{
	const brt_pending_entry_t *bpe1 = x1, *bpe2 = x2;
	const blkptr_t *bp1 = &bpe1->bpe_bp, *bp2 = &bpe2->bpe_bp;

	if (BP_PHYSICAL_BIRTH(bp1) < BP_PHYSICAL_BIRTH(bp2)) {
		return (-1);
	} else if (BP_PHYSICAL_BIRTH(bp1) > BP_PHYSICAL_BIRTH(bp2)) {
		return (-1);
	}

	if (DVA_GET_VDEV(&bp1->blk_dva[0]) <
	    DVA_GET_VDEV(&bp2->blk_dva[0])) {
		return (-1);
	} else if (DVA_GET_VDEV(&bp1->blk_dva[0]) >
	    DVA_GET_VDEV(&bp2->blk_dva[0])) {
		return (1);
	}

	if (DVA_GET_OFFSET(&bp1->blk_dva[0]) <
	    DVA_GET_OFFSET(&bp2->blk_dva[0])) {
		return (-1);
	} else if (DVA_GET_OFFSET(&bp1->blk_dva[0]) >
	    DVA_GET_OFFSET(&bp2->blk_dva[0])) {
		return (1);
	}

	return (0);
}

void
brt_pending_add(spa_t *spa, const blkptr_t *bp, dmu_tx_t *tx)
{
	brt_t *brt;
	avl_tree_t *pending_tree;
	kmutex_t *pending_lock;
	brt_pending_entry_t *bpe, *newbpe;
	avl_index_t where;
	uint64_t txg;

	brt = spa->spa_brt;
	txg = dmu_tx_get_txg(tx);
	ASSERT3U(txg, !=, 0);
	pending_tree = &brt->brt_pending_tree[txg & TXG_MASK];
	pending_lock = &brt->brt_pending_lock[txg & TXG_MASK];

	newbpe = kmem_cache_alloc(brt_pending_entry_cache, KM_SLEEP);
	newbpe->bpe_bp = *bp;
	newbpe->bpe_count = 1;

	mutex_enter(pending_lock);

	bpe = avl_find(pending_tree, newbpe, &where);
	if (bpe == NULL) {
		avl_insert(pending_tree, newbpe, where);
		newbpe = NULL;
	} else {
		bpe->bpe_count++;
	}

	mutex_exit(pending_lock);

	if (newbpe != NULL) {
		ASSERT(bpe != NULL);
		ASSERT(bpe != newbpe);
		kmem_cache_free(brt_pending_entry_cache, newbpe);
	} else {
		ASSERT(bpe == NULL);
	}

	/* Prefetch BRT entry, as we will need it in the syncing context. */
	brt_prefetch(brt, bp);
}

void
brt_pending_remove(spa_t *spa, const blkptr_t *bp, dmu_tx_t *tx)
{
	brt_t *brt;
	avl_tree_t *pending_tree;
	kmutex_t *pending_lock;
	brt_pending_entry_t *bpe, bpe_search;
	uint64_t txg;

	brt = spa->spa_brt;
	txg = dmu_tx_get_txg(tx);
	ASSERT3U(txg, !=, 0);
	pending_tree = &brt->brt_pending_tree[txg & TXG_MASK];
	pending_lock = &brt->brt_pending_lock[txg & TXG_MASK];

	bpe_search.bpe_bp = *bp;

	mutex_enter(pending_lock);

	bpe = avl_find(pending_tree, &bpe_search, NULL);
	/* I believe we should also find bpe when this function is called. */
	if (bpe != NULL) {
		ASSERT(bpe->bpe_count > 0);

		bpe->bpe_count--;
		if (bpe->bpe_count == 0) {
			avl_remove(pending_tree, bpe);
			kmem_cache_free(brt_pending_entry_cache, bpe);
		}
	}

	mutex_exit(pending_lock);
}

/* TODO: Move to ddt.c. */
static boolean_t
brt_add_to_ddt(spa_t *spa, const blkptr_t *bp)
{
	ddt_t *ddt;
	ddt_entry_t *dde;
	boolean_t result;

	spa_config_enter(spa, SCL_ZIO, FTAG, RW_READER);
	ddt = ddt_select(spa, bp);
	ddt_enter(ddt);

	dde = ddt_lookup(ddt, bp, B_TRUE);
	ASSERT(dde != NULL);

	if (dde->dde_type < DDT_TYPES) {
		ddt_phys_t *ddp;

		ASSERT3S(dde->dde_class, <, DDT_CLASSES);

		ddp = &dde->dde_phys[BP_GET_NDVAS(bp)];
		if (ddp->ddp_refcnt == 0) {
			/* This should never happen? */
			ddt_phys_fill(ddp, bp);
		}
		ddt_phys_addref(ddp);
		result = B_TRUE;
	} else {
		/*
		 * At the time of implementating this if the block has the
		 * DEDUP flag set it must exist in the DEDUP table, but
		 * there are many advocates that want ability to remove
		 * entries from DDT with refcnt=1. If this will happen,
		 * we may have a block with the DEDUP set, but which doesn't
		 * have a corresponding entry in the DDT. Be ready.
		 */
		ASSERT3S(dde->dde_class, ==, DDT_CLASSES);
		ddt_remove(ddt, dde);
		result = B_FALSE;
	}

	ddt_exit(ddt);
	spa_config_exit(spa, SCL_ZIO, FTAG);

	return (result);
}

void
brt_pending_apply(spa_t *spa, uint64_t txg)
{
	brt_t *brt;
	brt_pending_entry_t *bpe;
	avl_tree_t *pending_tree;
	kmutex_t *pending_lock;
	void *c;
	int i;

	ASSERT3U(txg, !=, 0);

	brt = spa->spa_brt;
	pending_tree = &brt->brt_pending_tree[txg & TXG_MASK];
	pending_lock = &brt->brt_pending_lock[txg & TXG_MASK];

	mutex_enter(pending_lock);

	c = NULL;
	while ((bpe = avl_destroy_nodes(pending_tree, &c)) != NULL) {
		boolean_t added_to_ddt;

		mutex_exit(pending_lock);

		for (i = 0; i < bpe->bpe_count; i++) {
			/*
			 * If the block has DEDUP bit set, it means that it
			 * already exists in the DEDUP table, so we can just
			 * use that instead of creating new entry in
			 * the BRT table.
			 */
			if (BP_GET_DEDUP(&bpe->bpe_bp)) {
				added_to_ddt = brt_add_to_ddt(spa,
				    &bpe->bpe_bp);
			} else {
				added_to_ddt = B_FALSE;
			}
			if (!added_to_ddt)
				brt_entry_addref(brt, &bpe->bpe_bp);
		}

		kmem_cache_free(brt_pending_entry_cache, bpe);
		mutex_enter(pending_lock);
	}

	mutex_exit(pending_lock);
}

static void
brt_sync_entry(brt_t *brt, brt_vdev_t *brtvd, brt_entry_t *bre, dmu_tx_t *tx)
{

	ASSERT(MUTEX_HELD(&brt->brt_lock));
	ASSERT(brtvd->bv_mos_entries != 0);

	if (bre->bre_refcount == 0) {
		int error;

		error = brt_entry_remove(brt, brtvd, bre, tx);
		ASSERT(error == 0 || error == ENOENT);
		/*
		 * If error == ENOENT then fclonefile(2) was done from a removed
		 * (but opened) file (open(), unlink()).
		 */
		ASSERT(brt_entry_lookup(brt, brtvd, bre) == ENOENT);
	} else {
		VERIFY0(brt_entry_update(brt, brtvd, bre, tx));
	}
}

static void
brt_sync_table(brt_t *brt, dmu_tx_t *tx)
{
	brt_vdev_t *brtvd;
	brt_entry_t *bre;
	uint64_t vdevid;
	void *c;

	ASSERT(MUTEX_HELD(&brt->brt_lock));

	for (vdevid = 0; vdevid < brt->brt_nvdevs; vdevid++) {
		brtvd = &brt->brt_vdevs[vdevid];

		if (!brtvd->bv_initiated)
			continue;

		if (!brtvd->bv_dirty) {
			ASSERT0(avl_numnodes(brtvd->bv_tree));
			continue;
		}

		ASSERT(avl_numnodes(brtvd->bv_tree) != 0);

		if (brtvd->bv_mos_brtvdev == 0)
			brt_vdev_create(brt, brtvd, tx);

		c = NULL;
		while ((bre = avl_destroy_nodes(brtvd->bv_tree, &c)) != NULL) {
			brt_sync_entry(brt, brtvd, bre, tx);
			brt_entry_free(bre);
			ASSERT(brt->brt_nentries > 0);
			brt->brt_nentries--;
		}

		brt_vdev_sync(brt, brtvd, tx);

		if (brtvd->bv_totalcount == 0)
			brt_vdev_destroy(brt, brtvd, tx);
	}

	ASSERT0(brt->brt_nentries);
}

void
brt_sync(spa_t *spa, uint64_t txg)
{
	dmu_tx_t *tx;
	brt_t *brt;

	ASSERT(spa_syncing_txg(spa) == txg);

	brt = spa->spa_brt;
	brt_enter(brt);
	if (brt->brt_nentries == 0) {
		/* No changes. */
		brt_exit(brt);
		return;
	}
	brt_exit(brt);

	tx = dmu_tx_create_assigned(spa->spa_dsl_pool, txg);

	brt_enter(brt);
	brt_sync_table(brt, tx);
	brt_exit(brt);

	dmu_tx_commit(tx);
}

static void
brt_table_alloc(brt_t *brt)
{
	int i;

	for (i = 0; i < TXG_SIZE; i++) {
		avl_create(&brt->brt_pending_tree[i],
		    brt_pending_entry_compare,
		    sizeof (brt_pending_entry_t),
		    offsetof(brt_pending_entry_t, bpe_node));
		mutex_init(&brt->brt_pending_lock[i], NULL, MUTEX_DEFAULT,
		    NULL);
	}
}

static void
brt_table_free(brt_t *brt)
{
	int i;

	for (i = 0; i < TXG_SIZE; i++) {
		ASSERT(avl_is_empty(&brt->brt_pending_tree[i]));

		avl_destroy(&brt->brt_pending_tree[i]);
		mutex_destroy(&brt->brt_pending_lock[i]);
	}
}

void
brt_create(spa_t *spa)
{
	brt_t *brt;

	ASSERT(spa->spa_brt == NULL);

	brt = kmem_zalloc(sizeof(*brt), KM_SLEEP);
	mutex_init(&brt->brt_lock, NULL, MUTEX_DEFAULT, NULL);
	brt->brt_spa = spa;
	brt->brt_blocksize = (1 << spa->spa_min_ashift);
	brt->brt_nentries = 0;
	brt->brt_vdevs = NULL;
	brt->brt_nvdevs = 0;
	brt_table_alloc(brt);

	spa->spa_brt = brt;
}

int
brt_load(spa_t *spa)
{

	brt_create(spa);
	brt_vdevs_load(spa->spa_brt);

	return (0);
}

void
brt_unload(spa_t *spa)
{
	brt_t *brt = spa->spa_brt;

	if (brt == NULL)
		return;

	brt_vdevs_free(brt);
	brt_table_free(brt);
	mutex_destroy(&brt->brt_lock);
	kmem_free(brt, sizeof(*brt));
	spa->spa_brt = NULL;
}

/* BEGIN CSTYLED */
ZFS_MODULE_PARAM(zfs_brt, zfs_brt_, prefetch, INT, ZMOD_RW,
    "Enable prefetching of BRT entries");
ZFS_MODULE_PARAM(zfs_brt, zfs_brt_, debug, INT, ZMOD_RW, "BRT debug");
/* END CSTYLED */
