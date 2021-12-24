
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
 * Copyright (c) 2021 Tino Reichardt <milky-zfs@mcmilk.de>
 */

#include <sys/types.h>
#include <sys/spa.h>
#include <sys/zio_checksum.h>
#include <sys/zfs_context.h>
#include <sys/zfs_chksum.h>

#include <sys/blake3.h>

static kstat_t *chksum_kstat = NULL;

typedef struct {
	const char *name;
	const char *impl;
	uint16_t digest;
	uint64_t bs1k;
	uint64_t bs2k;
	uint64_t bs4k;
	uint64_t bs8k;
	uint64_t bs16k;
	uint64_t bs32k;
	uint64_t bs64k;
	uint64_t bs128k;
	uint64_t bs256k;
	uint64_t bs512k;
	uint64_t bs1m;
	zio_checksum_t *(func);
	zio_checksum_tmpl_init_t *(init);
	zio_checksum_tmpl_free_t *(free);
} chksum_stat_t;

static int chksum_stat_cnt = 0;
static chksum_stat_t *chksum_stat_data = 0;

/*
 * implementation       digest       1k   2k   4k  16k  32k  64k 128k 256k 512k
 *
 * fletcher-4                4      22M  22M   22   22   22   22   22   22   22
 * edonr-generic           256      22M  22M   22   22   22   22   22   22   22
 * skein-generic           256      22M  22M   22   22   22   22   22   22   22
 * sha256-generic          256      22M  22M   22   22   22   22   22   22   22
 * sha512-generic          512      22M  22M   22   22   22   22   22   22   22
 *
 * blake3-generic          256      22M  22M   22   22   22   22   22   22   22
 * blake3-sse2             256      22M  22M   22   22   22   22   22   22   22
 * blake3-sse41            256      22M  22M   22   22   22   22   22   22   22
 * blake3-avx              256      22M  22M   22   22   22   22   22   22   22
 * blake3-avx2             256      22M  22M   22   22   22   22   22   22   22
 * blake3-avx512           256      22M  22M   22   22   22   22   22   22   22
 * blake3-neon             256      22M  22M   22   22   22   22   22   22   22
 */
static int
chksum_stat_kstat_headers(char *buf, size_t size)
{
	ssize_t off = 0;

	off += snprintf(buf + off, size, "%-17s", "implementation");
	off += snprintf(buf + off, size - off, "%-10s", "digest");
	off += snprintf(buf + off, size - off, "%-10s", "1k");
	off += snprintf(buf + off, size - off, "%-10s", "2k");
	off += snprintf(buf + off, size - off, "%-10s", "4k");
	off += snprintf(buf + off, size - off, "%-10s", "8k");
	off += snprintf(buf + off, size - off, "%-10s", "16k");
	off += snprintf(buf + off, size - off, "%-10s", "32k");
	off += snprintf(buf + off, size - off, "%-10s", "64k");
	off += snprintf(buf + off, size - off, "%-10s", "128k");
	off += snprintf(buf + off, size - off, "%-10s", "256k");
	off += snprintf(buf + off, size - off, "%-10s", "512k");
	(void) snprintf(buf + off, size - off, "%-10s\n", "1m");

	return (0);
}

static int
chksum_stat_kstat_data(char *buf, size_t size, void *data)
{
	chksum_stat_t *cs;
	ssize_t off = 0;
	char b[20];

	cs = (chksum_stat_t *)data;
	snprintf(b, 19, "%s-%s", cs->name, cs->impl);
	off += snprintf(buf + off, size - off, "%-17s", b);
	off += snprintf(buf + off, size - off, "%-10u",
	    (unsigned)cs->digest);
	off += snprintf(buf + off, size - off, "%-10llu",
	    (u_longlong_t)cs->bs1k);
	off += snprintf(buf + off, size - off, "%-10llu",
	    (u_longlong_t)cs->bs2k);
	off += snprintf(buf + off, size - off, "%-10llu",
	    (u_longlong_t)cs->bs4k);
	off += snprintf(buf + off, size - off, "%-10llu",
	    (u_longlong_t)cs->bs8k);
	off += snprintf(buf + off, size - off, "%-10llu",
	    (u_longlong_t)cs->bs16k);
	off += snprintf(buf + off, size - off, "%-10llu",
	    (u_longlong_t)cs->bs32k);
	off += snprintf(buf + off, size - off, "%-10llu",
	    (u_longlong_t)cs->bs64k);
	off += snprintf(buf + off, size - off, "%-10llu",
	    (u_longlong_t)cs->bs128k);
	off += snprintf(buf + off, size - off, "%-10llu",
	    (u_longlong_t)cs->bs256k);
	off += snprintf(buf + off, size - off, "%-10llu",
	    (u_longlong_t)cs->bs512k);
	(void) snprintf(buf + off, size - off, "%-10llu\n",
	    (u_longlong_t)cs->bs1m);

	return (0);
}

static void *
chksum_stat_kstat_addr(kstat_t *ksp, loff_t n)
{
	if (n < chksum_stat_cnt)
		ksp->ks_private = (void *)(chksum_stat_data + n);
	else
		ksp->ks_private = NULL;

	return (ksp->ks_private);
}

static void
chksum_run(chksum_stat_t *cs, abd_t *abd, void *ctx, uint64_t size,
    uint64_t *result)
{
	hrtime_t start;
	uint64_t run_bw, run_time_ns, run_count = 0;
	uint32_t l;
	zio_cksum_t zcp;

	kpreempt_disable();
	start = gethrtime();
	do {
		for (l = 0; l < 64; l++, run_count++)
			cs->func(abd, size, ctx, &zcp);

		run_time_ns = gethrtime() - start;
	} while (run_time_ns < MSEC2NSEC(1));
	kpreempt_enable();

	run_bw = size * run_count * NANOSEC;
	run_bw /= run_time_ns;	/* B/s */
	*result = run_bw/1024/1024; /* MiB/s */
}

static void
chksum_benchit(chksum_stat_t *cs)
{
	abd_t *abd;
	void *ctx = 0;
	zio_cksum_salt_t salt;

	/* allocate test memory via default abd interface */
	abd = abd_alloc_linear(1024*1024, B_FALSE);
	bzero(salt.zcs_bytes, sizeof (zio_cksum_salt_t));
	if (cs->init) {
		ctx = cs->init(&salt);
	}

	chksum_run(cs, abd, ctx, 1024, &cs->bs1k);
	chksum_run(cs, abd, ctx, 1024*2, &cs->bs2k);
	chksum_run(cs, abd, ctx, 1024*4, &cs->bs4k);
	chksum_run(cs, abd, ctx, 1024*8, &cs->bs8k);
	chksum_run(cs, abd, ctx, 1024*16, &cs->bs16k);
	chksum_run(cs, abd, ctx, 1024*32, &cs->bs32k);
	chksum_run(cs, abd, ctx, 1024*64, &cs->bs64k);
	chksum_run(cs, abd, ctx, 1024*128, &cs->bs128k);
	chksum_run(cs, abd, ctx, 1024*256, &cs->bs256k);
	chksum_run(cs, abd, ctx, 1024*512, &cs->bs512k);
	chksum_run(cs, abd, ctx, 1024*1024, &cs->bs1m);

	/* free up temp memory */
	if (cs->free) {
		cs->free(ctx);
	}
	abd_free(abd);
}

/*
 * Initialize and benchmark all supported implementations.
 */
static void
chksum_benchmark(void)
{
	chksum_stat_t *cs;
	int i = 0, id, id_max = 0;
	uint64_t max = 0;

	/* space for the benchmark times */
	chksum_stat_cnt = 5 + blake3_get_impl_count();
	chksum_stat_data = (chksum_stat_t *)kmem_zalloc(
	    sizeof (chksum_stat_t) * chksum_stat_cnt, KM_SLEEP);

	/*
	 * cs = &chksum_stat_data[i++];
	 * cs->init = 0;
	 * cs->func = abd_fletcher_4_native;
	 * cs->free = 0;
	 * cs->name = "fletcher";
	 * cs->impl = "4";
	 * cs->digest = 4;
	 * chksum_benchit(cs);
	 */

	/* edonr */
	cs = &chksum_stat_data[i++];
	cs->init = abd_checksum_edonr_tmpl_init;
	cs->func = abd_checksum_edonr_native;
	cs->free = abd_checksum_edonr_tmpl_free;
	cs->name = "edonr";
	cs->impl = "generic";
	cs->digest = 256;
	chksum_benchit(cs);

	/* skein */
	cs = &chksum_stat_data[i++];
	cs->init = abd_checksum_skein_tmpl_init;
	cs->func = abd_checksum_skein_native;
	cs->free = abd_checksum_skein_tmpl_free;
	cs->name = "skein";
	cs->impl = "generic";
	cs->digest = 256;
	chksum_benchit(cs);

	/* sha256 */
	cs = &chksum_stat_data[i++];
	cs->init = 0;
	cs->func = abd_checksum_SHA256;
	cs->free = 0;
	cs->name = "sha256";
	cs->impl = "generic";
	cs->digest = 256;
	chksum_benchit(cs);

	/* sha512 */
	cs = &chksum_stat_data[i++];
	cs->init = 0;
	cs->func = abd_checksum_SHA512_native;
	cs->free = 0;
	cs->name = "sha512";
	cs->impl = "generic";
	cs->digest = 512;
	chksum_benchit(cs);

	/* blake3 */
	for (id = 0; id < blake3_get_impl_count(); id++) {
		blake3_set_impl_id(id);
		cs = &chksum_stat_data[i++];
		cs->init = abd_checksum_blake3_tmpl_init;
		cs->func = abd_checksum_blake3_native;
		cs->free = abd_checksum_blake3_tmpl_free;
		cs->name = "blake3";
		cs->impl = blake3_get_impl_name();
		cs->digest = 256;
		chksum_benchit(cs);
		if (cs->bs128k > max) {
			max = cs->bs128k;
			id_max = id;
		}
	}

	/* switch blake to the fastest method */
	blake3_set_impl_id(id_max);
}

void
chksum_init(void)
{
	/* Benchmark supported implementations */
	chksum_benchmark();

	/* Install kstats for all implementations */
	chksum_kstat = kstat_create("zfs", 0, "chksum_bench", "misc",
	    KSTAT_TYPE_RAW, 0, KSTAT_FLAG_VIRTUAL);

	if (chksum_kstat != NULL) {
		chksum_kstat->ks_data = NULL;
		chksum_kstat->ks_ndata = UINT32_MAX;
		kstat_set_raw_ops(chksum_kstat,
		    chksum_stat_kstat_headers,
		    chksum_stat_kstat_data,
		    chksum_stat_kstat_addr);
		kstat_install(chksum_kstat);
	}
}

void
chksum_fini(void)
{
	if (chksum_kstat != NULL) {
		kstat_delete(chksum_kstat);
		chksum_kstat = NULL;
	}

	if (chksum_stat_cnt) {
		kmem_free(chksum_stat_data,
		    sizeof (chksum_stat_t) * chksum_stat_cnt);
		chksum_stat_cnt = 0;
		chksum_stat_data = 0;
	}
}
