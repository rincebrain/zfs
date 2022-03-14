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
//#include <sys/bmw.h>
//#include <sys/keccak.h>
#include <sys/sha2.h>

static kstat_t *chksum_kstat = NULL;

typedef struct {
	const char *name;
	const char *impl;
	uint64_t bs1k;
	uint64_t bs4k;
	uint64_t bs16k;
	uint64_t bs64k;
	uint64_t bs256k;
	uint64_t bs1m;
	uint64_t bs4m;
	zio_cksum_salt_t salt;
	zio_cksum_t chkme[7];
	boolean_t wrong[7];
	zio_checksum_t *(func);
	zio_checksum_tmpl_init_t *(init);
	zio_checksum_tmpl_free_t *(free);
} chksum_stat_t;

static int chksum_stat_cnt = 0;
static chksum_stat_t *chksum_stat_data = 0;

/*
 * i3-1005G1 test output:
 *
 * implementation     1k      4k     16k     64k    256k      1m      4m
 * fletcher-4       5421   15001   26468   32555   34720   32801   18847
 * edonr-generic    1196    1602    1761    1749    1762    1759    1751
 * skein-generic     546     591     608     615     619     612     616
 * sha256-generic    246     270     274     274     277     275     276
 * sha256-avx        262     296     304     307     307     307     306
 * sha256-sha-ni     769    1072    1172    1220    1219    1232    1228
 * sha256-openssl    240     300     316     314     304     285     276
 * sha512-generic    333     374     385     392     391     393     392
 * sha512-openssl    353     441     467     476     472     467     426
 * sha512-avx        362     444     473     475     479     476     478
 * sha512-avx2       394     500     530     538     543     545     542
 * blake3-generic    308     313     313     313     312     313     312
 * blake3-sse2       402    1289    1423    1446    1432    1458    1413
 * blake3-sse41      427    1470    1625    1704    1679    1607    1629
 * blake3-avx2       428    1920    3095    3343    3356    3318    3204
 * blake3-avx512     473    2687    4905    5836    5844    5643    5374
 */
static int
chksum_stat_kstat_headers(char *buf, size_t size)
{
	ssize_t off = 0;

	off += snprintf(buf + off, size, "%-23s", "implementation");
	off += snprintf(buf + off, size - off, "%9s", "1k");
	off += snprintf(buf + off, size - off, "%9s", "4k");
	off += snprintf(buf + off, size - off, "%9s", "16k");
	off += snprintf(buf + off, size - off, "%9s", "64k");
	off += snprintf(buf + off, size - off, "%9s", "256k");
	off += snprintf(buf + off, size - off, "%9s", "1m");
	(void) snprintf(buf + off, size - off, "%9s\n", "4m");

	return (0);
}

static int
chksum_stat_kstat_data(char *buf, size_t size, void *data)
{
	static char* oldname = NULL;
	static char* oldimpl = NULL;
	chksum_stat_t *cs;
	ssize_t off = 0;
	char b[24];

	cs = (chksum_stat_t *)data;
	if (cs->name == NULL || cs->impl == NULL || (cs->name == oldname && cs->impl == oldimpl)) {
//		buf[0] = '\0';
		return (0);
	}

	snprintf(b, 23, "%s-%s", cs->name, cs->impl);
	off += snprintf(buf + off, size - off, "%-23s", b);
	off += snprintf(buf + off, size - off, "%8llu%1s",
	    (u_longlong_t)cs->bs1k, (cs->wrong[0] ? "*" : ""));
	off += snprintf(buf + off, size - off, "%8llu%1s",
	    (u_longlong_t)cs->bs4k, (cs->wrong[1] ? "*" : ""));
	off += snprintf(buf + off, size - off, "%8llu%1s",
	    (u_longlong_t)cs->bs16k, (cs->wrong[2] ? "*" : ""));
	off += snprintf(buf + off, size - off, "%8llu%1s",
	    (u_longlong_t)cs->bs64k, (cs->wrong[3] ? "*" : ""));
	off += snprintf(buf + off, size - off, "%8llu%1s",
	    (u_longlong_t)cs->bs256k, (cs->wrong[4] ? "*" : ""));
	off += snprintf(buf + off, size - off, "%8llu%1s",
	    (u_longlong_t)cs->bs1m, (cs->wrong[5] ? "*" : ""));
	(void) snprintf(buf + off, size - off, "%8llu%1s\n",
	    (u_longlong_t)cs->bs4m, (cs->wrong[6] ? "*" : "") );

	oldname = (char*)cs->name;
	oldimpl = (char*)cs->impl;
//	bzero(cs, sizeof(*cs));

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
chksum_run(chksum_stat_t *cs, abd_t *abd, void *ctx, int round,
    uint64_t *result, zio_cksum_t *chkme)
{
	hrtime_t start;
	uint64_t run_bw, run_time_ns, run_count = 0, size = 0;
	uint32_t l, loops = 0;
	zio_cksum_t zcp;

	switch (round) {
#if 0
	case 1: /* 1k */
		size = 1<<10; loops = 128; break;
	case 2: /* 2k */
		size = 1<<12; loops = 64; break;
	case 3: /* 4k */
		size = 1<<14; loops = 32; break;
	case 4: /* 16k */
		size = 1<<16; loops = 16; break;
	case 5: /* 256k */
		size = 1<<18; loops = 8; break;
	case 6: /* 1m */
		size = 1<<20; loops = 4; break;
	case 7: /* 4m */
		size = 1<<22; loops = 1; break;
#endif
	case 1: /* 1k */
		size = 1<<10; loops = 1; break;
	case 2: /* 2k */
		size = 1<<12; loops = 1; break;
	case 3: /* 4k */
		size = 1<<14; loops = 1; break;
	case 4: /* 16k */
		size = 1<<16; loops = 1; break;
	case 5: /* 256k */
		size = 1<<18; loops = 1; break;
	case 6: /* 1m */
		size = 1<<20; loops = 1; break;
	case 7: /* 4m */
		size = 1<<22; loops = 1; break;
	}

	kpreempt_disable();
	start = gethrtime();
	do {
		for (l = 0; l < loops; l++, run_count++)
			cs->func(abd, size, ctx, &zcp);

		run_time_ns = gethrtime() - start;
	} while (run_time_ns < MSEC2NSEC(1));
	kpreempt_enable();

	if (chkme)
		memcpy(chkme,&zcp,sizeof(zio_cksum_t));

	run_bw = size * run_count * NANOSEC;
	run_bw /= run_time_ns;	/* B/s */
	*result = run_bw/1024/1024; /* MiB/s */
}

static void
chksum_benchit(chksum_stat_t *cs)
{
	abd_t *abd;
	void *ctx = 0;
	void *salt = &cs->salt.zcs_bytes;

	/* allocate test memory via default abd interface */
	abd = abd_alloc_linear(1024 * 1024 * 4, B_FALSE);
	bzero(salt, sizeof (cs->salt.zcs_bytes));
	if (cs->init) {
		ctx = cs->init(&cs->salt);
	}

	chksum_run(cs, abd, ctx, 1, &cs->bs1k, &cs->chkme[0]);
	chksum_run(cs, abd, ctx, 2, &cs->bs4k, &cs->chkme[1]);
	chksum_run(cs, abd, ctx, 3, &cs->bs16k, &cs->chkme[2]);
	chksum_run(cs, abd, ctx, 4, &cs->bs64k, &cs->chkme[3]);
	chksum_run(cs, abd, ctx, 5, &cs->bs256k, &cs->chkme[4]);
	chksum_run(cs, abd, ctx, 6, &cs->bs1m, &cs->chkme[5]);
	chksum_run(cs, abd, ctx, 7, &cs->bs4m, &cs->chkme[6]);

	/* free up temp memory */
	if (cs->free) {
		cs->free(ctx);
	}
	abd_free(abd);
}

//#ifdef _KERNEL
#if 1
#define printline(s)
#define printhead()
#else
void printhead(void);
void printline(chksum_stat_t *cs);
void printhead(void) {
	printf("%-23s", "implementation");
	printf("%9s", "1k");
	printf("%9s", "4k");
	printf("%9s", "16k");
	printf("%9s", "64k");
	printf("%9s", "256k");
	printf("%9s", "1m");
	printf("%9s", "4m\n");
}

void printline(chksum_stat_t *cs)
{
	char b[24];

	if (cs->name == NULL)
		return;
	snprintf(b, 23, "%s-%s", cs->name, cs->impl);
	printf("%-23s", b);
	printf("%8llu%1s",
	    (u_longlong_t)cs->bs1k, (cs->wrong[0] ? "*" : ""));
	printf("%8llu%1s",
	    (u_longlong_t)cs->bs4k, (cs->wrong[1] ? "*" : ""));
	printf("%8llu%1s",
	    (u_longlong_t)cs->bs16k, (cs->wrong[2] ? "*" : ""));
	printf("%8llu%1s",
	    (u_longlong_t)cs->bs64k, (cs->wrong[3] ? "*" : ""));
	printf("%8llu%1s",
	    (u_longlong_t)cs->bs256k, (cs->wrong[4] ? "*" : ""));
	printf("%8llu%1s",
	    (u_longlong_t)cs->bs1m, (cs->wrong[5] ? "*" : ""));
	(void) printf("%8llu%1s\n",
	    (u_longlong_t)cs->bs4m,(cs->wrong[6] ? "*" : ""));

}
#endif

static void validsums(zio_cksum_t *base, chksum_stat_t *cs) {
	for (int i = 0; i < 7; i++) {
		if (!ZIO_CHECKSUM_EQUAL(base[i],cs->chkme[i])) {
			cs->wrong[i] = B_TRUE;
	#ifndef _KERNEL
		printf("%s (%d) %llx:%llx:%llx:%llx != %llx:%llx:%llx:%llx\n",
			cs->name, i,
			base[i].zc_word[0],
			base[i].zc_word[1],
			base[i].zc_word[2],
			base[i].zc_word[3],
			cs->chkme[i].zc_word[0],
			cs->chkme[i].zc_word[1],
			cs->chkme[i].zc_word[2],
			cs->chkme[i].zc_word[3]);
	#endif
	}
	}
}

/*
 * Initialize and benchmark all supported implementations.
 */
static void
chksum_benchmark(void)
{
	zio_cksum_t baseline[7] = {0};
	
	printhead();
	chksum_stat_t *cs;
	int i = 0, id, id_max = 0;
//	int bmw256_id_max, bmw_id_max = 0;
//	int keccak256_id_max, keccak_id_max = 0;
	uint64_t max = 0;//, bmw256_max = 0 ,bmw_max = 0;
//	uint64_t keccak256_max = 0 ,keccak_max = 0;

	/* space for the benchmark times */
	chksum_stat_cnt = 10;// + (2* bmw_get_impl_count()) + (2* keccak_get_impl_count());
//	chksum_stat_cnt += 1;
//	chksum_stat_cnt += sha256_get_impl_count();
//	chksum_stat_cnt += sha512_get_impl_count();
	chksum_stat_cnt += blake3_get_impl_count();
	chksum_stat_data = (chksum_stat_t *)kmem_zalloc(
	    sizeof (chksum_stat_t) * chksum_stat_cnt, KM_SLEEP);

	/* fletcher-4 */
	fletcher_4_init();
	cs = &chksum_stat_data[i++];
	cs->init = 0;
	cs->func = abd_fletcher_4_native;
	cs->free = 0;
	cs->name = "fletcher";
	cs->impl = "4";
	chksum_benchit(cs);
	printline(cs);

	/* edonr */
	cs = &chksum_stat_data[i++];
	cs->init = abd_checksum_edonr_tmpl_init;
	cs->func = abd_checksum_edonr_native;
	cs->free = abd_checksum_edonr_tmpl_free;
	cs->name = "edonr";
	cs->impl = "new";
	chksum_benchit(cs);
	printline(cs);

	/* skein */
	cs = &chksum_stat_data[i++];
	cs->init = abd_checksum_skein_tmpl_init;
	cs->func = abd_checksum_skein_native;
	cs->free = abd_checksum_skein_tmpl_free;
	cs->name = "skein";
	cs->impl = "generic";
	chksum_benchit(cs);
	printline(cs);
#if 0
	cs = &chksum_stat_data[i++];
	cs->init = 0;
	cs->func = abd_checksum_kangarootwelve_native;
	cs->free = 0;
	cs->name = "k12";
	cs->impl = "generic";
	chksum_benchit(cs);
	printline(cs);

	/* sha256 */
	for (id = 0; id < sha256_get_impl_count(); id++) {
		sha256_set_impl_id(id);
		cs = &chksum_stat_data[i++];
		cs->init = 0;
		cs->func = abd_checksum_SHA256;
		cs->free = 0;
		cs->name = "sha256";
		cs->impl = sha256_get_impl_name();
		chksum_benchit(cs);
		if (id == 0)
			memcpy(&baseline,&cs->chkme,sizeof(cs->chkme));
		else
			validsums((zio_cksum_t *)&baseline,cs);
		printline(cs);
		if (cs->bs256k > max) {
			max = cs->bs256k;
			id_max = id;
		}
	}

	/* take fastest method */
	sha256_set_impl_id(id_max);

	/* sha512 */
	for (id = 0; id < sha512_get_impl_count(); id++) {
		sha512_set_impl_id(id);
		cs = &chksum_stat_data[i++];
		cs->init = 0;
		cs->func = abd_checksum_SHA512_native;
		cs->free = 0;
		cs->name = "sha512";
		cs->impl = sha512_get_impl_name();
		chksum_benchit(cs);
		if (id == 0)
			memcpy(&baseline,&cs->chkme,sizeof(cs->chkme));
		else
			validsums((zio_cksum_t *)&baseline,cs);
		printline(cs);
		if (cs->bs256k > max) {
			max = cs->bs256k;
			id_max = id;
		}
	}

	/* take fastest method */
	sha512_set_impl_id(id_max);

	cs = &chksum_stat_data[i++];
	cs->init = 0;
	cs->func = abd_checksum_prvhash64_native;
	cs->free = 0;
	cs->name = "prvhash64";
	cs->impl = "generic";
	chksum_benchit(cs);
	printline(cs);

	cs = &chksum_stat_data[i++];
	cs->init = 0;
	cs->func = abd_checksum_prvhash64s_native;
	cs->free = 0;
	cs->name = "prvhash64s";
	cs->impl = "generic";
	chksum_benchit(cs);
	printline(cs);

	cs = &chksum_stat_data[i++];
	cs->init = 0;
	cs->func = abd_checksum_prvhash64_512_native;
	cs->free = 0;
	cs->name = "prvhash64_512";
	cs->impl = "generic";
	chksum_benchit(cs);
	printline(cs);

	cs = &chksum_stat_data[i++];
	cs->init = 0;
	cs->func = abd_checksum_prvhash64s_512_native;
	cs->free = 0;
	cs->name = "prvhash64s_512";
	cs->impl = "generic";
	chksum_benchit(cs);
	printline(cs);

	/* bmw */
	for (id = 0; id < bmw_get_impl_count(); id++) {
		bmw_set_impl_id(id);

		cs = &chksum_stat_data[i++];
		cs->init = 0;
		cs->func = abd_checksum_bmw256_native;
		cs->free = 0;
		cs->name = "bmw256";
		cs->impl = bmw_get_impl_name();
		chksum_benchit(cs);
		if (id == 0)
			memcpy(&baseline,&cs->chkme,sizeof(cs->chkme));
		else
			validsums((zio_cksum_t *)&baseline,cs);
		printline(cs);
		if (cs->bs256k > max) {
			bmw256_max = cs->bs256k;
			bmw256_id_max = id;
		}
	}
	for (id = 0; id < bmw_get_impl_count(); id++) {
		bmw_set_impl_id(id);
		cs = &chksum_stat_data[i++];
		cs->init = 0;
		cs->func = abd_checksum_bmw512_native;
		cs->free = 0;
		cs->name = "bmw512";
		cs->impl = bmw_get_impl_name();
		chksum_benchit(cs);
		if (id == 0)
			memcpy(&baseline,&cs->chkme,sizeof(cs->chkme));
		else
			validsums((zio_cksum_t *)&baseline,cs);
		printline(cs);
		if (cs->bs256k > bmw_max) {
			bmw_max = cs->bs256k;
			bmw_id_max = id;
		}
	}

	/* keccak */
	for (id = 0; id < keccak_get_impl_count(); id++) {
		keccak_set_impl_id(id);

		cs = &chksum_stat_data[i++];
		cs->init = 0;
		cs->func = abd_checksum_keccak256_native;
		cs->free = 0;
		cs->name = "keccak256";
		cs->impl = keccak_get_impl_name();
		chksum_benchit(cs);
		if (id == 0)
			memcpy(&baseline,&cs->chkme,sizeof(cs->chkme));
		else
			validsums((zio_cksum_t *)&baseline,cs);
		printline(cs);
		if (cs->bs256k > max) {
			keccak256_max = cs->bs256k;
			keccak256_id_max = id;
		}
	}
	for (id = 0; id < keccak_get_impl_count(); id++) {
		keccak_set_impl_id(id);
		cs = &chksum_stat_data[i++];
		cs->init = 0;
		cs->func = abd_checksum_keccak512_native;
		cs->free = 0;
		cs->name = "keccak512";
		cs->impl = keccak_get_impl_name();
		chksum_benchit(cs);
		if (id == 0)
			memcpy(&baseline,&cs->chkme,sizeof(cs->chkme));
		else
			validsums((zio_cksum_t *)&baseline,cs);
		printline(cs);
		if (cs->bs256k > keccak_max) {
			keccak_max = cs->bs256k;
			keccak_id_max = id;
		}
	}
#endif
	/* blake3 */
	for (id = 0; id < blake3_get_impl_count(); id++) {
		blake3_set_impl_id(id);
		cs = &chksum_stat_data[i++];
		cs->init = abd_checksum_blake3_tmpl_init;
		cs->func = abd_checksum_blake3_native;
		cs->free = abd_checksum_blake3_tmpl_free;
		cs->name = "blake3";
		cs->impl = blake3_get_impl_name();
		chksum_benchit(cs);
		if (id == 0)
			memcpy(&baseline,&cs->chkme,sizeof(cs->chkme));
		else
			validsums((zio_cksum_t *)&baseline,cs);
		printline(cs);
		if (cs->bs256k > max) {
			max = cs->bs256k;
			id_max = id;
		}
	}

	/* take fastest method */
	blake3_set_impl_id(id_max);
//	bmw_set_impl_id(bmw_id_max);
//	keccak_set_impl_id(keccak_id_max);
}

void
chksum_init(void)
{
	fletcher_4_init();
	
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
	fletcher_4_fini();
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
