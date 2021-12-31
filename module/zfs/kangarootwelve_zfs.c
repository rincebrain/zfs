/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://opensource.org/licenses/CDDL-1.0.
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
 * Copyright 2013 Saso Kiselkov.  All rights reserved.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */
#include <sys/simd.h>
#include <sys/zfs_context.h>
#include <sys/zio.h>
#include <sys/zio_checksum.h>
#include <sys/kangarootwelve.h>

#include <sys/abd.h>

static int
kangarootwelve_incremental(void *buf, size_t size, void *arg)
{
	KangarooTwelve_Instance *ctx = arg;
	int ret = 0;
	ret = KangarooTwelve_Update(ctx, buf, size);
	return (ret);
}
/*
 * Computes a native 256-bit kangarootwelve MAC checksum.
 */
/*ARGSUSED*/
void
abd_checksum_kangarootwelve_native(abd_t *abd, uint64_t size,
    const void *ctx_template, zio_cksum_t *zcp)
{
	KangarooTwelve_Instance	ctx_o;
	KangarooTwelve_Instance *ctx = &ctx_o;
	int err = 0;

//	ASSERT(ctx_template != NULL);
//	bcopy(ctx_template, &ctx, sizeof (ctx));
	bzero(ctx, sizeof(*ctx));
	kfpu_begin();

	err = KangarooTwelve_Initialize(ctx, sizeof(zio_cksum_t));
	ASSERT(err == 0);
	err = abd_iterate_func(abd, 0, size, kangarootwelve_incremental, ctx);
	ASSERT(err == 0);
	err = KangarooTwelve_Final(ctx, (uint8_t *)zcp, NULL, 0);
	ASSERT(err == 0);
	kfpu_end();
	bzero(ctx, sizeof (*ctx));
//	kmem_free(ctx, sizeof(*ctx));
}

/*
 * Byteswapped version of abd_checksum_kangarootwelve_native. This just invokes
 * the native checksum function and byteswaps the resulting checksum (since
 * kangarootwelve is internally endian-insensitive).
 */
void
abd_checksum_kangarootwelve_byteswap(abd_t *abd, uint64_t size,
    const void *ctx_template, zio_cksum_t *zcp)
{
	zio_cksum_t	tmp;

	abd_checksum_kangarootwelve_native(abd, size, ctx_template, &tmp);
	zcp->zc_word[0] = BSWAP_64(tmp.zc_word[0]);
	zcp->zc_word[1] = BSWAP_64(tmp.zc_word[1]);
	zcp->zc_word[2] = BSWAP_64(tmp.zc_word[2]);
	zcp->zc_word[3] = BSWAP_64(tmp.zc_word[3]);
}

