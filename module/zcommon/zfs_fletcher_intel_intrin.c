/*
 * Implement fast Fletcher4 with AVX2 instructions. (x86_64)
 *
 * Use the 256-bit AVX2 SIMD instructions and registers to compute
 * Fletcher4 in four incremental 64-bit parallel accumulator streams,
 * and then combine the streams to form the final four checksum words.
 *
 * Copyright (C) 2015 Intel Corporation.
 *
 * Authors:
 *      James Guilford <james.guilford@intel.com>
 *      Jinshan Xiong <jinshan.xiong@intel.com>
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#if defined(HAVE_AVX) && defined(HAVE_AVX2)

#define ZFS_INTRIN 1
#define _MM_MALLOC_H_INCLUDED
#include <sys/spa_checksum.h>
#include <sys/simd.h>
#include <sys/strings.h>
#include <immintrin.h>
#include <zfs_fletcher.h>

ZFS_NO_SANITIZE_UNDEFINED
static void
fletcher_4_avx2_intrin_init(fletcher_4_ctx_t *ctx)
{
	bzero(ctx->avxi, 4 * sizeof (__m256i));
}

ZFS_NO_SANITIZE_UNDEFINED
static void
fletcher_4_avx2_intrin_fini(fletcher_4_ctx_t *ctx, zio_cksum_t *zcp)
{
	uint64_t A, B, C, D;

	A = ctx->avx[0].v[0] + ctx->avx[0].v[1] +
	    ctx->avx[0].v[2] + ctx->avx[0].v[3];
	B = 0 - ctx->avx[0].v[1] - 2 * ctx->avx[0].v[2] - 3 * ctx->avx[0].v[3] +
	    4 * ctx->avx[1].v[0] + 4 * ctx->avx[1].v[1] + 4 * ctx->avx[1].v[2] +
	    4 * ctx->avx[1].v[3];

	C = ctx->avx[0].v[2] + 3 * ctx->avx[0].v[3] - 6 * ctx->avx[1].v[0] -
	    10 * ctx->avx[1].v[1] - 14 * ctx->avx[1].v[2] -
	    18 * ctx->avx[1].v[3] + 16 * ctx->avx[2].v[0] +
	    16 * ctx->avx[2].v[1] + 16 * ctx->avx[2].v[2] +
	    16 * ctx->avx[2].v[3];

	D = 0 - ctx->avx[0].v[3] + 4 * ctx->avx[1].v[0] +
	    10 * ctx->avx[1].v[1] + 20 * ctx->avx[1].v[2] +
	    34 * ctx->avx[1].v[3] - 48 * ctx->avx[2].v[0] -
	    64 * ctx->avx[2].v[1] - 80 * ctx->avx[2].v[2] -
	    96 * ctx->avx[2].v[3] + 64 * ctx->avx[3].v[0] +
	    64 * ctx->avx[3].v[1] + 64 * ctx->avx[3].v[2] +
	    64 * ctx->avx[3].v[3];
	
	ZIO_SET_CHECKSUM(zcp, A, B, C, D);
}


//#pragma target ("avx2")
__attribute__((target("avx2")))
static void
fletcher_4_avx2_intrin_native(fletcher_4_ctx_t *ctx, const void *buf, uint64_t size)
{
	const uint64_t *ip = buf;
	const uint64_t *ipend = (uint64_t *)((uint8_t *)ip + size);

	kfpu_begin();
	__m256i tmp = {0};
	__m256i regs[4] = {0};

	regs[0] = _mm256_loadu_si256(&ctx->avxi[0]);
	regs[1] = _mm256_loadu_si256(&ctx->avxi[1]);
	regs[2] = _mm256_loadu_si256(&ctx->avxi[2]);
	regs[3] = _mm256_loadu_si256(&ctx->avxi[3]);

	for (; ip < ipend; ip += 2) {
		tmp = _mm256_cvtepu32_epi64(*(__m128i*)ip);
		regs[0] = _mm256_add_epi64(tmp, regs[0]);
		regs[1] = _mm256_add_epi64(regs[0], regs[1]);
		regs[2] = _mm256_add_epi64(regs[1], regs[2]);
		regs[3] = _mm256_add_epi64(regs[2], regs[3]);
	}

	ctx->avxi[0] = regs[0];
	ctx->avxi[1] = regs[1];
	ctx->avxi[2] = regs[2];
	ctx->avxi[3] = regs[3];
	_mm256_zeroupper();

	kfpu_end();
}

__attribute__((target("avx2")))
static void
fletcher_4_avx2_intrin_byteswap(fletcher_4_ctx_t *ctx, const void *buf, uint64_t size)
{
	static const __m256i mask = { 0xFFFFFFFF00010203, 0xFFFFFFFF08090A0B,
		    0xFFFFFFFF00010203, 0xFFFFFFFF08090A0B };
	const uint64_t *ip = buf;
	const uint64_t *ipend = (uint64_t *)((uint8_t *)ip + size);

	kfpu_begin();
	__m256i tmp = {0};
	__m256i regs[4] = {0};

	regs[0] = _mm256_loadu_si256(&ctx->avxi[0]);
	regs[1] = _mm256_loadu_si256(&ctx->avxi[1]);
	regs[2] = _mm256_loadu_si256(&ctx->avxi[2]);
	regs[3] = _mm256_loadu_si256(&ctx->avxi[3]);

	for (; ip < ipend; ip += 2) {
		tmp = _mm256_cvtepu32_epi64(*(__m128i*)ip);
		tmp = _mm256_shuffle_epi8(tmp, mask);

		regs[0] = _mm256_add_epi64(tmp, regs[0]);
		regs[1] = _mm256_add_epi64(regs[0], regs[1]);
		regs[2] = _mm256_add_epi64(regs[1], regs[2]);
		regs[3] = _mm256_add_epi64(regs[2], regs[3]);
	}

	ctx->avxi[0] = regs[0];
	ctx->avxi[1] = regs[1];
	ctx->avxi[2] = regs[2];
	ctx->avxi[3] = regs[3];
	_mm256_zeroupper();

	kfpu_end();
}

static boolean_t fletcher_4_avx2_intrin_valid(void)
{
	return (kfpu_allowed() && zfs_avx_available() && zfs_avx2_available());
}

const fletcher_4_ops_t fletcher_4_avx2_intrin_ops = {
	.init_native = fletcher_4_avx2_intrin_init,
	.fini_native = fletcher_4_avx2_intrin_fini,
	.compute_native = fletcher_4_avx2_intrin_native,
	.init_byteswap = fletcher_4_avx2_intrin_init,
	.fini_byteswap = fletcher_4_avx2_intrin_fini,
	.compute_byteswap = fletcher_4_avx2_intrin_byteswap,
	.valid = fletcher_4_avx2_intrin_valid,
	.name = "avx2-i"
};

#endif /* defined(HAVE_AVX) && defined(HAVE_AVX2) */
