/*
 * Implement fast Fletcher4 with SSE2,SSSE3 instructions. (x86)
 *
 * Use the 128-bit SSE2/SSSE3 SIMD instructions and registers to compute
 * Fletcher4 in two incremental 64-bit parallel accumulator streams,
 * and then combine the streams to form the final four checksum words.
 * This implementation is a derivative of the AVX SIMD implementation by
 * James Guilford and Jinshan Xiong from Intel (see zfs_fletcher_intel.c).
 *
 * Copyright (C) 2016 Tyler J. Stachecki.
 *
 * Authors:
 *	Tyler J. Stachecki <stachecki.tyler@gmail.com>
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

#if defined(HAVE_SSE2)

#include <sys/simd.h>
#include <sys/spa_checksum.h>
#include <sys/byteorder.h>
#include <sys/strings.h>
#if defined(__aarch64__)
#define zfs_sse2_available(...) (1)
#endif
#include <zfs_fletcher.h>

/*
 * We extern'd these into their own compile unit
 * so we could do special, separate things with them.
 */
extern void
_fletcher_4_sse2_intrin_native(fletcher_4_ctx_t *ctx, const void *buf, uint64_t size);
extern void
_fletcher_4_sse2_intrin_byteswap(fletcher_4_ctx_t *ctx, const void *buf, uint64_t size);

ZFS_NO_SANITIZE_UNDEFINED
static void
fletcher_4_sse2_intrin_init(fletcher_4_ctx_t *ctx)
{
	bzero(ctx->sse, 4 * sizeof (zfs_fletcher_sse_t));
}

ZFS_NO_SANITIZE_UNDEFINED
static void
fletcher_4_sse2_intrin_fini(fletcher_4_ctx_t *ctx, zio_cksum_t *zcp)
{
	uint64_t A, B, C, D;

	/*
	 * The mixing matrix for checksum calculation is:
	 * a = a0 + a1
	 * b = 2b0 + 2b1 - a1
	 * c = 4c0 - b0 + 4c1 -3b1
	 * d = 8d0 - 4c0 + 8d1 - 8c1 + b1;
	 *
	 * c and d are multiplied by 4 and 8, respectively,
	 * before spilling the vectors out to memory.
	 */
	A = ctx->sse[0].v[0] + ctx->sse[0].v[1];
	B = 2 * ctx->sse[1].v[0] + 2 * ctx->sse[1].v[1] - ctx->sse[0].v[1];
	C = 4 * ctx->sse[2].v[0] - ctx->sse[1].v[0] + 4 * ctx->sse[2].v[1] -
	    3 * ctx->sse[1].v[1];
	D = 8 * ctx->sse[3].v[0] - 4 * ctx->sse[2].v[0] + 8 * ctx->sse[3].v[1] -
	    8 * ctx->sse[2].v[1] + ctx->sse[1].v[1];

	ZIO_SET_CHECKSUM(zcp, A, B, C, D);
}

#define	FLETCHER_4_SSE_RESTORE_CTX(ctx)					\
{									\
	asm volatile("movdqu %0, %%xmm0" :: "m" ((ctx)->sse[0]));	\
	asm volatile("movdqu %0, %%xmm1" :: "m" ((ctx)->sse[1]));	\
	asm volatile("movdqu %0, %%xmm2" :: "m" ((ctx)->sse[2]));	\
	asm volatile("movdqu %0, %%xmm3" :: "m" ((ctx)->sse[3]));	\
}

#define	FLETCHER_4_SSE_SAVE_CTX(ctx)					\
{									\
	asm volatile("movdqu %%xmm0, %0" : "=m" ((ctx)->sse[0]));	\
	asm volatile("movdqu %%xmm1, %0" : "=m" ((ctx)->sse[1]));	\
	asm volatile("movdqu %%xmm2, %0" : "=m" ((ctx)->sse[2]));	\
	asm volatile("movdqu %%xmm3, %0" : "=m" ((ctx)->sse[3]));	\
}

static void
fletcher_4_sse2_intrin_native(fletcher_4_ctx_t *ctx, const void *buf, uint64_t size)
{
	kfpu_begin();
	_fletcher_4_sse2_intrin_native(ctx,buf,size);
	kfpu_end();
}

static void
fletcher_4_sse2_intrin_byteswap(fletcher_4_ctx_t *ctx, const void *buf, uint64_t size)
{
	kfpu_begin();

	_fletcher_4_sse2_intrin_byteswap(ctx,buf,size);

	kfpu_end();
}

static boolean_t fletcher_4_sse2_intrin_valid(void)
{
	return (kfpu_allowed() && zfs_sse2_available());
}

const fletcher_4_ops_t fletcher_4_sse2_intrin_ops = {
	.init_native = fletcher_4_sse2_intrin_init,
	.fini_native = fletcher_4_sse2_intrin_fini,
	.compute_native = fletcher_4_sse2_intrin_native,
	.init_byteswap = fletcher_4_sse2_intrin_init,
	.fini_byteswap = fletcher_4_sse2_intrin_fini,
	.compute_byteswap = fletcher_4_sse2_intrin_byteswap,
	.valid = fletcher_4_sse2_intrin_valid,
	.name = "sse2-i"
};

#endif /* defined(HAVE_SSE2) */

#if defined(HAVE_SSE2) && defined(HAVE_SSSE3)
extern void
_fletcher_4_ssse3_intrin_byteswap(fletcher_4_ctx_t *ctx, const void *buf, uint64_t size);

static void
fletcher_4_ssse3_intrin_byteswap(fletcher_4_ctx_t *ctx, const void *buf, uint64_t size)
{
	kfpu_begin();
	
	_fletcher_4_ssse3_intrin_byteswap(ctx,buf,size);

	kfpu_end();
}

static boolean_t fletcher_4_ssse3_intrin_valid(void)
{
	return (kfpu_allowed() && zfs_sse2_available() &&
	    zfs_ssse3_available());
}

const fletcher_4_ops_t fletcher_4_ssse3_intrin_ops = {
	.init_native = fletcher_4_sse2_intrin_init,
	.fini_native = fletcher_4_sse2_intrin_fini,
	.compute_native = fletcher_4_sse2_intrin_native,
	.init_byteswap = fletcher_4_sse2_intrin_init,
	.fini_byteswap = fletcher_4_sse2_intrin_fini,
	.compute_byteswap = fletcher_4_ssse3_intrin_byteswap,
	.valid = fletcher_4_ssse3_intrin_valid,
	.name = "ssse3-i"
};

#endif /* defined(HAVE_SSE2) && defined(HAVE_SSSE3) */
