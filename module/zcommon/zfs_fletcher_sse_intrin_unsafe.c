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

#define ZFS_SSE2_INTRIN 1
#define _MM_MALLOC_H_INCLUDED
#define __MM_MALLOC_H
#include <sys/simd.h>
#include <sys/spa_checksum.h>
#include <sys/byteorder.h>
#include <sys/strings.h>
#if defined(__x86__) || defined(__x86_64__)
#include <emmintrin.h>
#else
#undef fallthrough
#undef noinline
#include <sys/types.h>
#define _GCC_WRAP_STDINT_H
#include "sse2.h"
#define zfs_sse2_available(...) (1)
#endif
#if defined(ZFS_AVX2_INTRIN)
#include <immintrin.h>
#endif
#include <zfs_fletcher.h>

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


void
_fletcher_4_sse2_intrin_native(fletcher_4_ctx_t *ctx, const void *buf, uint64_t size);
void
_fletcher_4_sse2_intrin_byteswap(fletcher_4_ctx_t *ctx, const void *buf, uint64_t size);

#if defined(__x86__) || defined(__x86_64__)
__attribute__((target("sse2")))
#endif
void
_fletcher_4_sse2_intrin_native(fletcher_4_ctx_t *ctx, const void *buf, uint64_t size)
{
	const uint64_t *ip = buf;
	const uint64_t *ipend = (uint64_t *)((uint8_t *)ip + size);

	kfpu_begin();
	// asm volatile("pxor %xmm4, %xmm4");
	// xmm4
	__m128i tmp;
	tmp = _mm_setzero_si128();
	// xmm5,xmm6
	__m128i tmp2;
	__m128i tmp3;
	__m128i regs[4] = {0};
	//FLETCHER_4_SSE_RESTORE_CTX(ctx);
/*
	regs[0] = _mm_load_si128(&ctx->ssei[0]);
	regs[1] = _mm_load_si128(&ctx->ssei[1]);
	regs[2] = _mm_load_si128(&ctx->ssei[2]);
	regs[3] = _mm_load_si128(&ctx->ssei[3]);
*/
	regs[0] = ctx->ssei[0];
	regs[1] = ctx->ssei[1];
	regs[2] = ctx->ssei[2];
	regs[3] = ctx->ssei[3];

	for (; ip < ipend; ip += 2) {
//		asm volatile("movdqu %0, %%xmm5" :: "m"(*ip));
                tmp2 = _mm_load_si128((__m128i *)&ip[0]);
//		asm volatile("movdqa %xmm5, %xmm6");
		tmp3 = tmp2;
//		asm volatile("punpckldq %xmm4, %xmm5");
		tmp2 = _mm_unpacklo_epi32(tmp2, tmp);
//		asm volatile("punpckhdq %xmm4, %xmm6");
		tmp3 = _mm_unpackhi_epi32(tmp3, tmp);
//		asm volatile("paddq %xmm5, %xmm0");
		regs[0] = _mm_add_epi64(tmp2, regs[0]);
//		asm volatile("paddq %xmm0, %xmm1");
		regs[1] = _mm_add_epi64(regs[0], regs[1]);
//		asm volatile("paddq %xmm1, %xmm2");
		regs[2] = _mm_add_epi64(regs[1], regs[2]);
//		asm volatile("paddq %xmm2, %xmm3");
		regs[3] = _mm_add_epi64(regs[2], regs[3]);
//		asm volatile("paddq %xmm6, %xmm0");
		regs[0] = _mm_add_epi64(tmp2, regs[0]);
//		asm volatile("paddq %xmm0, %xmm1");
		regs[1] = _mm_add_epi64(regs[0], regs[1]);
//		asm volatile("paddq %xmm1, %xmm2");
		regs[2] = _mm_add_epi64(regs[1], regs[2]);
//		asm volatile("paddq %xmm2, %xmm3");
		regs[3] = _mm_add_epi64(regs[2], regs[3]);
	}

//	FLETCHER_4_SSE_SAVE_CTX(ctx);
/*
	_mm_store_si128(&regs[0],ctx->ssei[0]);
	_mm_store_si128(&regs[1],ctx->ssei[1]);
	_mm_store_si128(&regs[2],ctx->ssei[2]);
	_mm_store_si128(&regs[3],ctx->ssei[3]);
*/
	ctx->ssei[0] = regs[0];
	ctx->ssei[1] = regs[1];
	ctx->ssei[2] = regs[2];
	ctx->ssei[3] = regs[3];

	kfpu_end();
}

#if defined(__x86__) || defined(__x86_64__)
__attribute__((target("sse2")))
#endif
void
_fletcher_4_sse2_intrin_byteswap(fletcher_4_ctx_t *ctx, const void *buf, uint64_t size)
{
	const uint32_t *ip = buf;
	const uint32_t *ipend = (uint32_t *)((uint8_t *)ip + size);

	kfpu_begin();

	// xmm4
	__m128i tmp;
	// xmm5
	__m128i tmp2;
	__m128i regs[4] = {0};
	//FLETCHER_4_SSE_RESTORE_CTX(ctx);
//	regs[0] = _mm_load_si128(ctx->ssei[0]);
//	regs[1] = _mm_load_si128(ctx->ssei[1]);
//	regs[2] = _mm_load_si128(ctx->ssei[2]);
//	regs[3] = _mm_load_si128(ctx->ssei[3]);
	regs[0] = ctx->ssei[0];
	regs[1] = ctx->ssei[1];
	regs[2] = ctx->ssei[2];
	regs[3] = ctx->ssei[3];

	for (; ip < ipend; ip += 2) {
		uint32_t scratch1 = BSWAP_32(ip[0]);
		uint32_t scratch2 = BSWAP_32(ip[1]);
//		asm volatile("movd %0, %%xmm5" :: "r"(scratch1));
//		asm volatile("movd %0, %%xmm6" :: "r"(scratch2));
		// gcc is missing _mm_loadu_si32 variants until recently, so
		tmp = _mm_cvtsi32_si128(scratch1);
		tmp2 = _mm_cvtsi32_si128(scratch2);
//		tmp2 = _mm_loadu_si128(&scratch2);
//		asm volatile("punpcklqdq %xmm6, %xmm5");
		tmp = _mm_unpacklo_epi64(tmp, tmp2);
//		asm volatile("paddq %xmm5, %xmm0");
		regs[0] = _mm_add_epi64(tmp, regs[0]);
//		asm volatile("paddq %xmm0, %xmm1");
		regs[1] = _mm_add_epi64(regs[0], regs[1]);
//		asm volatile("paddq %xmm1, %xmm2");
		regs[2] = _mm_add_epi64(regs[1], regs[2]);
//		asm volatile("paddq %xmm2, %xmm3");
		regs[3] = _mm_add_epi64(regs[2], regs[3]);
	}

	// restore
	ctx->ssei[0] = regs[0];
	ctx->ssei[1] = regs[1];
	ctx->ssei[2] = regs[2];
	ctx->ssei[3] = regs[3];

	kfpu_end();
}

#endif /* defined(HAVE_SSE2) */

#if defined(HAVE_SSE2) && defined(HAVE_SSSE3)
#if defined(__x86__) || defined(__x86_64__)
__attribute__((target("ssse3")))
#endif
void
_fletcher_4_ssse3_intrin_byteswap(fletcher_4_ctx_t *ctx, const void *buf, uint64_t size);

void
_fletcher_4_ssse3_intrin_byteswap(fletcher_4_ctx_t *ctx, const void *buf, uint64_t size)
{
	static const zfs_fletcher_sse_t mask = {
		.v = { 0x0405060700010203, 0x0C0D0E0F08090A0B }
	};

	const uint64_t *ip = buf;
	const uint64_t *ipend = (uint64_t *)((uint8_t *)ip + size);

	FLETCHER_4_SSE_RESTORE_CTX(ctx);

	asm volatile("movdqu %0, %%xmm7"::"m" (mask));
	asm volatile("pxor %xmm4, %xmm4");

	for (; ip < ipend; ip += 2) {
		asm volatile("movdqu %0, %%xmm5"::"m" (*ip));
		asm volatile("pshufb %xmm7, %xmm5");
		asm volatile("movdqa %xmm5, %xmm6");
		asm volatile("punpckldq %xmm4, %xmm5");
		asm volatile("punpckhdq %xmm4, %xmm6");
		asm volatile("paddq %xmm5, %xmm0");
		asm volatile("paddq %xmm0, %xmm1");
		asm volatile("paddq %xmm1, %xmm2");
		asm volatile("paddq %xmm2, %xmm3");
		asm volatile("paddq %xmm6, %xmm0");
		asm volatile("paddq %xmm0, %xmm1");
		asm volatile("paddq %xmm1, %xmm2");
		asm volatile("paddq %xmm2, %xmm3");
	}

	FLETCHER_4_SSE_SAVE_CTX(ctx);

}

#endif /* defined(HAVE_SSE2) && defined(HAVE_SSSE3) */
