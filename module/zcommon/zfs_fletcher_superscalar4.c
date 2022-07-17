/*
 * Implement fast Fletcher4 using superscalar pipelines.
 *
 * Use regular C code to compute
 * Fletcher4 in four incremental 64-bit parallel accumulator streams,
 * and then combine the streams to form the final four checksum words.
 * This implementation is a derivative of the AVX SIMD implementation by
 * James Guilford and Jinshan Xiong from Intel (see zfs_fletcher_intel.c).
 *
 * Copyright (C) 2016 Romain Dolbeau.
 *
 * Authors:
 *	Romain Dolbeau <romain.dolbeau@atos.net>
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
 *	- Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *
 *	- Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
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

#include <sys/param.h>
#include <sys/byteorder.h>
#include <sys/spa_checksum.h>
#include <sys/string.h>
#include <sys/zfs_context.h>
#include <zfs_fletcher.h>

/*
 * See the large block comment in zfs_fletcher.c for an explanation of
 * the explicit casts strategically placed below;
 * zfs_fletcher_superscalar_t has a similar lack of alignment
 * requirement to zio_cksum_t.
 */

novector static void
fletcher_4_superscalar4_init(fletcher_4_ctx_t *ctx)
{
	memset((zfs_fletcher_superscalar_t *)ctx->superscalar, 0,
	    4 * sizeof (zfs_fletcher_superscalar_t));
}

novector static void
fletcher_4_superscalar4_fini(fletcher_4_ctx_t *ctx, zio_cksum_t *zcp)
{
	zfs_fletcher_superscalar_t *ss_ctx =
	    (zfs_fletcher_superscalar_t *)ctx->superscalar;
	uint64_t A, B, C, D;

	A = ss_ctx[0].v[0] + ss_ctx[0].v[1] +
	    ss_ctx[0].v[2] + ss_ctx[0].v[3];
	B = 0 - ss_ctx[0].v[1] - 2 * ss_ctx[0].v[2] -
	    3 * ss_ctx[0].v[3] + 4 * ss_ctx[1].v[0] +
	    4 * ss_ctx[1].v[1] + 4 * ss_ctx[1].v[2] +
	    4 * ss_ctx[1].v[3];

	C = ss_ctx[0].v[2] + 3 * ss_ctx[0].v[3] -
	    6 * ss_ctx[1].v[0] - 10 * ss_ctx[1].v[1] -
	    14 * ss_ctx[1].v[2] - 18 * ss_ctx[1].v[3] +
	    16 * ss_ctx[2].v[0] + 16 * ss_ctx[2].v[1] +
	    16 * ss_ctx[2].v[2] + 16 * ss_ctx[2].v[3];

	D = 0 - ss_ctx[0].v[3] + 4 * ss_ctx[1].v[0] +
	    10 * ss_ctx[1].v[1] + 20 * ss_ctx[1].v[2] +
	    34 * ss_ctx[1].v[3] - 48 * ss_ctx[2].v[0] -
	    64 * ss_ctx[2].v[1] - 80 * ss_ctx[2].v[2] -
	    96 * ss_ctx[2].v[3] + 64 * ss_ctx[3].v[0] +
	    64 * ss_ctx[3].v[1] + 64 * ss_ctx[3].v[2] +
	    64 * ss_ctx[3].v[3];

	ZIO_SET_CHECKSUM(zcp, A, B, C, D);
}

novector static void
fletcher_4_superscalar4_native(fletcher_4_ctx_t *ctx,
    const void *buf, uint64_t size)
{
	zfs_fletcher_superscalar_t *ss_ctx =
	    (zfs_fletcher_superscalar_t *)ctx->superscalar;

	const uint32_t *ip = buf;
	const uint32_t *ipend = ip + (size / sizeof (uint32_t));
	uint64_t a, b, c, d;
	uint64_t a2, b2, c2, d2;
	uint64_t a3, b3, c3, d3;
	uint64_t a4, b4, c4, d4;

	a = ss_ctx[0].v[0];
	b = ss_ctx[1].v[0];
	c = ss_ctx[2].v[0];
	d = ss_ctx[3].v[0];
	a2 = ss_ctx[0].v[1];
	b2 = ss_ctx[1].v[1];
	c2 = ss_ctx[2].v[1];
	d2 = ss_ctx[3].v[1];
	a3 = ss_ctx[0].v[2];
	b3 = ss_ctx[1].v[2];
	c3 = ss_ctx[2].v[2];
	d3 = ss_ctx[3].v[2];
	a4 = ss_ctx[0].v[3];
	b4 = ss_ctx[1].v[3];
	c4 = ss_ctx[2].v[3];
	d4 = ss_ctx[3].v[3];

	for (; ip < ipend; ip += 4) {
		a += ip[0];
		a2 += ip[1];
		a3 += ip[2];
		a4 += ip[3];
		b += a;
		b2 += a2;
		b3 += a3;
		b4 += a4;
		c += b;
		c2 += b2;
		c3 += b3;
		c4 += b4;
		d += c;
		d2 += c2;
		d3 += c3;
		d4 += c4;
	}

	ss_ctx[0].v[0] = a;
	ss_ctx[1].v[0] = b;
	ss_ctx[2].v[0] = c;
	ss_ctx[3].v[0] = d;
	ss_ctx[0].v[1] = a2;
	ss_ctx[1].v[1] = b2;
	ss_ctx[2].v[1] = c2;
	ss_ctx[3].v[1] = d2;
	ss_ctx[0].v[2] = a3;
	ss_ctx[1].v[2] = b3;
	ss_ctx[2].v[2] = c3;
	ss_ctx[3].v[2] = d3;
	ss_ctx[0].v[3] = a4;
	ss_ctx[1].v[3] = b4;
	ss_ctx[2].v[3] = c4;
	ss_ctx[3].v[3] = d4;
}

novector static void
fletcher_4_superscalar4_byteswap(fletcher_4_ctx_t *ctx,
    const void *buf, uint64_t size)
{
	zfs_fletcher_superscalar_t *ss_ctx =
	    (zfs_fletcher_superscalar_t *)ctx->superscalar;

	const uint32_t *ip = buf;
	const uint32_t *ipend = ip + (size / sizeof (uint32_t));
	uint64_t a, b, c, d;
	uint64_t a2, b2, c2, d2;
	uint64_t a3, b3, c3, d3;
	uint64_t a4, b4, c4, d4;

	a = ss_ctx[0].v[0];
	b = ss_ctx[1].v[0];
	c = ss_ctx[2].v[0];
	d = ss_ctx[3].v[0];
	a2 = ss_ctx[0].v[1];
	b2 = ss_ctx[1].v[1];
	c2 = ss_ctx[2].v[1];
	d2 = ss_ctx[3].v[1];
	a3 = ss_ctx[0].v[2];
	b3 = ss_ctx[1].v[2];
	c3 = ss_ctx[2].v[2];
	d3 = ss_ctx[3].v[2];
	a4 = ss_ctx[0].v[3];
	b4 = ss_ctx[1].v[3];
	c4 = ss_ctx[2].v[3];
	d4 = ss_ctx[3].v[3];

	for (; ip < ipend; ip += 4) {
		a += BSWAP_32(ip[0]);
		a2 += BSWAP_32(ip[1]);
		a3 += BSWAP_32(ip[2]);
		a4 += BSWAP_32(ip[3]);
		b += a;
		b2 += a2;
		b3 += a3;
		b4 += a4;
		c += b;
		c2 += b2;
		c3 += b3;
		c4 += b4;
		d += c;
		d2 += c2;
		d3 += c3;
		d4 += c4;
	}

	ss_ctx[0].v[0] = a;
	ss_ctx[1].v[0] = b;
	ss_ctx[2].v[0] = c;
	ss_ctx[3].v[0] = d;
	ss_ctx[0].v[1] = a2;
	ss_ctx[1].v[1] = b2;
	ss_ctx[2].v[1] = c2;
	ss_ctx[3].v[1] = d2;
	ss_ctx[0].v[2] = a3;
	ss_ctx[1].v[2] = b3;
	ss_ctx[2].v[2] = c3;
	ss_ctx[3].v[2] = d3;
	ss_ctx[0].v[3] = a4;
	ss_ctx[1].v[3] = b4;
	ss_ctx[2].v[3] = c4;
	ss_ctx[3].v[3] = d4;
}

static boolean_t fletcher_4_superscalar4_valid(void)
{
	return (B_TRUE);
}

const fletcher_4_ops_t fletcher_4_superscalar4_ops = {
	.init_native = fletcher_4_superscalar4_init,
	.compute_native = fletcher_4_superscalar4_native,
	.fini_native = fletcher_4_superscalar4_fini,
	.init_byteswap = fletcher_4_superscalar4_init,
	.compute_byteswap = fletcher_4_superscalar4_byteswap,
	.fini_byteswap = fletcher_4_superscalar4_fini,
	.valid = fletcher_4_superscalar4_valid,
	.name = "superscalar4"
};
