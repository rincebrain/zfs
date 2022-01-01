/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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

/* straight out of clang -S to blake3_neon.c, then modified to taste */

/*
 * Based on BLAKE3 v1.2.0, https://github.com/BLAKE3-team/BLAKE3
 * Copyright (c) 2019-2021 Samuel Neves
 */

#if defined(__aarch64__)

	.p2align	4                               // -- Begin function _blake3_hash_many_neon
	.globl  _blake3_hash_many_neon
	.type	_blake3_hash_many_neon,@function
_blake3_hash_many_neon:                  // @_blake3_hash_many_neon
// %bb.0:
	stp	d15, d14, [sp, #-160]!          // 16-byte Folded Spill
	stp	d13, d12, [sp, #16]             // 16-byte Folded Spill
	stp	d11, d10, [sp, #32]             // 16-byte Folded Spill
	stp	d9, d8, [sp, #48]               // 16-byte Folded Spill
	stp	x29, x30, [sp, #64]             // 16-byte Folded Spill
	stp	x28, x27, [sp, #80]             // 16-byte Folded Spill
	stp	x26, x25, [sp, #96]             // 16-byte Folded Spill
	stp	x24, x23, [sp, #112]            // 16-byte Folded Spill
	stp	x22, x21, [sp, #128]            // 16-byte Folded Spill
	stp	x20, x19, [sp, #144]            // 16-byte Folded Spill
	sub	sp, sp, #416                    // =416
                                        // kill: def $w5 killed $w5 def $x5
	str	x3, [sp, #40]                   // 8-byte Folded Spill
	ldr	x3, [sp, #584]
	ldrb	w19, [sp, #576]
	cmp	x1, #4                          // =4
	b.lo	.LBB0_6
// %bb.1:
	sbfx	x8, x5, #0, #1
	and	x10, x8, #0x1
	and	x11, x8, #0x2
	and	x12, x8, #0x3
	orr	w13, w7, w6
	mov	w8, #58983
	movk	w8, #27145, lsl #16
	dup	v0.4s, w8
	mov	w8, #44677
	movk	w8, #47975, lsl #16
	dup	v1.4s, w8
	mov	w8, #62322
	movk	w8, #15470, lsl #16
	dup	v2.4s, w8
	mov	w8, #62778
	movk	w8, #42319, lsl #16
	dup	v3.4s, w8
	stp	q3, q0, [sp, #112]              // 32-byte Folded Spill
	stp	q2, q1, [sp, #80]               // 32-byte Folded Spill
	b	.LBB0_3
.LBB0_2:                                //   in Loop: Header=BB0_3 Depth=1
	trn1	v0.4s, v13.4s, v16.4s
	trn2	v1.4s, v13.4s, v16.4s
	trn1	v2.4s, v14.4s, v17.4s
	trn2	v3.4s, v14.4s, v17.4s
	trn1	v4.4s, v8.4s, v10.4s
	trn2	v5.4s, v8.4s, v10.4s
	trn1	v6.4s, v9.4s, v31.4s
	trn2	v7.4s, v9.4s, v31.4s
	ext	v16.16b, v2.16b, v0.16b, #8
	ext	v16.16b, v0.16b, v16.16b, #8
	mov	v0.d[1], v2.d[0]
	str	q0, [sp, #384]
	mov	v0.16b, v1.16b
	mov	v2.16b, v4.16b
	ldr	q18, [sp, #384]
	mov	v17.16b, v5.16b
	mov	v2.d[1], v6.d[0]
	str	q2, [sp, #384]
	mov	v0.d[1], v3.d[0]
	ldr	q2, [sp, #384]
	stp	q18, q2, [x3]
	str	q0, [sp, #384]
	mov	v17.d[1], v7.d[0]
	ldr	q0, [sp, #384]
	str	q0, [x3, #32]
	str	q17, [sp, #384]
	ext	v0.16b, v6.16b, v4.16b, #8
	ext	v0.16b, v4.16b, v0.16b, #8
	ldr	q4, [sp, #384]
	str	q16, [sp, #384]
	ext	v2.16b, v3.16b, v1.16b, #8
	ext	v1.16b, v1.16b, v2.16b, #8
	ldr	q2, [sp, #384]
	stp	q4, q2, [x3, #48]
	str	q0, [sp, #384]
	ext	v0.16b, v7.16b, v5.16b, #8
	ext	v0.16b, v5.16b, v0.16b, #8
	ldr	q2, [sp, #384]
	str	q1, [sp, #384]
	add	x8, x4, #4                      // =4
	tst	w5, #0x1
	ldr	q1, [sp, #384]
	stp	q2, q1, [x3, #80]
	str	q0, [sp, #384]
	add	x0, x0, #32                     // =32
	csel	x4, x8, x4, ne
	ldr	q0, [sp, #384]
	str	q0, [x3, #112]
	sub	x1, x1, #4                      // =4
	add	x3, x3, #128                    // =128
	cmp	x1, #3                          // =3
	b.ls	.LBB0_6
.LBB0_3:                                // =>This Loop Header: Depth=1
                                        //     Child Loop BB0_5 Depth 2
	ldr	x9, [sp, #40]                   // 8-byte Folded Reload
	mov	x8, x9
	ld1r	{ v13.4s }, [x8], #4
	ld1r	{ v16.4s }, [x8]
	add	x8, x9, #8                      // =8
	ld1r	{ v14.4s }, [x8]
	add	x8, x9, #12                     // =12
	ld1r	{ v17.4s }, [x8]
	add	x8, x9, #16                     // =16
	ld1r	{ v8.4s }, [x8]
	add	x8, x9, #20                     // =20
	ld1r	{ v10.4s }, [x8]
	add	x8, x9, #24                     // =24
	ld1r	{ v9.4s }, [x8]
	add	x8, x9, #28                     // =28
	ld1r	{ v31.4s }, [x8]
	cbz	x2, .LBB0_2
// %bb.4:                               //   in Loop: Header=BB0_3 Depth=1
	add	x8, x4, x10
	fmov	s4, w4
	mov	v4.s[1], w8
	add	x9, x4, x11
	mov	v4.s[2], w9
	add	x14, x4, x12
	mov	v4.s[3], w14
	str	q4, [sp, #160]                  // 16-byte Folded Spill
	lsr	x15, x4, #32
	lsr	x8, x8, #32
	lsr	x9, x9, #32
	fmov	s4, w15
	mov	v4.s[1], w8
	lsr	x8, x14, #32
	mov	v4.s[2], w9
	mov	v4.s[3], w8
	str	q4, [sp, #144]                  // 16-byte Folded Spill
	ldp	x8, x9, [x0]
	add	x14, x9, #32                    // =32
	add	x15, x8, #32                    // =32
	ldp	x8, x9, [x0, #16]
	add	x16, x9, #32                    // =32
	add	x17, x8, #32                    // =32
	mov	x18, x2
	mov	w8, w13
.LBB0_5:                                //   Parent Loop BB0_3 Depth=1
                                        // =>  This Inner Loop Header: Depth=2
	str	q16, [sp, #240]                 // 16-byte Folded Spill
	str	q17, [sp, #320]                 // 16-byte Folded Spill
	subs	x18, x18, #1                    // =1
	ldp	q7, q17, [x15, #-32]
	ldp	q16, q18, [x14, #-32]
	ldp	q19, q21, [x17, #-32]
	ldp	q22, q25, [x16, #-32]
	csel	w9, w19, wzr, eq
	ldp	q27, q24, [x15]
	orr	w8, w9, w8
	ldp	q2, q15, [x16]
	and	w8, w8, #0xff
	trn1	v23.4s, v7.4s, v16.4s
	trn2	v26.4s, v7.4s, v16.4s
	trn1	v5.4s, v19.4s, v22.4s
	trn2	v6.4s, v19.4s, v22.4s
	ext	v7.16b, v5.16b, v23.16b, #8
	ext	v11.16b, v23.16b, v7.16b, #8
	ext	v7.16b, v6.16b, v26.16b, #8
	trn1	v16.4s, v17.4s, v18.4s
	trn2	v22.4s, v17.4s, v18.4s
	ext	v18.16b, v26.16b, v7.16b, #8
	trn1	v0.4s, v21.4s, v25.4s
	ext	v7.16b, v0.16b, v16.16b, #8
	ext	v12.16b, v16.16b, v7.16b, #8
	str	q12, [sp, #368]                 // 16-byte Folded Spill
	trn2	v1.4s, v21.4s, v25.4s
	ext	v21.16b, v1.16b, v22.16b, #8
	ldp	q25, q30, [x14]
	trn1	v28.4s, v27.4s, v25.4s
	ldp	q29, q3, [x17]
	trn2	v25.4s, v27.4s, v25.4s
	trn1	v4.4s, v29.4s, v2.4s
	ext	v21.16b, v22.16b, v21.16b, #8
	trn2	v2.4s, v29.4s, v2.4s
	ext	v27.16b, v4.16b, v28.16b, #8
	ext	v7.16b, v28.16b, v27.16b, #8
	ext	v27.16b, v2.16b, v25.16b, #8
	mov	v17.16b, v28.16b
	trn1	v20.4s, v24.4s, v30.4s
	trn2	v19.4s, v24.4s, v30.4s
	ext	v27.16b, v25.16b, v27.16b, #8
	trn1	v24.4s, v3.4s, v15.4s
	trn2	v15.4s, v3.4s, v15.4s
	ext	v3.16b, v24.16b, v20.16b, #8
	mov	v23.d[1], v5.d[0]
	str	q23, [sp, #208]                 // 16-byte Folded Spill
	ext	v29.16b, v20.16b, v3.16b, #8
	mov	v16.d[1], v0.d[0]
	dup	v0.4s, w8
	ext	v5.16b, v15.16b, v19.16b, #8
	mov	v26.d[1], v6.d[0]
	ext	v30.16b, v19.16b, v5.16b, #8
	mov	v22.d[1], v1.d[0]
	str	q22, [sp, #272]                 // 16-byte Folded Spill
	mov	v17.d[1], v4.d[0]
	add	v1.4s, v13.4s, v8.4s
	mov	v25.d[1], v2.d[0]
	ldr	q2, [sp, #240]                  // 16-byte Folded Reload
	add	v2.4s, v2.4s, v10.4s
	add	v3.4s, v2.4s, v11.4s
	mov	v28.16b, v11.16b
	add	v1.4s, v1.4s, v23.4s
	add	v4.4s, v14.4s, v9.4s
	ldr	q2, [sp, #320]                  // 16-byte Folded Reload
	add	v5.4s, v2.4s, v31.4s
	add	v4.4s, v4.4s, v16.4s
	mov	v23.16b, v16.16b
	str	q16, [sp, #352]                 // 16-byte Folded Spill
	add	v5.4s, v5.4s, v12.4s
	mov	v20.d[1], v24.d[0]
	ldr	q2, [sp, #144]                  // 16-byte Folded Reload
	eor	v6.16b, v3.16b, v2.16b
	eor	v0.16b, v5.16b, v0.16b
	ldr	q2, [sp, #160]                  // 16-byte Folded Reload
	eor	v24.16b, v1.16b, v2.16b
	ushr	v11.4s, v6.4s, #16
	shl	v6.4s, v6.4s, #16
	ushr	v12.4s, v24.4s, #16
	orr	v6.16b, v6.16b, v11.16b
	ushr	v11.4s, v4.4s, #16
	shl	v24.4s, v24.4s, #16
	shl	v13.4s, v4.4s, #16
	orr	v11.16b, v13.16b, v11.16b
	orr	v24.16b, v24.16b, v12.16b
	ushr	v12.4s, v5.4s, #16
	shl	v0.4s, v0.4s, #16
	movi	v2.4s, #64, lsl #16
	eor	v11.16b, v11.16b, v2.16b
	orr	v2.16b, v0.16b, v12.16b
	mov	v19.d[1], v15.d[0]
	ldr	q0, [sp, #128]                  // 16-byte Folded Reload
	add	v12.4s, v24.4s, v0.4s
	ldr	q0, [sp, #96]                   // 16-byte Folded Reload
	add	v13.4s, v6.4s, v0.4s
	ldr	q0, [sp, #80]                   // 16-byte Folded Reload
	add	v14.4s, v11.4s, v0.4s
	eor	v8.16b, v12.16b, v8.16b
	eor	v10.16b, v13.16b, v10.16b
	eor	v9.16b, v14.16b, v9.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	orr	v10.16b, v10.16b, v15.16b
	ushr	v15.4s, v8.4s, #12
	shl	v8.4s, v8.4s, #20
	orr	v8.16b, v8.16b, v15.16b
	ushr	v15.4s, v9.4s, #12
	shl	v9.4s, v9.4s, #20
	orr	v9.16b, v9.16b, v15.16b
	ldr	q0, [sp, #112]                  // 16-byte Folded Reload
	add	v15.4s, v2.4s, v0.4s
	eor	v31.16b, v15.16b, v31.16b
	ushr	v0.4s, v31.4s, #12
	shl	v31.4s, v31.4s, #20
	orr	v0.16b, v31.16b, v0.16b
	add	v1.4s, v1.4s, v26.4s
	str	q26, [sp, #336]                 // 16-byte Folded Spill
	add	v1.4s, v1.4s, v8.4s
	eor	v24.16b, v1.16b, v24.16b
	ushr	v31.4s, v24.4s, #8
	shl	v24.4s, v24.4s, #24
	orr	v24.16b, v24.16b, v31.16b
	add	v3.4s, v3.4s, v18.4s
	add	v3.4s, v3.4s, v10.4s
	eor	v6.16b, v3.16b, v6.16b
	ushr	v31.4s, v6.4s, #8
	shl	v6.4s, v6.4s, #24
	orr	v6.16b, v6.16b, v31.16b
	add	v4.4s, v4.4s, v22.4s
	add	v4.4s, v4.4s, v9.4s
	eor	v31.16b, v4.16b, v11.16b
	ushr	v11.4s, v31.4s, #8
	shl	v31.4s, v31.4s, #24
	orr	v31.16b, v31.16b, v11.16b
	add	v5.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v0.4s
	eor	v2.16b, v5.16b, v2.16b
	ushr	v11.4s, v2.4s, #8
	shl	v2.4s, v2.4s, #24
	orr	v2.16b, v2.16b, v11.16b
	add	v11.4s, v6.4s, v13.4s
	eor	v10.16b, v11.16b, v10.16b
	ushr	v13.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	orr	v10.16b, v10.16b, v13.16b
	add	v12.4s, v24.4s, v12.4s
	eor	v8.16b, v12.16b, v8.16b
	ushr	v13.4s, v8.4s, #7
	shl	v8.4s, v8.4s, #25
	orr	v8.16b, v8.16b, v13.16b
	add	v13.4s, v31.4s, v14.4s
	eor	v9.16b, v13.16b, v9.16b
	ushr	v14.4s, v9.4s, #7
	shl	v9.4s, v9.4s, #25
	orr	v9.16b, v9.16b, v14.16b
	add	v14.4s, v2.4s, v15.4s
	eor	v0.16b, v14.16b, v0.16b
	ushr	v15.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	orr	v0.16b, v0.16b, v15.16b
	add	v1.4s, v1.4s, v17.4s
	add	v1.4s, v1.4s, v10.4s
	eor	v2.16b, v1.16b, v2.16b
	ushr	v15.4s, v2.4s, #16
	shl	v2.4s, v2.4s, #16
	orr	v2.16b, v2.16b, v15.16b
	add	v3.4s, v3.4s, v7.4s
	add	v3.4s, v3.4s, v9.4s
	eor	v24.16b, v3.16b, v24.16b
	ushr	v15.4s, v24.4s, #16
	shl	v24.4s, v24.4s, #16
	orr	v24.16b, v24.16b, v15.16b
	add	v4.4s, v4.4s, v20.4s
	add	v4.4s, v4.4s, v0.4s
	eor	v6.16b, v4.16b, v6.16b
	ushr	v15.4s, v6.4s, #16
	shl	v6.4s, v6.4s, #16
	orr	v6.16b, v6.16b, v15.16b
	add	v5.4s, v5.4s, v29.4s
	add	v5.4s, v5.4s, v8.4s
	eor	v31.16b, v5.16b, v31.16b
	ushr	v15.4s, v31.4s, #16
	shl	v31.4s, v31.4s, #16
	orr	v31.16b, v31.16b, v15.16b
	add	v13.4s, v2.4s, v13.4s
	eor	v10.16b, v13.16b, v10.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	orr	v10.16b, v10.16b, v15.16b
	add	v14.4s, v24.4s, v14.4s
	eor	v9.16b, v14.16b, v9.16b
	ushr	v15.4s, v9.4s, #12
	shl	v9.4s, v9.4s, #20
	orr	v9.16b, v9.16b, v15.16b
	add	v12.4s, v6.4s, v12.4s
	eor	v0.16b, v12.16b, v0.16b
	ushr	v15.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	orr	v0.16b, v0.16b, v15.16b
	add	v11.4s, v31.4s, v11.4s
	eor	v8.16b, v11.16b, v8.16b
	ushr	v15.4s, v8.4s, #12
	shl	v8.4s, v8.4s, #20
	orr	v8.16b, v8.16b, v15.16b
	add	v1.4s, v1.4s, v25.4s
	add	v1.4s, v1.4s, v10.4s
	eor	v2.16b, v1.16b, v2.16b
	ushr	v15.4s, v2.4s, #8
	shl	v2.4s, v2.4s, #24
	orr	v2.16b, v2.16b, v15.16b
	add	v4.4s, v4.4s, v19.4s
	add	v4.4s, v4.4s, v0.4s
	eor	v6.16b, v4.16b, v6.16b
	ushr	v15.4s, v6.4s, #8
	shl	v6.4s, v6.4s, #24
	orr	v6.16b, v6.16b, v15.16b
	add	v3.4s, v3.4s, v27.4s
	add	v3.4s, v3.4s, v9.4s
	eor	v24.16b, v3.16b, v24.16b
	ushr	v15.4s, v24.4s, #8
	shl	v24.4s, v24.4s, #24
	orr	v24.16b, v24.16b, v15.16b
	str	q30, [sp, #192]                 // 16-byte Folded Spill
	add	v5.4s, v5.4s, v30.4s
	add	v5.4s, v5.4s, v8.4s
	eor	v31.16b, v5.16b, v31.16b
	ushr	v15.4s, v31.4s, #8
	shl	v31.4s, v31.4s, #24
	orr	v31.16b, v31.16b, v15.16b
	add	v13.4s, v2.4s, v13.4s
	eor	v10.16b, v13.16b, v10.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	orr	v10.16b, v10.16b, v15.16b
	add	v12.4s, v6.4s, v12.4s
	eor	v0.16b, v12.16b, v0.16b
	ushr	v15.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	orr	v0.16b, v0.16b, v15.16b
	add	v14.4s, v24.4s, v14.4s
	eor	v9.16b, v14.16b, v9.16b
	ushr	v15.4s, v9.4s, #7
	shl	v9.4s, v9.4s, #25
	orr	v9.16b, v9.16b, v15.16b
	add	v11.4s, v31.4s, v11.4s
	eor	v8.16b, v11.16b, v8.16b
	ushr	v15.4s, v8.4s, #7
	shl	v8.4s, v8.4s, #25
	orr	v8.16b, v8.16b, v15.16b
	mov	v16.16b, v28.16b
	str	q28, [sp, #256]                 // 16-byte Folded Spill
	add	v1.4s, v1.4s, v28.4s
	add	v1.4s, v1.4s, v8.4s
	eor	v24.16b, v1.16b, v24.16b
	ushr	v15.4s, v24.4s, #16
	shl	v24.4s, v24.4s, #16
	orr	v24.16b, v24.16b, v15.16b
	str	q18, [sp, #224]                 // 16-byte Folded Spill
	add	v3.4s, v3.4s, v18.4s
	add	v3.4s, v3.4s, v10.4s
	eor	v6.16b, v3.16b, v6.16b
	ushr	v15.4s, v6.4s, #16
	shl	v6.4s, v6.4s, #16
	orr	v6.16b, v6.16b, v15.16b
	mov	v28.16b, v21.16b
	add	v4.4s, v4.4s, v21.4s
	add	v4.4s, v4.4s, v9.4s
	eor	v31.16b, v4.16b, v31.16b
	ushr	v15.4s, v31.4s, #16
	shl	v31.4s, v31.4s, #16
	orr	v31.16b, v31.16b, v15.16b
	add	v5.4s, v5.4s, v23.4s
	add	v5.4s, v5.4s, v0.4s
	eor	v2.16b, v5.16b, v2.16b
	ushr	v15.4s, v2.4s, #16
	shl	v2.4s, v2.4s, #16
	orr	v2.16b, v2.16b, v15.16b
	add	v11.4s, v6.4s, v11.4s
	eor	v10.16b, v11.16b, v10.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	orr	v10.16b, v10.16b, v15.16b
	add	v12.4s, v24.4s, v12.4s
	eor	v8.16b, v12.16b, v8.16b
	ushr	v15.4s, v8.4s, #12
	shl	v8.4s, v8.4s, #20
	orr	v8.16b, v8.16b, v15.16b
	add	v13.4s, v31.4s, v13.4s
	eor	v9.16b, v13.16b, v9.16b
	ushr	v15.4s, v9.4s, #12
	shl	v9.4s, v9.4s, #20
	orr	v9.16b, v9.16b, v15.16b
	add	v14.4s, v2.4s, v14.4s
	eor	v0.16b, v14.16b, v0.16b
	ushr	v15.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	orr	v0.16b, v0.16b, v15.16b
	ldr	q23, [sp, #368]                 // 16-byte Folded Reload
	add	v1.4s, v1.4s, v23.4s
	add	v1.4s, v1.4s, v8.4s
	eor	v24.16b, v1.16b, v24.16b
	ushr	v15.4s, v24.4s, #8
	shl	v24.4s, v24.4s, #24
	orr	v24.16b, v24.16b, v15.16b
	add	v3.4s, v3.4s, v7.4s
	add	v3.4s, v3.4s, v10.4s
	eor	v6.16b, v3.16b, v6.16b
	ushr	v15.4s, v6.4s, #8
	shl	v6.4s, v6.4s, #24
	orr	v6.16b, v6.16b, v15.16b
	ldr	q22, [sp, #208]                 // 16-byte Folded Reload
	add	v4.4s, v4.4s, v22.4s
	add	v4.4s, v4.4s, v9.4s
	eor	v31.16b, v4.16b, v31.16b
	ushr	v15.4s, v31.4s, #8
	shl	v31.4s, v31.4s, #24
	orr	v31.16b, v31.16b, v15.16b
	add	v5.4s, v5.4s, v19.4s
	add	v5.4s, v5.4s, v0.4s
	eor	v2.16b, v5.16b, v2.16b
	ushr	v15.4s, v2.4s, #8
	shl	v2.4s, v2.4s, #24
	orr	v2.16b, v2.16b, v15.16b
	add	v12.4s, v24.4s, v12.4s
	eor	v8.16b, v12.16b, v8.16b
	ushr	v15.4s, v8.4s, #7
	shl	v8.4s, v8.4s, #25
	orr	v8.16b, v8.16b, v15.16b
	add	v11.4s, v6.4s, v11.4s
	eor	v10.16b, v11.16b, v10.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	orr	v10.16b, v10.16b, v15.16b
	add	v14.4s, v2.4s, v14.4s
	eor	v0.16b, v14.16b, v0.16b
	ushr	v15.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	orr	v0.16b, v0.16b, v15.16b
	add	v13.4s, v31.4s, v13.4s
	eor	v9.16b, v13.16b, v9.16b
	ushr	v15.4s, v9.4s, #7
	shl	v9.4s, v9.4s, #25
	orr	v9.16b, v9.16b, v15.16b
	add	v1.4s, v1.4s, v26.4s
	add	v1.4s, v1.4s, v10.4s
	eor	v2.16b, v1.16b, v2.16b
	ushr	v15.4s, v2.4s, #16
	shl	v2.4s, v2.4s, #16
	orr	v2.16b, v2.16b, v15.16b
	add	v4.4s, v4.4s, v25.4s
	add	v4.4s, v4.4s, v0.4s
	eor	v6.16b, v4.16b, v6.16b
	ushr	v15.4s, v6.4s, #16
	shl	v6.4s, v6.4s, #16
	orr	v6.16b, v6.16b, v15.16b
	add	v3.4s, v3.4s, v20.4s
	add	v3.4s, v3.4s, v9.4s
	eor	v24.16b, v3.16b, v24.16b
	ushr	v15.4s, v24.4s, #16
	shl	v24.4s, v24.4s, #16
	orr	v24.16b, v24.16b, v15.16b
	add	v5.4s, v5.4s, v30.4s
	add	v5.4s, v5.4s, v8.4s
	eor	v31.16b, v5.16b, v31.16b
	ushr	v15.4s, v31.4s, #16
	shl	v31.4s, v31.4s, #16
	orr	v31.16b, v31.16b, v15.16b
	add	v13.4s, v2.4s, v13.4s
	eor	v10.16b, v13.16b, v10.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	orr	v10.16b, v10.16b, v15.16b
	add	v12.4s, v6.4s, v12.4s
	eor	v0.16b, v12.16b, v0.16b
	ushr	v15.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	orr	v0.16b, v0.16b, v15.16b
	add	v14.4s, v24.4s, v14.4s
	eor	v9.16b, v14.16b, v9.16b
	ushr	v15.4s, v9.4s, #12
	shl	v9.4s, v9.4s, #20
	orr	v9.16b, v9.16b, v15.16b
	add	v11.4s, v31.4s, v11.4s
	eor	v8.16b, v11.16b, v8.16b
	ushr	v15.4s, v8.4s, #12
	shl	v8.4s, v8.4s, #20
	orr	v8.16b, v8.16b, v15.16b
	add	v1.4s, v1.4s, v27.4s
	mov	v30.16b, v27.16b
	add	v1.4s, v1.4s, v10.4s
	eor	v2.16b, v1.16b, v2.16b
	ushr	v15.4s, v2.4s, #8
	shl	v2.4s, v2.4s, #24
	orr	v2.16b, v2.16b, v15.16b
	ldr	q26, [sp, #272]                 // 16-byte Folded Reload
	add	v3.4s, v3.4s, v26.4s
	add	v3.4s, v3.4s, v9.4s
	eor	v24.16b, v3.16b, v24.16b
	ushr	v15.4s, v24.4s, #8
	shl	v24.4s, v24.4s, #24
	orr	v24.16b, v24.16b, v15.16b
	add	v4.4s, v4.4s, v29.4s
	add	v4.4s, v4.4s, v0.4s
	eor	v6.16b, v4.16b, v6.16b
	ushr	v15.4s, v6.4s, #8
	shl	v6.4s, v6.4s, #24
	orr	v6.16b, v6.16b, v15.16b
	mov	v27.16b, v17.16b
	str	q17, [sp, #176]                 // 16-byte Folded Spill
	add	v5.4s, v5.4s, v17.4s
	add	v5.4s, v5.4s, v8.4s
	eor	v31.16b, v5.16b, v31.16b
	ushr	v15.4s, v31.4s, #8
	shl	v31.4s, v31.4s, #24
	orr	v31.16b, v31.16b, v15.16b
	add	v13.4s, v2.4s, v13.4s
	eor	v10.16b, v13.16b, v10.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	orr	v10.16b, v10.16b, v15.16b
	add	v14.4s, v24.4s, v14.4s
	eor	v9.16b, v14.16b, v9.16b
	ushr	v15.4s, v9.4s, #7
	shl	v9.4s, v9.4s, #25
	orr	v9.16b, v9.16b, v15.16b
	add	v12.4s, v6.4s, v12.4s
	eor	v0.16b, v12.16b, v0.16b
	ushr	v15.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	orr	v0.16b, v0.16b, v15.16b
	add	v11.4s, v31.4s, v11.4s
	eor	v8.16b, v11.16b, v8.16b
	ushr	v15.4s, v8.4s, #7
	shl	v8.4s, v8.4s, #25
	orr	v8.16b, v8.16b, v15.16b
	add	v1.4s, v1.4s, v18.4s
	add	v1.4s, v1.4s, v8.4s
	eor	v24.16b, v1.16b, v24.16b
	ushr	v15.4s, v24.4s, #16
	shl	v24.4s, v24.4s, #16
	orr	v24.16b, v24.16b, v15.16b
	add	v3.4s, v3.4s, v7.4s
	add	v3.4s, v3.4s, v10.4s
	eor	v6.16b, v3.16b, v6.16b
	ushr	v15.4s, v6.4s, #16
	shl	v6.4s, v6.4s, #16
	orr	v6.16b, v6.16b, v15.16b
	add	v4.4s, v4.4s, v19.4s
	str	q19, [sp, #320]                 // 16-byte Folded Spill
	add	v4.4s, v4.4s, v9.4s
	eor	v31.16b, v4.16b, v31.16b
	ushr	v15.4s, v31.4s, #16
	shl	v31.4s, v31.4s, #16
	orr	v31.16b, v31.16b, v15.16b
	add	v5.4s, v5.4s, v21.4s
	add	v5.4s, v5.4s, v0.4s
	eor	v2.16b, v5.16b, v2.16b
	ushr	v15.4s, v2.4s, #16
	shl	v2.4s, v2.4s, #16
	orr	v2.16b, v2.16b, v15.16b
	add	v12.4s, v24.4s, v12.4s
	eor	v8.16b, v12.16b, v8.16b
	ushr	v15.4s, v8.4s, #12
	shl	v8.4s, v8.4s, #20
	orr	v8.16b, v8.16b, v15.16b
	add	v11.4s, v6.4s, v11.4s
	eor	v10.16b, v11.16b, v10.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	orr	v10.16b, v10.16b, v15.16b
	add	v14.4s, v2.4s, v14.4s
	eor	v0.16b, v14.16b, v0.16b
	ushr	v15.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	orr	v0.16b, v0.16b, v15.16b
	add	v13.4s, v31.4s, v13.4s
	eor	v9.16b, v13.16b, v9.16b
	ushr	v15.4s, v9.4s, #12
	shl	v9.4s, v9.4s, #20
	orr	v9.16b, v9.16b, v15.16b
	add	v3.4s, v3.4s, v20.4s
	add	v3.4s, v3.4s, v10.4s
	eor	v6.16b, v3.16b, v6.16b
	ushr	v15.4s, v6.4s, #8
	shl	v6.4s, v6.4s, #24
	orr	v6.16b, v6.16b, v15.16b
	mov	v17.16b, v29.16b
	add	v5.4s, v5.4s, v29.4s
	add	v5.4s, v5.4s, v0.4s
	eor	v2.16b, v5.16b, v2.16b
	ushr	v15.4s, v2.4s, #8
	shl	v2.4s, v2.4s, #24
	orr	v2.16b, v2.16b, v15.16b
	ldr	q21, [sp, #352]                 // 16-byte Folded Reload
	add	v1.4s, v1.4s, v21.4s
	add	v1.4s, v1.4s, v8.4s
	eor	v24.16b, v1.16b, v24.16b
	ushr	v15.4s, v24.4s, #8
	shl	v24.4s, v24.4s, #24
	orr	v24.16b, v24.16b, v15.16b
	add	v4.4s, v4.4s, v16.4s
	add	v4.4s, v4.4s, v9.4s
	eor	v31.16b, v4.16b, v31.16b
	ushr	v15.4s, v31.4s, #8
	shl	v31.4s, v31.4s, #24
	orr	v31.16b, v31.16b, v15.16b
	add	v12.4s, v24.4s, v12.4s
	eor	v8.16b, v12.16b, v8.16b
	ushr	v15.4s, v8.4s, #7
	shl	v8.4s, v8.4s, #25
	orr	v8.16b, v8.16b, v15.16b
	add	v11.4s, v6.4s, v11.4s
	eor	v10.16b, v11.16b, v10.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	orr	v10.16b, v10.16b, v15.16b
	add	v13.4s, v31.4s, v13.4s
	eor	v9.16b, v13.16b, v9.16b
	ushr	v15.4s, v9.4s, #7
	shl	v9.4s, v9.4s, #25
	orr	v9.16b, v9.16b, v15.16b
	add	v14.4s, v2.4s, v14.4s
	eor	v0.16b, v14.16b, v0.16b
	ushr	v15.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	orr	v0.16b, v0.16b, v15.16b
	add	v1.4s, v1.4s, v23.4s
	add	v1.4s, v1.4s, v10.4s
	eor	v2.16b, v1.16b, v2.16b
	ushr	v15.4s, v2.4s, #16
	shl	v2.4s, v2.4s, #16
	orr	v2.16b, v2.16b, v15.16b
	add	v3.4s, v3.4s, v25.4s
	add	v3.4s, v3.4s, v9.4s
	eor	v24.16b, v3.16b, v24.16b
	ushr	v15.4s, v24.4s, #16
	shl	v24.4s, v24.4s, #16
	orr	v24.16b, v24.16b, v15.16b
	add	v4.4s, v4.4s, v30.4s
	mov	v18.16b, v30.16b
	add	v4.4s, v4.4s, v0.4s
	eor	v6.16b, v4.16b, v6.16b
	ushr	v15.4s, v6.4s, #16
	shl	v6.4s, v6.4s, #16
	orr	v6.16b, v6.16b, v15.16b
	add	v5.4s, v5.4s, v27.4s
	add	v5.4s, v5.4s, v8.4s
	eor	v31.16b, v5.16b, v31.16b
	ushr	v15.4s, v31.4s, #16
	shl	v31.4s, v31.4s, #16
	orr	v31.16b, v31.16b, v15.16b
	add	v13.4s, v2.4s, v13.4s
	eor	v10.16b, v13.16b, v10.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	orr	v10.16b, v10.16b, v15.16b
	add	v14.4s, v24.4s, v14.4s
	eor	v9.16b, v14.16b, v9.16b
	ushr	v15.4s, v9.4s, #12
	shl	v9.4s, v9.4s, #20
	orr	v9.16b, v9.16b, v15.16b
	add	v12.4s, v6.4s, v12.4s
	eor	v0.16b, v12.16b, v0.16b
	ushr	v15.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	orr	v0.16b, v0.16b, v15.16b
	add	v11.4s, v31.4s, v11.4s
	eor	v8.16b, v11.16b, v8.16b
	ushr	v15.4s, v8.4s, #12
	shl	v8.4s, v8.4s, #20
	orr	v8.16b, v8.16b, v15.16b
	add	v1.4s, v1.4s, v26.4s
	mov	v29.16b, v26.16b
	add	v1.4s, v1.4s, v10.4s
	eor	v2.16b, v1.16b, v2.16b
	ushr	v15.4s, v2.4s, #8
	shl	v2.4s, v2.4s, #24
	orr	v2.16b, v2.16b, v15.16b
	mov	v16.16b, v22.16b
	add	v3.4s, v3.4s, v22.4s
	add	v3.4s, v3.4s, v9.4s
	eor	v24.16b, v3.16b, v24.16b
	ushr	v15.4s, v24.4s, #8
	shl	v24.4s, v24.4s, #24
	orr	v24.16b, v24.16b, v15.16b
	ldr	q30, [sp, #192]                 // 16-byte Folded Reload
	add	v4.4s, v4.4s, v30.4s
	add	v4.4s, v4.4s, v0.4s
	eor	v6.16b, v4.16b, v6.16b
	ushr	v15.4s, v6.4s, #8
	shl	v6.4s, v6.4s, #24
	orr	v6.16b, v6.16b, v15.16b
	ldr	q23, [sp, #336]                 // 16-byte Folded Reload
	add	v5.4s, v5.4s, v23.4s
	add	v5.4s, v5.4s, v8.4s
	eor	v31.16b, v5.16b, v31.16b
	ushr	v15.4s, v31.4s, #8
	shl	v31.4s, v31.4s, #24
	orr	v31.16b, v31.16b, v15.16b
	add	v13.4s, v2.4s, v13.4s
	eor	v10.16b, v13.16b, v10.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	orr	v10.16b, v10.16b, v15.16b
	add	v14.4s, v24.4s, v14.4s
	eor	v9.16b, v14.16b, v9.16b
	ushr	v15.4s, v9.4s, #7
	shl	v9.4s, v9.4s, #25
	orr	v9.16b, v9.16b, v15.16b
	add	v12.4s, v6.4s, v12.4s
	eor	v0.16b, v12.16b, v0.16b
	ushr	v15.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	orr	v0.16b, v0.16b, v15.16b
	add	v11.4s, v31.4s, v11.4s
	eor	v8.16b, v11.16b, v8.16b
	ushr	v15.4s, v8.4s, #7
	shl	v8.4s, v8.4s, #25
	orr	v8.16b, v8.16b, v15.16b
	add	v3.4s, v3.4s, v20.4s
	str	q20, [sp, #240]                 // 16-byte Folded Spill
	add	v3.4s, v3.4s, v10.4s
	eor	v6.16b, v3.16b, v6.16b
	ushr	v15.4s, v6.4s, #16
	shl	v6.4s, v6.4s, #16
	orr	v6.16b, v6.16b, v15.16b
	add	v5.4s, v5.4s, v19.4s
	add	v5.4s, v5.4s, v0.4s
	eor	v2.16b, v5.16b, v2.16b
	ushr	v15.4s, v2.4s, #16
	shl	v2.4s, v2.4s, #16
	orr	v2.16b, v2.16b, v15.16b
	add	v1.4s, v1.4s, v7.4s
	mov	v22.16b, v7.16b
	str	q7, [sp, #304]                  // 16-byte Folded Spill
	add	v1.4s, v1.4s, v8.4s
	eor	v24.16b, v1.16b, v24.16b
	ushr	v15.4s, v24.4s, #16
	shl	v24.4s, v24.4s, #16
	orr	v24.16b, v24.16b, v15.16b
	add	v4.4s, v4.4s, v17.4s
	add	v4.4s, v4.4s, v9.4s
	eor	v31.16b, v4.16b, v31.16b
	ushr	v15.4s, v31.4s, #16
	shl	v31.4s, v31.4s, #16
	orr	v31.16b, v31.16b, v15.16b
	add	v12.4s, v24.4s, v12.4s
	eor	v8.16b, v12.16b, v8.16b
	ushr	v15.4s, v8.4s, #12
	shl	v8.4s, v8.4s, #20
	orr	v8.16b, v8.16b, v15.16b
	add	v11.4s, v6.4s, v11.4s
	eor	v10.16b, v11.16b, v10.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	orr	v10.16b, v10.16b, v15.16b
	add	v13.4s, v31.4s, v13.4s
	eor	v9.16b, v13.16b, v9.16b
	ushr	v15.4s, v9.4s, #12
	shl	v9.4s, v9.4s, #20
	orr	v9.16b, v9.16b, v15.16b
	add	v14.4s, v2.4s, v14.4s
	eor	v0.16b, v14.16b, v0.16b
	ushr	v15.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	orr	v0.16b, v0.16b, v15.16b
	mov	v27.16b, v28.16b
	str	q28, [sp, #288]                 // 16-byte Folded Spill
	add	v1.4s, v1.4s, v28.4s
	add	v1.4s, v1.4s, v8.4s
	eor	v24.16b, v1.16b, v24.16b
	ushr	v15.4s, v24.4s, #8
	shl	v24.4s, v24.4s, #24
	orr	v24.16b, v24.16b, v15.16b
	add	v3.4s, v3.4s, v25.4s
	add	v3.4s, v3.4s, v10.4s
	eor	v6.16b, v3.16b, v6.16b
	ushr	v15.4s, v6.4s, #8
	shl	v6.4s, v6.4s, #24
	orr	v6.16b, v6.16b, v15.16b
	ldr	q26, [sp, #224]                 // 16-byte Folded Reload
	add	v4.4s, v4.4s, v26.4s
	add	v4.4s, v4.4s, v9.4s
	eor	v31.16b, v4.16b, v31.16b
	ushr	v15.4s, v31.4s, #8
	shl	v31.4s, v31.4s, #24
	orr	v31.16b, v31.16b, v15.16b
	add	v5.4s, v5.4s, v30.4s
	mov	v19.16b, v30.16b
	add	v5.4s, v5.4s, v0.4s
	eor	v2.16b, v5.16b, v2.16b
	ushr	v15.4s, v2.4s, #8
	shl	v2.4s, v2.4s, #24
	orr	v2.16b, v2.16b, v15.16b
	add	v11.4s, v6.4s, v11.4s
	eor	v10.16b, v11.16b, v10.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	orr	v10.16b, v10.16b, v15.16b
	add	v12.4s, v24.4s, v12.4s
	eor	v8.16b, v12.16b, v8.16b
	ushr	v15.4s, v8.4s, #7
	shl	v8.4s, v8.4s, #25
	orr	v8.16b, v8.16b, v15.16b
	add	v13.4s, v31.4s, v13.4s
	eor	v9.16b, v13.16b, v9.16b
	ushr	v15.4s, v9.4s, #7
	shl	v9.4s, v9.4s, #25
	orr	v9.16b, v9.16b, v15.16b
	add	v14.4s, v2.4s, v14.4s
	eor	v0.16b, v14.16b, v0.16b
	ushr	v15.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	orr	v0.16b, v0.16b, v15.16b
	add	v1.4s, v1.4s, v21.4s
	add	v1.4s, v1.4s, v10.4s
	eor	v2.16b, v1.16b, v2.16b
	ushr	v15.4s, v2.4s, #16
	shl	v2.4s, v2.4s, #16
	orr	v2.16b, v2.16b, v15.16b
	mov	v30.16b, v18.16b
	add	v3.4s, v3.4s, v18.4s
	add	v3.4s, v3.4s, v9.4s
	eor	v24.16b, v3.16b, v24.16b
	ushr	v15.4s, v24.4s, #16
	shl	v24.4s, v24.4s, #16
	orr	v24.16b, v24.16b, v15.16b
	add	v4.4s, v4.4s, v29.4s
	add	v4.4s, v4.4s, v0.4s
	eor	v6.16b, v4.16b, v6.16b
	ushr	v15.4s, v6.4s, #16
	shl	v6.4s, v6.4s, #16
	orr	v6.16b, v6.16b, v15.16b
	add	v5.4s, v5.4s, v23.4s
	add	v5.4s, v5.4s, v8.4s
	eor	v31.16b, v5.16b, v31.16b
	ushr	v15.4s, v31.4s, #16
	shl	v31.4s, v31.4s, #16
	orr	v31.16b, v31.16b, v15.16b
	add	v13.4s, v2.4s, v13.4s
	eor	v10.16b, v13.16b, v10.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	orr	v10.16b, v10.16b, v15.16b
	add	v14.4s, v24.4s, v14.4s
	eor	v9.16b, v14.16b, v9.16b
	ushr	v15.4s, v9.4s, #12
	shl	v9.4s, v9.4s, #20
	orr	v9.16b, v9.16b, v15.16b
	add	v12.4s, v6.4s, v12.4s
	eor	v0.16b, v12.16b, v0.16b
	ushr	v15.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	orr	v0.16b, v0.16b, v15.16b
	add	v11.4s, v31.4s, v11.4s
	eor	v8.16b, v11.16b, v8.16b
	ushr	v15.4s, v8.4s, #12
	shl	v8.4s, v8.4s, #20
	orr	v8.16b, v8.16b, v15.16b
	mov	v23.16b, v16.16b
	add	v1.4s, v1.4s, v16.4s
	add	v1.4s, v1.4s, v10.4s
	eor	v2.16b, v1.16b, v2.16b
	ushr	v15.4s, v2.4s, #8
	shl	v2.4s, v2.4s, #24
	orr	v2.16b, v2.16b, v15.16b
	ldr	q28, [sp, #176]                 // 16-byte Folded Reload
	add	v4.4s, v4.4s, v28.4s
	add	v4.4s, v4.4s, v0.4s
	eor	v6.16b, v4.16b, v6.16b
	ushr	v15.4s, v6.4s, #8
	shl	v6.4s, v6.4s, #24
	orr	v6.16b, v6.16b, v15.16b
	ldr	q7, [sp, #256]                  // 16-byte Folded Reload
	add	v3.4s, v3.4s, v7.4s
	add	v3.4s, v3.4s, v9.4s
	eor	v24.16b, v3.16b, v24.16b
	ushr	v15.4s, v24.4s, #8
	shl	v24.4s, v24.4s, #24
	orr	v24.16b, v24.16b, v15.16b
	ldr	q18, [sp, #368]                 // 16-byte Folded Reload
	add	v5.4s, v5.4s, v18.4s
	add	v5.4s, v5.4s, v8.4s
	eor	v31.16b, v5.16b, v31.16b
	ushr	v15.4s, v31.4s, #8
	shl	v31.4s, v31.4s, #24
	orr	v31.16b, v31.16b, v15.16b
	add	v13.4s, v2.4s, v13.4s
	eor	v10.16b, v13.16b, v10.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	orr	v10.16b, v10.16b, v15.16b
	add	v12.4s, v6.4s, v12.4s
	eor	v0.16b, v12.16b, v0.16b
	ushr	v15.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	orr	v0.16b, v0.16b, v15.16b
	add	v14.4s, v24.4s, v14.4s
	eor	v9.16b, v14.16b, v9.16b
	ushr	v15.4s, v9.4s, #7
	shl	v9.4s, v9.4s, #25
	orr	v9.16b, v9.16b, v15.16b
	add	v11.4s, v31.4s, v11.4s
	eor	v8.16b, v11.16b, v8.16b
	ushr	v15.4s, v8.4s, #7
	shl	v8.4s, v8.4s, #25
	orr	v8.16b, v8.16b, v15.16b
	add	v1.4s, v1.4s, v20.4s
	add	v1.4s, v1.4s, v8.4s
	eor	v24.16b, v1.16b, v24.16b
	ushr	v15.4s, v24.4s, #16
	shl	v24.4s, v24.4s, #16
	orr	v24.16b, v24.16b, v15.16b
	add	v3.4s, v3.4s, v25.4s
	add	v3.4s, v3.4s, v10.4s
	eor	v6.16b, v3.16b, v6.16b
	ushr	v15.4s, v6.4s, #16
	shl	v6.4s, v6.4s, #16
	orr	v6.16b, v6.16b, v15.16b
	add	v4.4s, v4.4s, v19.4s
	add	v4.4s, v4.4s, v9.4s
	eor	v31.16b, v4.16b, v31.16b
	ushr	v15.4s, v31.4s, #16
	shl	v31.4s, v31.4s, #16
	orr	v31.16b, v31.16b, v15.16b
	add	v5.4s, v5.4s, v17.4s
	add	v5.4s, v5.4s, v0.4s
	eor	v2.16b, v5.16b, v2.16b
	ushr	v15.4s, v2.4s, #16
	shl	v2.4s, v2.4s, #16
	orr	v2.16b, v2.16b, v15.16b
	add	v11.4s, v6.4s, v11.4s
	eor	v10.16b, v11.16b, v10.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	orr	v10.16b, v10.16b, v15.16b
	add	v12.4s, v24.4s, v12.4s
	eor	v8.16b, v12.16b, v8.16b
	ushr	v15.4s, v8.4s, #12
	shl	v8.4s, v8.4s, #20
	orr	v8.16b, v8.16b, v15.16b
	add	v13.4s, v31.4s, v13.4s
	eor	v9.16b, v13.16b, v9.16b
	ushr	v15.4s, v9.4s, #12
	shl	v9.4s, v9.4s, #20
	orr	v9.16b, v9.16b, v15.16b
	add	v14.4s, v2.4s, v14.4s
	eor	v0.16b, v14.16b, v0.16b
	ushr	v15.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	orr	v0.16b, v0.16b, v15.16b
	ldr	q16, [sp, #320]                 // 16-byte Folded Reload
	add	v1.4s, v1.4s, v16.4s
	add	v1.4s, v1.4s, v8.4s
	eor	v24.16b, v1.16b, v24.16b
	ushr	v15.4s, v24.4s, #8
	shl	v24.4s, v24.4s, #24
	orr	v24.16b, v24.16b, v15.16b
	add	v3.4s, v3.4s, v30.4s
	add	v3.4s, v3.4s, v10.4s
	eor	v6.16b, v3.16b, v6.16b
	ushr	v15.4s, v6.4s, #8
	shl	v6.4s, v6.4s, #24
	orr	v6.16b, v6.16b, v15.16b
	add	v4.4s, v4.4s, v22.4s
	add	v4.4s, v4.4s, v9.4s
	eor	v31.16b, v4.16b, v31.16b
	ushr	v15.4s, v31.4s, #8
	shl	v31.4s, v31.4s, #24
	orr	v31.16b, v31.16b, v15.16b
	add	v5.4s, v5.4s, v28.4s
	add	v5.4s, v5.4s, v0.4s
	eor	v2.16b, v5.16b, v2.16b
	ushr	v15.4s, v2.4s, #8
	shl	v2.4s, v2.4s, #24
	orr	v2.16b, v2.16b, v15.16b
	add	v12.4s, v24.4s, v12.4s
	eor	v8.16b, v12.16b, v8.16b
	ushr	v15.4s, v8.4s, #7
	shl	v8.4s, v8.4s, #25
	orr	v8.16b, v8.16b, v15.16b
	add	v11.4s, v6.4s, v11.4s
	eor	v10.16b, v11.16b, v10.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	orr	v10.16b, v10.16b, v15.16b
	add	v14.4s, v2.4s, v14.4s
	eor	v0.16b, v14.16b, v0.16b
	ushr	v15.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	orr	v0.16b, v0.16b, v15.16b
	add	v13.4s, v31.4s, v13.4s
	eor	v9.16b, v13.16b, v9.16b
	ushr	v15.4s, v9.4s, #7
	shl	v9.4s, v9.4s, #25
	orr	v9.16b, v9.16b, v15.16b
	add	v1.4s, v1.4s, v27.4s
	add	v1.4s, v1.4s, v10.4s
	eor	v2.16b, v1.16b, v2.16b
	ushr	v15.4s, v2.4s, #16
	shl	v2.4s, v2.4s, #16
	orr	v2.16b, v2.16b, v15.16b
	add	v4.4s, v4.4s, v23.4s
	add	v4.4s, v4.4s, v0.4s
	eor	v6.16b, v4.16b, v6.16b
	ushr	v15.4s, v6.4s, #16
	shl	v6.4s, v6.4s, #16
	orr	v6.16b, v6.16b, v15.16b
	add	v3.4s, v3.4s, v29.4s
	add	v3.4s, v3.4s, v9.4s
	eor	v24.16b, v3.16b, v24.16b
	ushr	v15.4s, v24.4s, #16
	shl	v24.4s, v24.4s, #16
	orr	v24.16b, v24.16b, v15.16b
	add	v5.4s, v5.4s, v18.4s
	add	v5.4s, v5.4s, v8.4s
	eor	v31.16b, v5.16b, v31.16b
	ushr	v15.4s, v31.4s, #16
	shl	v31.4s, v31.4s, #16
	orr	v31.16b, v31.16b, v15.16b
	add	v13.4s, v2.4s, v13.4s
	eor	v10.16b, v13.16b, v10.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	orr	v10.16b, v10.16b, v15.16b
	add	v12.4s, v6.4s, v12.4s
	eor	v0.16b, v12.16b, v0.16b
	ushr	v15.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	orr	v0.16b, v0.16b, v15.16b
	add	v14.4s, v24.4s, v14.4s
	eor	v9.16b, v14.16b, v9.16b
	ushr	v15.4s, v9.4s, #12
	shl	v9.4s, v9.4s, #20
	orr	v9.16b, v9.16b, v15.16b
	add	v11.4s, v31.4s, v11.4s
	eor	v8.16b, v11.16b, v8.16b
	ushr	v15.4s, v8.4s, #12
	shl	v8.4s, v8.4s, #20
	orr	v8.16b, v8.16b, v15.16b
	add	v1.4s, v1.4s, v7.4s
	mov	v20.16b, v7.16b
	add	v1.4s, v1.4s, v10.4s
	eor	v2.16b, v1.16b, v2.16b
	ushr	v15.4s, v2.4s, #8
	shl	v2.4s, v2.4s, #24
	orr	v2.16b, v2.16b, v15.16b
	mov	v21.16b, v26.16b
	add	v3.4s, v3.4s, v26.4s
	add	v3.4s, v3.4s, v9.4s
	eor	v24.16b, v3.16b, v24.16b
	ushr	v15.4s, v24.4s, #8
	shl	v24.4s, v24.4s, #24
	orr	v24.16b, v24.16b, v15.16b
	ldp	q26, q22, [sp, #336]            // 32-byte Folded Reload
	add	v4.4s, v4.4s, v26.4s
	add	v4.4s, v4.4s, v0.4s
	eor	v6.16b, v4.16b, v6.16b
	ushr	v15.4s, v6.4s, #8
	shl	v6.4s, v6.4s, #24
	orr	v6.16b, v6.16b, v15.16b
	add	v5.4s, v5.4s, v22.4s
	add	v5.4s, v5.4s, v8.4s
	eor	v31.16b, v5.16b, v31.16b
	ushr	v15.4s, v31.4s, #8
	shl	v31.4s, v31.4s, #24
	orr	v31.16b, v31.16b, v15.16b
	add	v13.4s, v2.4s, v13.4s
	eor	v10.16b, v13.16b, v10.16b
	ushr	v15.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	orr	v10.16b, v10.16b, v15.16b
	add	v14.4s, v24.4s, v14.4s
	eor	v9.16b, v14.16b, v9.16b
	ushr	v15.4s, v9.4s, #7
	shl	v9.4s, v9.4s, #25
	orr	v9.16b, v9.16b, v15.16b
	add	v12.4s, v6.4s, v12.4s
	eor	v0.16b, v12.16b, v0.16b
	ushr	v15.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	orr	v0.16b, v0.16b, v15.16b
	add	v11.4s, v31.4s, v11.4s
	eor	v8.16b, v11.16b, v8.16b
	ushr	v15.4s, v8.4s, #7
	shl	v8.4s, v8.4s, #25
	orr	v8.16b, v8.16b, v15.16b
	add	v1.4s, v1.4s, v25.4s
	mov	v27.16b, v25.16b
	add	v1.4s, v1.4s, v8.4s
	eor	v24.16b, v1.16b, v24.16b
	ushr	v15.4s, v24.4s, #16
	shl	v24.4s, v24.4s, #16
	orr	v24.16b, v24.16b, v15.16b
	add	v3.4s, v3.4s, v30.4s
	add	v3.4s, v3.4s, v10.4s
	eor	v6.16b, v3.16b, v6.16b
	ushr	v15.4s, v6.4s, #16
	shl	v6.4s, v6.4s, #16
	orr	v6.16b, v6.16b, v15.16b
	add	v4.4s, v4.4s, v28.4s
	add	v4.4s, v4.4s, v9.4s
	eor	v31.16b, v4.16b, v31.16b
	ushr	v15.4s, v31.4s, #16
	shl	v31.4s, v31.4s, #16
	orr	v31.16b, v31.16b, v15.16b
	add	v5.4s, v5.4s, v19.4s
	mov	v25.16b, v19.16b
	add	v5.4s, v5.4s, v0.4s
	eor	v2.16b, v5.16b, v2.16b
	ushr	v15.4s, v2.4s, #16
	shl	v2.4s, v2.4s, #16
	orr	v2.16b, v2.16b, v15.16b
	add	v12.4s, v24.4s, v12.4s
	eor	v8.16b, v12.16b, v8.16b
	ushr	v15.4s, v8.4s, #12
	shl	v8.4s, v8.4s, #20
	orr	v8.16b, v8.16b, v15.16b
	add	v11.4s, v6.4s, v11.4s
	eor	v10.16b, v11.16b, v10.16b
	ushr	v15.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	orr	v10.16b, v10.16b, v15.16b
	add	v14.4s, v2.4s, v14.4s
	eor	v0.16b, v14.16b, v0.16b
	ushr	v15.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	orr	v0.16b, v0.16b, v15.16b
	add	v13.4s, v31.4s, v13.4s
	eor	v9.16b, v13.16b, v9.16b
	ushr	v15.4s, v9.4s, #12
	shl	v9.4s, v9.4s, #20
	orr	v9.16b, v9.16b, v15.16b
	add	v3.4s, v3.4s, v29.4s
	add	v3.4s, v3.4s, v10.4s
	eor	v6.16b, v3.16b, v6.16b
	ushr	v15.4s, v6.4s, #8
	shl	v6.4s, v6.4s, #24
	orr	v6.16b, v6.16b, v15.16b
	add	v5.4s, v5.4s, v26.4s
	add	v5.4s, v5.4s, v0.4s
	eor	v2.16b, v5.16b, v2.16b
	ushr	v15.4s, v2.4s, #8
	shl	v2.4s, v2.4s, #24
	orr	v2.16b, v2.16b, v15.16b
	add	v1.4s, v1.4s, v17.4s
	add	v1.4s, v1.4s, v8.4s
	eor	v24.16b, v1.16b, v24.16b
	ushr	v15.4s, v24.4s, #8
	shl	v24.4s, v24.4s, #24
	orr	v24.16b, v24.16b, v15.16b
	ldr	q19, [sp, #240]                 // 16-byte Folded Reload
	add	v4.4s, v4.4s, v19.4s
	add	v4.4s, v4.4s, v9.4s
	eor	v31.16b, v4.16b, v31.16b
	ushr	v15.4s, v31.4s, #8
	shl	v31.4s, v31.4s, #24
	orr	v15.16b, v31.16b, v15.16b
	add	v12.4s, v24.4s, v12.4s
	eor	v31.16b, v12.16b, v8.16b
	ushr	v8.4s, v31.4s, #7
	shl	v31.4s, v31.4s, #25
	orr	v31.16b, v31.16b, v8.16b
	add	v8.4s, v6.4s, v11.4s
	eor	v10.16b, v8.16b, v10.16b
	ushr	v11.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	orr	v10.16b, v10.16b, v11.16b
	add	v13.4s, v15.4s, v13.4s
	eor	v9.16b, v13.16b, v9.16b
	ushr	v11.4s, v9.4s, #7
	shl	v9.4s, v9.4s, #25
	orr	v9.16b, v9.16b, v11.16b
	add	v14.4s, v2.4s, v14.4s
	eor	v0.16b, v14.16b, v0.16b
	ushr	v11.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	orr	v0.16b, v0.16b, v11.16b
	add	v1.4s, v1.4s, v16.4s
	add	v1.4s, v1.4s, v10.4s
	eor	v2.16b, v1.16b, v2.16b
	ushr	v7.4s, v2.4s, #16
	shl	v2.4s, v2.4s, #16
	orr	v2.16b, v2.16b, v7.16b
	add	v3.4s, v3.4s, v23.4s
	add	v7.4s, v3.4s, v9.4s
	eor	v3.16b, v7.16b, v24.16b
	ushr	v24.4s, v3.4s, #16
	shl	v3.4s, v3.4s, #16
	orr	v24.16b, v3.16b, v24.16b
	add	v3.4s, v4.4s, v20.4s
	add	v3.4s, v3.4s, v0.4s
	eor	v4.16b, v3.16b, v6.16b
	ushr	v6.4s, v4.4s, #16
	shl	v4.4s, v4.4s, #16
	orr	v6.16b, v4.16b, v6.16b
	add	v4.4s, v5.4s, v22.4s
	mov	v16.16b, v22.16b
	add	v4.4s, v4.4s, v31.4s
	eor	v5.16b, v4.16b, v15.16b
	ushr	v11.4s, v5.4s, #16
	shl	v5.4s, v5.4s, #16
	orr	v11.16b, v5.16b, v11.16b
	add	v5.4s, v2.4s, v13.4s
	eor	v10.16b, v5.16b, v10.16b
	ushr	v13.4s, v10.4s, #12
	shl	v10.4s, v10.4s, #20
	orr	v10.16b, v10.16b, v13.16b
	add	v13.4s, v24.4s, v14.4s
	eor	v9.16b, v13.16b, v9.16b
	ushr	v14.4s, v9.4s, #12
	shl	v9.4s, v9.4s, #20
	orr	v9.16b, v9.16b, v14.16b
	add	v12.4s, v6.4s, v12.4s
	eor	v0.16b, v12.16b, v0.16b
	ushr	v14.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	orr	v0.16b, v0.16b, v14.16b
	add	v8.4s, v11.4s, v8.4s
	eor	v31.16b, v8.16b, v31.16b
	ushr	v14.4s, v31.4s, #12
	shl	v31.4s, v31.4s, #20
	orr	v31.16b, v31.16b, v14.16b
	add	v1.4s, v1.4s, v21.4s
	mov	v15.16b, v21.16b
	add	v1.4s, v1.4s, v10.4s
	eor	v2.16b, v1.16b, v2.16b
	ushr	v14.4s, v2.4s, #8
	shl	v2.4s, v2.4s, #24
	orr	v2.16b, v2.16b, v14.16b
	add	v3.4s, v3.4s, v18.4s
	add	v3.4s, v3.4s, v0.4s
	eor	v6.16b, v3.16b, v6.16b
	ushr	v14.4s, v6.4s, #8
	shl	v6.4s, v6.4s, #24
	orr	v6.16b, v6.16b, v14.16b
	add	v1.4s, v1.4s, v30.4s
	ldp	q21, q14, [sp, #288]            // 32-byte Folded Reload
	add	v7.4s, v7.4s, v14.4s
	add	v4.4s, v4.4s, v21.4s
	add	v7.4s, v7.4s, v9.4s
	add	v4.4s, v4.4s, v31.4s
	eor	v24.16b, v7.16b, v24.16b
	eor	v30.16b, v4.16b, v11.16b
	add	v7.4s, v7.4s, v29.4s
	ushr	v29.4s, v30.4s, #8
	shl	v30.4s, v30.4s, #24
	orr	v29.16b, v30.16b, v29.16b
	ushr	v30.4s, v24.4s, #8
	shl	v24.4s, v24.4s, #24
	orr	v24.16b, v24.16b, v30.16b
	add	v5.4s, v2.4s, v5.4s
	add	v30.4s, v6.4s, v12.4s
	add	v11.4s, v24.4s, v13.4s
	eor	v10.16b, v5.16b, v10.16b
	eor	v0.16b, v30.16b, v0.16b
	add	v8.4s, v29.4s, v8.4s
	eor	v31.16b, v8.16b, v31.16b
	add	v3.4s, v3.4s, v26.4s
	eor	v26.16b, v11.16b, v9.16b
	ushr	v9.4s, v10.4s, #7
	shl	v10.4s, v10.4s, #25
	orr	v9.16b, v10.16b, v9.16b
	ushr	v10.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	orr	v0.16b, v0.16b, v10.16b
	ushr	v10.4s, v26.4s, #7
	shl	v26.4s, v26.4s, #25
	orr	v26.16b, v26.16b, v10.16b
	ushr	v10.4s, v31.4s, #7
	shl	v31.4s, v31.4s, #25
	orr	v31.16b, v31.16b, v10.16b
	add	v4.4s, v4.4s, v28.4s
	add	v7.4s, v7.4s, v9.4s
	add	v4.4s, v4.4s, v0.4s
	eor	v6.16b, v7.16b, v6.16b
	eor	v2.16b, v4.16b, v2.16b
	add	v7.4s, v7.4s, v23.4s
	ushr	v22.4s, v6.4s, #16
	shl	v6.4s, v6.4s, #16
	orr	v6.16b, v6.16b, v22.16b
	ushr	v22.4s, v2.4s, #16
	shl	v2.4s, v2.4s, #16
	orr	v2.16b, v2.16b, v22.16b
	add	v1.4s, v1.4s, v31.4s
	eor	v22.16b, v1.16b, v24.16b
	add	v1.4s, v1.4s, v25.4s
	add	v3.4s, v3.4s, v26.4s
	eor	v24.16b, v3.16b, v29.16b
	add	v3.4s, v3.4s, v27.4s
	ushr	v25.4s, v24.4s, #16
	shl	v24.4s, v24.4s, #16
	orr	v24.16b, v24.16b, v25.16b
	ushr	v25.4s, v22.4s, #16
	shl	v22.4s, v22.4s, #16
	orr	v22.16b, v22.16b, v25.16b
	add	v25.4s, v22.4s, v30.4s
	add	v27.4s, v6.4s, v8.4s
	add	v5.4s, v24.4s, v5.4s
	add	v28.4s, v2.4s, v11.4s
	eor	v29.16b, v27.16b, v9.16b
	eor	v30.16b, v25.16b, v31.16b
	eor	v0.16b, v28.16b, v0.16b
	add	v4.4s, v4.4s, v18.4s
	eor	v23.16b, v5.16b, v26.16b
	ushr	v26.4s, v29.4s, #12
	shl	v29.4s, v29.4s, #20
	orr	v26.16b, v29.16b, v26.16b
	ushr	v29.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	orr	v0.16b, v0.16b, v29.16b
	ushr	v29.4s, v30.4s, #12
	shl	v30.4s, v30.4s, #20
	orr	v29.16b, v30.16b, v29.16b
	ushr	v30.4s, v23.4s, #12
	shl	v23.4s, v23.4s, #20
	orr	v23.16b, v23.16b, v30.16b
	add	v1.4s, v1.4s, v29.4s
	add	v7.4s, v7.4s, v26.4s
	add	v3.4s, v3.4s, v23.4s
	add	v4.4s, v4.4s, v0.4s
	eor	v6.16b, v7.16b, v6.16b
	eor	v22.16b, v1.16b, v22.16b
	eor	v24.16b, v3.16b, v24.16b
	eor	v2.16b, v4.16b, v2.16b
	ushr	v30.4s, v22.4s, #8
	shl	v22.4s, v22.4s, #24
	orr	v30.16b, v22.16b, v30.16b
	ushr	v22.4s, v6.4s, #8
	shl	v6.4s, v6.4s, #24
	orr	v6.16b, v6.16b, v22.16b
	ushr	v22.4s, v24.4s, #8
	shl	v24.4s, v24.4s, #24
	orr	v24.16b, v24.16b, v22.16b
	ushr	v22.4s, v2.4s, #8
	shl	v2.4s, v2.4s, #24
	orr	v2.16b, v2.16b, v22.16b
	add	v22.4s, v6.4s, v27.4s
	add	v27.4s, v2.4s, v28.4s
	eor	v26.16b, v22.16b, v26.16b
	add	v25.4s, v30.4s, v25.4s
	eor	v0.16b, v27.16b, v0.16b
	add	v1.4s, v1.4s, v17.4s
	eor	v17.16b, v25.16b, v29.16b
	ushr	v28.4s, v26.4s, #7
	shl	v26.4s, v26.4s, #25
	orr	v26.16b, v26.16b, v28.16b
	ushr	v28.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	orr	v0.16b, v0.16b, v28.16b
	ushr	v28.4s, v17.4s, #7
	shl	v17.4s, v17.4s, #25
	orr	v17.16b, v17.16b, v28.16b
	add	v7.4s, v7.4s, v20.4s
	add	v3.4s, v3.4s, v15.4s
	add	v5.4s, v24.4s, v5.4s
	eor	v18.16b, v5.16b, v23.16b
	add	v4.4s, v4.4s, v21.4s
	ushr	v21.4s, v18.4s, #7
	shl	v18.4s, v18.4s, #25
	add	v1.4s, v1.4s, v26.4s
	orr	v18.16b, v18.16b, v21.16b
	add	v7.4s, v7.4s, v18.4s
	add	v3.4s, v3.4s, v0.4s
	add	v4.4s, v4.4s, v17.4s
	eor	v2.16b, v1.16b, v2.16b
	eor	v6.16b, v3.16b, v6.16b
	eor	v21.16b, v7.16b, v30.16b
	eor	v23.16b, v4.16b, v24.16b
	ushr	v24.4s, v2.4s, #16
	shl	v2.4s, v2.4s, #16
	orr	v2.16b, v2.16b, v24.16b
	ushr	v24.4s, v21.4s, #16
	shl	v21.4s, v21.4s, #16
	orr	v21.16b, v21.16b, v24.16b
	ushr	v24.4s, v6.4s, #16
	shl	v6.4s, v6.4s, #16
	orr	v6.16b, v6.16b, v24.16b
	ushr	v24.4s, v23.4s, #16
	shl	v23.4s, v23.4s, #16
	orr	v23.16b, v23.16b, v24.16b
	add	v1.4s, v1.4s, v14.4s
	add	v5.4s, v2.4s, v5.4s
	add	v24.4s, v6.4s, v25.4s
	eor	v25.16b, v5.16b, v26.16b
	add	v26.4s, v21.4s, v27.4s
	eor	v0.16b, v24.16b, v0.16b
	add	v7.4s, v7.4s, v19.4s
	eor	v18.16b, v26.16b, v18.16b
	ushr	v20.4s, v25.4s, #12
	shl	v25.4s, v25.4s, #20
	orr	v20.16b, v25.16b, v20.16b
	ushr	v25.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	orr	v0.16b, v0.16b, v25.16b
	ushr	v25.4s, v18.4s, #12
	shl	v18.4s, v18.4s, #20
	orr	v18.16b, v18.16b, v25.16b
	add	v3.4s, v3.4s, v16.4s
	add	v16.4s, v23.4s, v22.4s
	eor	v17.16b, v16.16b, v17.16b
	ldr	q19, [sp, #320]                 // 16-byte Folded Reload
	add	v4.4s, v4.4s, v19.4s
	ushr	v19.4s, v17.4s, #12
	shl	v17.4s, v17.4s, #20
	add	v1.4s, v1.4s, v20.4s
	add	v3.4s, v3.4s, v0.4s
	orr	v17.16b, v17.16b, v19.16b
	add	v4.4s, v4.4s, v17.4s
	eor	v2.16b, v1.16b, v2.16b
	add	v7.4s, v7.4s, v18.4s
	eor	v19.16b, v7.16b, v21.16b
	eor	v6.16b, v3.16b, v6.16b
	eor	v21.16b, v4.16b, v23.16b
	ushr	v22.4s, v2.4s, #8
	shl	v2.4s, v2.4s, #24
	orr	v2.16b, v2.16b, v22.16b
	ushr	v22.4s, v6.4s, #8
	shl	v6.4s, v6.4s, #24
	orr	v6.16b, v6.16b, v22.16b
	ushr	v22.4s, v19.4s, #8
	shl	v19.4s, v19.4s, #24
	orr	v19.16b, v19.16b, v22.16b
	ushr	v22.4s, v21.4s, #8
	shl	v21.4s, v21.4s, #24
	orr	v21.16b, v21.16b, v22.16b
	add	v22.4s, v6.4s, v24.4s
	eor	v0.16b, v22.16b, v0.16b
	eor	v13.16b, v22.16b, v1.16b
	add	v1.4s, v2.4s, v5.4s
	eor	v5.16b, v1.16b, v20.16b
	eor	v14.16b, v1.16b, v3.16b
	ushr	v1.4s, v5.4s, #7
	shl	v3.4s, v5.4s, #25
	orr	v1.16b, v3.16b, v1.16b
	ushr	v3.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	orr	v0.16b, v0.16b, v3.16b
	add	v3.4s, v21.4s, v16.4s
	eor	v5.16b, v3.16b, v17.16b
	eor	v16.16b, v3.16b, v7.16b
	add	v3.4s, v19.4s, v26.4s
	eor	v7.16b, v3.16b, v18.16b
	eor	v17.16b, v3.16b, v4.16b
	ushr	v3.4s, v7.4s, #7
	shl	v4.4s, v7.4s, #25
	orr	v3.16b, v4.16b, v3.16b
	ushr	v4.4s, v5.4s, #7
	shl	v5.4s, v5.4s, #25
	orr	v4.16b, v5.16b, v4.16b
	eor	v8.16b, v19.16b, v4.16b
	eor	v10.16b, v6.16b, v1.16b
	eor	v9.16b, v3.16b, v21.16b
	eor	v31.16b, v0.16b, v2.16b
	add	x14, x14, #64                   // =64
	add	x15, x15, #64                   // =64
	add	x16, x16, #64                   // =64
	add	x17, x17, #64                   // =64
	mov	w8, w6
	cbnz	x18, .LBB0_5
	b	.LBB0_2
.LBB0_6:
	stp	w19, w6, [sp, #72]              // 8-byte Folded Spill
	str	x2, [sp, #32]                   // 8-byte Folded Spill
	cbz	x1, .LBB0_14
// %bb.7:
	ldr	w8, [sp, #76]                   // 4-byte Folded Reload
	orr	w8, w7, w8
	str	w8, [sp, #28]                   // 4-byte Folded Spill
	and	x8, x5, #0x1
	str	x8, [sp, #16]                   // 8-byte Folded Spill
.LBB0_8:                                // =>This Loop Header: Depth=1
                                        //     Child Loop BB0_11 Depth 2
	stp	x3, x0, [sp, #48]               // 16-byte Folded Spill
	str	x1, [sp, #64]                   // 8-byte Folded Spill
	ldp	x9, x8, [sp, #32]               // 16-byte Folded Reload
	ldp	q0, q1, [x8]
	ldr	x11, [x0]
	stp	q0, q1, [sp, #384]
	str	x4, [sp, #96]                   // 8-byte Folded Spill
	lsr	x8, x4, #32
	str	x8, [sp, #80]                   // 8-byte Folded Spill
	ldr	w8, [sp, #28]                   // 4-byte Folded Reload
	b	.LBB0_11
.LBB0_9:                                //   in Loop: Header=BB0_11 Depth=2
	ldr	w9, [sp, #72]                   // 4-byte Folded Reload
	orr	w8, w8, w9
.LBB0_10:                               //   in Loop: Header=BB0_11 Depth=2
	and	w8, w8, #0xff
	mov	x26, x11
	ldr	w11, [x11]
	ldp	w24, w21, [x26, #4]
	ldr	w9, [sp, #384]
	str	x10, [sp, #240]                 // 8-byte Folded Spill
	ldr	w10, [sp, #388]
	add	w9, w9, w11
	mov	w28, w11
	str	w11, [sp, #288]                 // 4-byte Folded Spill
	ldr	w11, [sp, #400]
	ldr	w12, [sp, #404]
	add	w9, w9, w11
	ldr	x13, [sp, #96]                  // 8-byte Folded Reload
	eor	w13, w9, w13
	ldr	w22, [x26, #12]
	add	w10, w10, w21
	add	w10, w10, w12
	add	w9, w9, w24
	str	w24, [sp, #176]                 // 4-byte Folded Spill
	ldr	x14, [sp, #80]                  // 8-byte Folded Reload
	eor	w14, w10, w14
	add	w10, w10, w22
	ror	w13, w13, #16
	ror	w14, w14, #16
	mov	w15, #58983
	movk	w15, #27145, lsl #16
	add	w15, w13, w15
	mov	w16, #44677
	movk	w16, #47975, lsl #16
	add	w17, w14, w16
	eor	w11, w15, w11
	eor	w12, w17, w12
	ror	w11, w11, #12
	ldp	w16, w7, [x26, #16]
	str	w16, [sp, #368]                 // 4-byte Folded Spill
	str	w7, [sp, #272]                  // 4-byte Folded Spill
	ldr	w18, [sp, #392]
	ldr	w0, [sp, #396]
	add	w18, w18, w16
	ror	w12, w12, #12
	add	w9, w9, w11
	add	w1, w10, w12
	ldr	w10, [sp, #408]
	ldr	w2, [sp, #412]
	add	w18, w18, w10
	ror	w3, w18, #16
	eor	w3, w3, #0x400000
	mov	w16, #62322
	movk	w16, #15470, lsl #16
	add	w4, w3, w16
	eor	w13, w9, w13
	eor	w14, w1, w14
	ror	w13, w13, #8
	ror	w14, w14, #8
	add	w15, w13, w15
	add	w17, w14, w17
	eor	w11, w15, w11
	eor	w12, w17, w12
	ldp	w27, w20, [x26, #24]
	ror	w6, w11, #7
	ror	w12, w12, #7
	eor	w10, w4, w10
	ror	w10, w10, #12
	ldp	w23, w25, [x26, #32]
	str	w23, [sp, #192]                 // 4-byte Folded Spill
	str	w25, [sp, #304]                 // 4-byte Folded Spill
	add	w11, w18, w7
	add	w18, w11, w10
	eor	w11, w18, w3
	ror	w3, w11, #8
	ldp	w11, w29, [x26, #40]
	add	w4, w3, w4
	eor	w10, w4, w10
	ror	w30, w10, #7
	add	w10, w0, w27
	str	w27, [sp, #352]                 // 4-byte Folded Spill
	ldp	w19, w7, [x26, #48]
	add	w10, w10, w2
	eor	w8, w10, w8
	extr	w8, w8, w10, #16
	mov	w16, #62778
	movk	w16, #42319, lsl #16
	add	w0, w8, w16
	eor	w2, w0, w2
	ror	w2, w2, #12
	add	w10, w10, w20
	add	w16, w10, w2
	eor	w8, w16, w8
	ror	w8, w8, #8
	add	w0, w8, w0
	eor	w10, w0, w2
	ror	w2, w10, #7
	add	w9, w9, w23
	add	w9, w9, w12
	eor	w8, w9, w8
	ror	w8, w8, #16
	add	w10, w8, w4
	eor	w12, w10, w12
	ror	w12, w12, #12
	add	w9, w9, w25
	add	w9, w9, w12
	eor	w8, w9, w8
	ror	w8, w8, #8
	add	w10, w8, w10
	eor	w12, w10, w12
	ror	w4, w12, #7
	add	w12, w1, w11
	str	w11, [sp, #320]                 // 4-byte Folded Spill
	add	w12, w12, w30
	eor	w13, w12, w13
	ror	w13, w13, #16
	add	w0, w13, w0
	eor	w1, w0, w30
	ror	w1, w1, #12
	add	w12, w12, w29
	mov	w30, w29
	add	w5, w12, w1
	eor	w12, w5, w13
	ror	w13, w12, #8
	add	w12, w13, w0
	eor	w0, w12, w1
	ror	w0, w0, #7
	add	w18, w18, w19
	mov	w29, w19
	add	w18, w18, w2
	eor	w14, w18, w14
	ror	w14, w14, #16
	add	w15, w14, w15
	eor	w1, w15, w2
	ror	w1, w1, #12
	add	w18, w18, w7
	mov	w23, w7
	add	w18, w18, w1
	eor	w14, w18, w14
	ror	w14, w14, #8
	add	w15, w14, w15
	eor	w1, w15, w1
	ror	w1, w1, #7
	str	x26, [sp, #224]                 // 8-byte Folded Spill
	ldp	w2, w7, [x26, #56]
	str	w7, [sp, #256]                  // 4-byte Folded Spill
	add	w16, w16, w2
	add	w16, w16, w6
	eor	w3, w16, w3
	ror	w3, w3, #16
	add	w17, w3, w17
	eor	w6, w17, w6
	ror	w6, w6, #12
	add	w16, w16, w7
	add	w16, w16, w6
	eor	w3, w16, w3
	ror	w3, w3, #8
	add	w17, w3, w17
	eor	w6, w17, w6
	ror	w6, w6, #7
	add	w9, w9, w21
	mov	w25, w21
	add	w9, w9, w6
	eor	w13, w9, w13
	ror	w13, w13, #16
	add	w15, w13, w15
	eor	w6, w15, w6
	ror	w6, w6, #12
	add	w9, w9, w27
	add	w7, w9, w6
	eor	w9, w7, w13
	ror	w19, w9, #8
	add	w13, w19, w15
	eor	w9, w13, w6
	ror	w9, w9, #7
	add	w15, w5, w22
	mov	w26, w22
	add	w15, w15, w4
	eor	w14, w15, w14
	ror	w14, w14, #16
	add	w17, w14, w17
	eor	w4, w17, w4
	ror	w4, w4, #12
	add	w15, w15, w11
	add	w15, w15, w4
	eor	w14, w15, w14
	ror	w5, w14, #8
	add	w14, w5, w17
	eor	w17, w14, w4
	ror	w17, w17, #7
	add	w18, w18, w20
	add	w18, w18, w0
	eor	w3, w18, w3
	ror	w3, w3, #16
	add	w10, w3, w10
	eor	w0, w10, w0
	ror	w0, w0, #12
	add	w18, w18, w28
	add	w18, w18, w0
	eor	w3, w18, w3
	ror	w3, w3, #8
	add	w10, w3, w10
	eor	w0, w10, w0
	ror	w0, w0, #7
	ldr	w22, [sp, #368]                 // 4-byte Folded Reload
	add	w16, w16, w22
	add	w16, w16, w1
	eor	w8, w16, w8
	ror	w8, w8, #16
	add	w12, w8, w12
	eor	w1, w12, w1
	ror	w1, w1, #12
	mov	w27, w23
	str	w23, [sp, #112]                 // 4-byte Folded Spill
	add	w16, w16, w23
	add	w16, w16, w1
	eor	w8, w16, w8
	ror	w8, w8, #8
	add	w12, w8, w12
	eor	w1, w12, w1
	ror	w1, w1, #7
	add	w4, w7, w24
	add	w4, w4, w17
	eor	w8, w4, w8
	ror	w8, w8, #16
	add	w10, w8, w10
	eor	w17, w10, w17
	ror	w17, w17, #12
	add	w4, w4, w30
	add	w4, w4, w17
	eor	w8, w4, w8
	ror	w8, w8, #8
	add	w10, w8, w10
	eor	w17, w10, w17
	ror	w17, w17, #7
	mov	w11, w29
	add	w15, w15, w29
	add	w15, w15, w0
	eor	w6, w15, w19
	ror	w6, w6, #16
	add	w12, w6, w12
	eor	w0, w12, w0
	ror	w0, w0, #12
	ldr	w7, [sp, #272]                  // 4-byte Folded Reload
	add	w15, w15, w7
	add	w15, w15, w0
	eor	w6, w15, w6
	ror	w6, w6, #8
	add	w12, w6, w12
	eor	w0, w12, w0
	ror	w0, w0, #7
	ldr	w24, [sp, #304]                 // 4-byte Folded Reload
	add	w18, w18, w24
	add	w18, w18, w1
	eor	w5, w18, w5
	ror	w5, w5, #16
	add	w13, w5, w13
	eor	w1, w13, w1
	ror	w1, w1, #12
	add	w18, w18, w2
	add	w18, w18, w1
	eor	w5, w18, w5
	ror	w5, w5, #8
	add	w13, w5, w13
	eor	w1, w13, w1
	ror	w1, w1, #7
	ldr	w29, [sp, #256]                 // 4-byte Folded Reload
	add	w16, w16, w29
	add	w16, w16, w9
	eor	w3, w16, w3
	ror	w3, w3, #16
	add	w14, w3, w14
	eor	w9, w14, w9
	ror	w9, w9, #12
	ldr	w21, [sp, #192]                 // 4-byte Folded Reload
	add	w16, w16, w21
	add	w16, w16, w9
	eor	w3, w16, w3
	ror	w3, w3, #8
	add	w14, w3, w14
	eor	w9, w14, w9
	ror	w9, w9, #7
	add	w4, w4, w26
	mov	w28, w26
	str	w26, [sp, #160]                 // 4-byte Folded Spill
	add	w4, w4, w9
	eor	w6, w4, w6
	ror	w6, w6, #16
	add	w13, w6, w13
	eor	w9, w13, w9
	ror	w9, w9, #12
	add	w4, w4, w22
	add	w4, w4, w9
	eor	w6, w4, w6
	ror	w6, w6, #8
	add	w13, w6, w13
	eor	w9, w13, w9
	ror	w9, w9, #7
	ldr	w23, [sp, #320]                 // 4-byte Folded Reload
	add	w15, w15, w23
	add	w15, w15, w17
	eor	w5, w15, w5
	ror	w5, w5, #16
	add	w14, w5, w14
	eor	w17, w14, w17
	ror	w17, w17, #12
	add	w15, w15, w11
	mov	w22, w11
	add	w15, w15, w17
	eor	w5, w15, w5
	ror	w5, w5, #8
	add	w14, w5, w14
	eor	w17, w14, w17
	ror	w17, w17, #7
	add	w18, w18, w27
	add	w18, w18, w0
	eor	w3, w18, w3
	ror	w3, w3, #16
	add	w10, w3, w10
	eor	w0, w10, w0
	ror	w0, w0, #12
	add	w18, w18, w25
	mov	w26, w25
	add	w18, w18, w0
	eor	w3, w18, w3
	ror	w3, w3, #8
	add	w10, w3, w10
	eor	w0, w10, w0
	ror	w0, w0, #7
	mov	w11, w20
	str	w20, [sp, #336]                 // 4-byte Folded Spill
	add	w16, w16, w20
	add	w16, w16, w1
	eor	w8, w16, w8
	ror	w8, w8, #16
	add	w12, w8, w12
	eor	w1, w12, w1
	ror	w1, w1, #12
	add	w16, w16, w2
	mov	w27, w2
	str	w2, [sp, #128]                  // 4-byte Folded Spill
	add	w16, w16, w1
	eor	w8, w16, w8
	ror	w8, w8, #8
	add	w12, w8, w12
	eor	w1, w12, w1
	ror	w1, w1, #7
	ldr	w2, [sp, #352]                  // 4-byte Folded Reload
	add	w4, w4, w2
	add	w4, w4, w17
	eor	w8, w4, w8
	ror	w8, w8, #16
	add	w10, w8, w10
	eor	w17, w10, w17
	ror	w17, w17, #12
	add	w4, w4, w7
	add	w4, w4, w17
	eor	w8, w4, w8
	ror	w8, w8, #8
	add	w10, w8, w10
	eor	w17, w10, w17
	ror	w17, w17, #7
	add	w15, w15, w24
	mov	w2, w24
	add	w15, w15, w0
	eor	w6, w15, w6
	ror	w6, w6, #16
	add	w12, w6, w12
	eor	w0, w12, w0
	ror	w0, w0, #12
	ldr	w7, [sp, #288]                  // 4-byte Folded Reload
	add	w15, w15, w7
	add	w15, w15, w0
	eor	w6, w15, w6
	ror	w6, w6, #8
	add	w12, w6, w12
	eor	w0, w12, w0
	ror	w0, w0, #7
	mov	w25, w30
	add	w18, w18, w30
	add	w18, w18, w1
	eor	w5, w18, w5
	ror	w5, w5, #16
	add	w13, w5, w13
	eor	w1, w13, w1
	ror	w1, w1, #12
	add	w18, w18, w29
	mov	w30, w29
	add	w18, w18, w1
	eor	w5, w18, w5
	ror	w5, w5, #8
	add	w13, w5, w13
	eor	w1, w13, w1
	ror	w1, w1, #7
	add	w16, w16, w21
	mov	w20, w21
	add	w16, w16, w9
	eor	w3, w16, w3
	ror	w3, w3, #16
	add	w14, w3, w14
	eor	w9, w14, w9
	ror	w9, w9, #12
	ldr	w19, [sp, #176]                 // 4-byte Folded Reload
	add	w16, w16, w19
	add	w16, w16, w9
	eor	w3, w16, w3
	ror	w3, w3, #8
	add	w14, w3, w14
	eor	w9, w14, w9
	ror	w9, w9, #7
	add	w4, w4, w23
	mov	w29, w23
	add	w4, w4, w9
	eor	w6, w4, w6
	ror	w6, w6, #16
	add	w13, w6, w13
	eor	w9, w13, w9
	ror	w9, w9, #12
	add	w4, w4, w11
	add	w4, w4, w9
	eor	w6, w4, w6
	ror	w6, w6, #8
	add	w13, w6, w13
	eor	w9, w13, w9
	ror	w9, w9, #7
	add	w15, w15, w22
	mov	w24, w22
	str	w22, [sp, #144]                 // 4-byte Folded Spill
	add	w15, w15, w17
	eor	w5, w15, w5
	ror	w5, w5, #16
	add	w14, w5, w14
	eor	w17, w14, w17
	ror	w17, w17, #12
	mov	w21, w2
	add	w15, w15, w2
	add	w15, w15, w17
	eor	w5, w15, w5
	ror	w5, w5, #8
	add	w14, w5, w14
	eor	w17, w14, w17
	ror	w17, w17, #7
	add	w18, w18, w27
	add	w18, w18, w0
	eor	w3, w18, w3
	ror	w3, w3, #16
	add	w10, w3, w10
	eor	w0, w10, w0
	ror	w0, w0, #12
	add	w18, w18, w28
	add	w18, w18, w0
	eor	w3, w18, w3
	ror	w3, w3, #8
	add	w10, w3, w10
	eor	w0, w10, w0
	ror	w0, w0, #7
	ldr	w27, [sp, #112]                 // 4-byte Folded Reload
	add	w16, w16, w27
	add	w16, w16, w1
	eor	w8, w16, w8
	ror	w8, w8, #16
	add	w12, w8, w12
	eor	w1, w12, w1
	ror	w1, w1, #12
	add	w16, w16, w30
	mov	w11, w30
	add	w16, w16, w1
	eor	w8, w16, w8
	ror	w8, w8, #8
	add	w12, w8, w12
	eor	w1, w12, w1
	ror	w1, w1, #7
	ldr	w22, [sp, #368]                 // 4-byte Folded Reload
	add	w4, w4, w22
	add	w4, w4, w17
	eor	w8, w4, w8
	ror	w8, w8, #16
	add	w10, w8, w10
	eor	w17, w10, w17
	ror	w17, w17, #12
	add	w4, w4, w7
	add	w4, w4, w17
	eor	w8, w4, w8
	ror	w8, w8, #8
	add	w10, w8, w10
	eor	w17, w10, w17
	ror	w17, w17, #7
	add	w15, w15, w25
	add	w15, w15, w0
	eor	w6, w15, w6
	ror	w6, w6, #16
	add	w12, w6, w12
	eor	w0, w12, w0
	ror	w0, w0, #12
	mov	w22, w26
	str	w26, [sp, #208]                 // 4-byte Folded Spill
	add	w15, w15, w26
	add	w15, w15, w0
	eor	w6, w15, w6
	ror	w6, w6, #8
	add	w12, w6, w12
	eor	w0, w12, w0
	ror	w7, w0, #7
	ldr	w26, [sp, #272]                 // 4-byte Folded Reload
	add	w18, w18, w26
	add	w18, w18, w1
	eor	w0, w18, w5
	ror	w0, w0, #16
	add	w13, w0, w13
	eor	w1, w13, w1
	ror	w1, w1, #12
	mov	w30, w20
	add	w18, w18, w20
	add	w18, w18, w1
	eor	w0, w18, w0
	ror	w0, w0, #8
	add	w13, w0, w13
	eor	w1, w13, w1
	ror	w1, w1, #7
	add	w16, w16, w19
	mov	w28, w19
	add	w16, w16, w9
	eor	w3, w16, w3
	ror	w3, w3, #16
	add	w14, w3, w14
	eor	w9, w14, w9
	ror	w9, w9, #12
	ldr	w23, [sp, #352]                 // 4-byte Folded Reload
	add	w16, w16, w23
	add	w16, w16, w9
	eor	w3, w16, w3
	ror	w3, w3, #8
	add	w5, w3, w14
	eor	w9, w5, w9
	ror	w9, w9, #7
	add	w14, w4, w24
	add	w14, w14, w9
	eor	w4, w14, w6
	ror	w4, w4, #16
	add	w13, w4, w13
	eor	w9, w13, w9
	ror	w9, w9, #12
	add	w14, w14, w27
	add	w6, w14, w9
	eor	w14, w6, w4
	ror	w4, w14, #8
	add	w14, w4, w13
	eor	w9, w14, w9
	ror	w9, w9, #7
	add	w13, w15, w2
	mov	w20, w2
	add	w13, w13, w17
	eor	w15, w13, w0
	ror	w15, w15, #16
	add	w0, w15, w5
	eor	w17, w0, w17
	ror	w17, w17, #12
	add	w13, w13, w25
	add	w5, w13, w17
	eor	w13, w5, w15
	ror	w19, w13, #8
	add	w0, w19, w0
	eor	w13, w0, w17
	ror	w13, w13, #7
	add	w15, w18, w11
	add	w15, w15, w7
	eor	w17, w15, w3
	ror	w17, w17, #16
	add	w10, w17, w10
	eor	w18, w10, w7
	ror	w18, w18, #12
	add	w15, w15, w29
	add	w3, w15, w18
	eor	w15, w3, w17
	ror	w7, w15, #8
	add	w10, w7, w10
	eor	w15, w10, w18
	ror	w17, w15, #7
	ldr	w29, [sp, #128]                 // 4-byte Folded Reload
	add	w15, w16, w29
	add	w15, w15, w1
	eor	w8, w15, w8
	ror	w8, w8, #16
	add	w12, w8, w12
	eor	w16, w12, w1
	ror	w16, w16, #12
	add	w15, w15, w30
	add	w18, w15, w16
	eor	w8, w18, w8
	ror	w8, w8, #8
	add	w12, w8, w12
	eor	w15, w12, w16
	ror	w16, w15, #7
	ldr	w11, [sp, #336]                 // 4-byte Folded Reload
	add	w15, w6, w11
	add	w15, w15, w13
	eor	w8, w15, w8
	ror	w8, w8, #16
	add	w10, w8, w10
	eor	w13, w10, w13
	ror	w1, w13, #12
	add	w13, w15, w22
	add	w6, w13, w1
	eor	w8, w6, w8
	ror	w13, w8, #8
	add	w15, w13, w10
	eor	w8, w15, w1
	ror	w10, w8, #7
	mov	w21, w26
	add	w8, w5, w26
	add	w8, w8, w17
	eor	w1, w8, w4
	ror	w1, w1, #16
	add	w12, w1, w12
	eor	w17, w12, w17
	ror	w4, w17, #12
	ldr	w24, [sp, #160]                 // 4-byte Folded Reload
	add	w8, w8, w24
	add	w5, w8, w4
	eor	w8, w5, w1
	ror	w8, w8, #8
	add	w17, w8, w12
	eor	w12, w17, w4
	ror	w4, w12, #7
	ldr	w22, [sp, #288]                 // 4-byte Folded Reload
	add	w12, w3, w22
	add	w12, w12, w16
	eor	w1, w12, w19
	ror	w1, w1, #16
	add	w14, w1, w14
	eor	w16, w14, w16
	ror	w16, w16, #12
	mov	w11, w28
	add	w12, w12, w28
	add	w19, w12, w16
	eor	w12, w19, w1
	ror	w12, w12, #8
	add	w14, w12, w14
	eor	w16, w14, w16
	ror	w16, w16, #7
	add	w18, w18, w23
	add	w18, w18, w9
	eor	w1, w18, w7
	ror	w1, w1, #16
	add	w0, w1, w0
	eor	w9, w0, w9
	ror	w9, w9, #12
	ldr	w2, [sp, #368]                  // 4-byte Folded Reload
	add	w18, w18, w2
	add	w18, w18, w9
	eor	w1, w18, w1
	ror	w7, w1, #8
	add	w0, w7, w0
	eor	w9, w0, w9
	ror	w9, w9, #7
	add	w1, w6, w20
	add	w1, w1, w9
	eor	w8, w1, w8
	ror	w6, w8, #16
	add	w8, w6, w14
	eor	w9, w8, w9
	ror	w3, w9, #12
	add	w9, w1, w29
	mov	w26, w29
	add	w20, w9, w3
	eor	w1, w20, w6
	add	w9, w5, w25
	add	w9, w9, w10
	eor	w12, w9, w12
	ror	w14, w12, #16
	add	w0, w14, w0
	eor	w10, w0, w10
	ror	w5, w10, #12
	add	w9, w9, w21
	mov	w29, w21
	add	w12, w9, w5
	eor	w9, w12, w14
	ror	w10, w9, #8
	add	w9, w10, w0
	eor	w14, w9, w5
	ror	w5, w14, #7
	add	w14, w19, w30
	add	w14, w14, w4
	eor	w0, w14, w7
	ror	w6, w0, #16
	add	w15, w6, w15
	eor	w0, w15, w4
	ror	w4, w0, #12
	ldr	w21, [sp, #144]                 // 4-byte Folded Reload
	add	w14, w14, w21
	add	w0, w14, w4
	eor	w14, w0, w6
	ror	w14, w14, #8
	add	w15, w14, w15
	eor	w4, w15, w4
	ldr	w28, [sp, #256]                 // 4-byte Folded Reload
	add	w18, w18, w28
	add	w6, w18, w16
	eor	w13, w6, w13
	ror	w13, w13, #16
	add	w7, w13, w17
	eor	w16, w7, w16
	ror	w18, w16, #12
	add	w16, w6, w11
	mov	w23, w11
	add	w17, w16, w18
	eor	w13, w17, w13
	ror	w13, w13, #8
	add	w16, w13, w7
	add	w6, w20, w27
	add	w6, w6, w5
	eor	w13, w6, w13
	ror	w7, w13, #16
	add	w13, w7, w15
	eor	w15, w13, w5
	ror	w15, w15, #12
	add	w5, w6, w24
	add	w5, w5, w15
	eor	w6, w5, w7
	add	w11, w5, w25
	ror	w1, w1, #8
	add	w8, w1, w8
	eor	w3, w8, w3
	ror	w3, w3, #7
	ror	w4, w4, #7
	eor	w18, w16, w18
	add	w12, w12, w22
	add	w12, w12, w4
	eor	w1, w12, w1
	ror	w1, w1, #16
	add	w16, w1, w16
	eor	w4, w16, w4
	ror	w4, w4, #12
	ldr	w20, [sp, #320]                 // 4-byte Folded Reload
	add	w12, w12, w20
	add	w12, w12, w4
	eor	w1, w12, w1
	ror	w1, w1, #8
	add	w16, w1, w16
	add	w17, w17, w2
	mov	w25, w2
	add	w17, w17, w3
	eor	w14, w17, w14
	ror	w14, w14, #16
	add	w9, w14, w9
	eor	w3, w9, w3
	ror	w3, w3, #12
	ldr	w19, [sp, #336]                 // 4-byte Folded Reload
	add	w17, w17, w19
	add	w17, w17, w3
	eor	w14, w17, w14
	ror	w14, w14, #8
	add	w9, w14, w9
	eor	w3, w9, w3
	ror	w3, w3, #7
	add	w11, w11, w3
	eor	w1, w11, w1
	add	w11, w11, w28
	add	w12, w12, w29
	ror	w18, w18, #7
	ror	w2, w6, #8
	add	w13, w2, w13
	eor	w15, w13, w15
	ror	w15, w15, #7
	ldr	w5, [sp, #208]                  // 4-byte Folded Reload
	add	w0, w0, w5
	add	w0, w0, w18
	eor	w10, w0, w10
	ror	w10, w10, #16
	add	w8, w10, w8
	eor	w18, w8, w18
	ror	w18, w18, #12
	ldr	w6, [sp, #352]                  // 4-byte Folded Reload
	add	w0, w0, w6
	add	w0, w0, w18
	eor	w10, w0, w10
	ror	w10, w10, #8
	add	w8, w10, w8
	add	w12, w12, w15
	eor	w10, w12, w10
	add	w12, w12, w22
	add	w0, w0, w23
	eor	w4, w16, w4
	ror	w4, w4, #7
	add	w0, w0, w4
	eor	w14, w0, w14
	ldr	w7, [sp, #304]                  // 4-byte Folded Reload
	add	w0, w0, w7
	add	w17, w17, w30
	eor	w18, w8, w18
	ror	w18, w18, #7
	add	w17, w17, w18
	eor	w2, w17, w2
	add	w17, w17, w6
	ror	w1, w1, #16
	add	w8, w1, w8
	eor	w3, w8, w3
	ror	w3, w3, #12
	add	w11, w11, w3
	eor	w1, w11, w1
	add	w11, w11, w26
	ror	w10, w10, #16
	add	w9, w10, w9
	eor	w15, w9, w15
	ror	w15, w15, #12
	add	w12, w12, w15
	eor	w10, w12, w10
	ror	w10, w10, #8
	add	w9, w10, w9
	eor	w15, w9, w15
	ror	w15, w15, #7
	ror	w2, w2, #16
	add	w16, w2, w16
	eor	w18, w16, w18
	ror	w18, w18, #12
	add	w17, w17, w18
	eor	w2, w17, w2
	ror	w2, w2, #8
	add	w16, w2, w16
	add	w11, w11, w15
	eor	w2, w11, w2
	add	w11, w11, w20
	add	w12, w12, w5
	ror	w1, w1, #8
	add	w8, w1, w8
	ror	w14, w14, #16
	add	w13, w14, w13
	eor	w4, w13, w4
	ror	w4, w4, #12
	add	w0, w0, w4
	eor	w14, w0, w14
	ror	w14, w14, #8
	add	w13, w14, w13
	eor	w4, w13, w4
	ror	w4, w4, #7
	add	w12, w12, w4
	eor	w1, w12, w1
	add	w12, w12, w21
	add	w0, w0, w24
	eor	w18, w16, w18
	ror	w18, w18, #7
	add	w0, w0, w18
	eor	w10, w0, w10
	add	w0, w0, w25
	eor	w3, w8, w3
	ror	w2, w2, #16
	add	w13, w2, w13
	eor	w15, w13, w15
	ror	w15, w15, #12
	add	w11, w11, w15
	ror	w10, w10, #16
	add	w8, w10, w8
	eor	w18, w8, w18
	ror	w18, w18, #12
	add	w0, w0, w18
	eor	w10, w0, w10
	ror	w10, w10, #8
	add	w8, w10, w8
	add	w17, w17, w19
	eor	w5, w8, w11
	str	w5, [sp, #384]
	ror	w3, w3, #7
	ror	w1, w1, #16
	add	w16, w1, w16
	eor	w4, w16, w4
	ror	w4, w4, #12
	add	w12, w12, w4
	add	w17, w17, w3
	eor	w14, w17, w14
	ror	w14, w14, #16
	add	w9, w14, w9
	eor	w3, w9, w3
	ror	w3, w3, #12
	add	w17, w17, w27
	add	w17, w17, w3
	eor	w14, w17, w14
	ror	w14, w14, #8
	add	w9, w14, w9
	eor	w5, w9, w12
	str	w5, [sp, #388]
	eor	w11, w11, w2
	ror	w11, w11, #8
	add	w13, w11, w13
	eor	w0, w13, w0
	str	w0, [sp, #392]
	eor	w12, w12, w1
	ror	w12, w12, #8
	add	w16, w12, w16
	eor	w17, w16, w17
	str	w17, [sp, #396]
	eor	w9, w9, w3
	eor	w9, w12, w9, ror #7
	str	w9, [sp, #400]
	eor	w9, w13, w15
	eor	w9, w10, w9, ror #7
	str	w9, [sp, #404]
	eor	w9, w16, w4
	eor	w9, w14, w9, ror #7
	eor	w8, w8, w18
	str	w9, [sp, #408]
	eor	w8, w11, w8, ror #7
	str	w8, [sp, #412]
	ldr	x11, [sp, #224]                 // 8-byte Folded Reload
	add	x11, x11, #64                   // =64
	ldr	x9, [sp, #240]                  // 8-byte Folded Reload
	ldr	w8, [sp, #76]                   // 4-byte Folded Reload
.LBB0_11:                               //   Parent Loop BB0_8 Depth=1
                                        // =>  This Inner Loop Header: Depth=2
	subs	x10, x9, #1                     // =1
	b.eq	.LBB0_9
// %bb.12:                              //   in Loop: Header=BB0_11 Depth=2
	cbnz	x9, .LBB0_10
// %bb.13:                              //   in Loop: Header=BB0_8 Depth=1
	ldp	q0, q1, [sp, #384]
	ldr	x4, [sp, #96]                   // 8-byte Folded Reload
	ldr	x8, [sp, #16]                   // 8-byte Folded Reload
	add	x4, x4, x8
	ldp	x3, x0, [sp, #48]               // 16-byte Folded Reload
	stp	q0, q1, [x3], #32
	add	x0, x0, #8                      // =8
	ldr	x1, [sp, #64]                   // 8-byte Folded Reload
	subs	x1, x1, #1                      // =1
	b.ne	.LBB0_8
.LBB0_14:
	add	sp, sp, #416                    // =416
	ldp	x20, x19, [sp, #144]            // 16-byte Folded Reload
	ldp	x22, x21, [sp, #128]            // 16-byte Folded Reload
	ldp	x24, x23, [sp, #112]            // 16-byte Folded Reload
	ldp	x26, x25, [sp, #96]             // 16-byte Folded Reload
	ldp	x28, x27, [sp, #80]             // 16-byte Folded Reload
	ldp	x29, x30, [sp, #64]             // 16-byte Folded Reload
	ldp	d9, d8, [sp, #48]               // 16-byte Folded Reload
	ldp	d11, d10, [sp, #32]             // 16-byte Folded Reload
	ldp	d13, d12, [sp, #16]             // 16-byte Folded Reload
	ldp	d15, d14, [sp], #160            // 16-byte Folded Reload
	ret
.Lfunc_end0:
	.size	_blake3_hash_many_neon, .Lfunc_end0-_blake3_hash_many_neon
                                        // -- End function

	.p2align	2                               // -- Begin function round_fn4
	.type	round_fn4,@function
round_fn4:                              // @round_fn4
// %bb.0:
	adrp	x8, MSG_SCHEDULE
	add	x8, x8, :lo12:MSG_SCHEDULE
	add	x8, x8, x2, lsl #4
	ldrb	w9, [x8]
	ldp	q3, q6, [x0]
	ldp	q4, q5, [x0, #64]
	ldp	q17, q18, [x0, #192]
	ldr	q19, [x1, x9, lsl #4]
	ldrb	w9, [x8, #2]
	ldp	q16, q0, [x0, #32]
	ldp	q20, q22, [x0, #128]
	add	v3.4s, v19.4s, v3.4s
	str	q3, [x0]
	ldr	q19, [x1, x9, lsl #4]
	ldrb	w9, [x8, #4]
	add	v28.4s, v4.4s, v3.4s
	eor	v3.16b, v17.16b, v28.16b
	add	v6.4s, v19.4s, v6.4s
	str	q6, [x0, #16]
	ldr	q19, [x1, x9, lsl #4]
	add	v29.4s, v5.4s, v6.4s
	ldp	q2, q1, [x0, #96]
	ldrb	w9, [x8, #6]
	add	v19.4s, v19.4s, v16.4s
	ushr	v16.4s, v3.4s, #16
	shl	v3.4s, v3.4s, #16
	orr	v16.16b, v3.16b, v16.16b
	add	v3.4s, v20.4s, v16.4s
	eor	v4.16b, v3.16b, v4.16b
	ushr	v6.4s, v4.4s, #12
	shl	v4.4s, v4.4s, #20
	eor	v17.16b, v18.16b, v29.16b
	ldp	q21, q7, [x0, #224]
	orr	v20.16b, v4.16b, v6.16b
	ushr	v4.4s, v17.4s, #16
	shl	v6.4s, v17.4s, #16
	orr	v18.16b, v6.16b, v4.16b
	str	q19, [x0, #32]
	add	v4.4s, v22.4s, v18.4s
	ldp	q25, q26, [x0, #160]
	ldr	q27, [x1, x9, lsl #4]
	eor	v5.16b, v4.16b, v5.16b
	add	v30.4s, v2.4s, v19.4s
	ushr	v6.4s, v5.4s, #12
	shl	v5.4s, v5.4s, #20
	eor	v17.16b, v21.16b, v30.16b
	orr	v24.16b, v5.16b, v6.16b
	ushr	v5.4s, v17.4s, #16
	shl	v6.4s, v17.4s, #16
	orr	v23.16b, v6.16b, v5.16b
	add	v6.4s, v25.4s, v23.4s
	add	v0.4s, v27.4s, v0.4s
	eor	v2.16b, v6.16b, v2.16b
	add	v17.4s, v1.4s, v0.4s
	ushr	v0.4s, v2.4s, #12
	shl	v2.4s, v2.4s, #20
	eor	v5.16b, v7.16b, v17.16b
	orr	v22.16b, v2.16b, v0.16b
	ushr	v0.4s, v5.4s, #16
	shl	v2.4s, v5.4s, #16
	orr	v21.16b, v2.16b, v0.16b
	add	v7.4s, v26.4s, v21.4s
	ldrb	w9, [x8, #1]
	eor	v0.16b, v7.16b, v1.16b
	ushr	v1.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	orr	v19.16b, v0.16b, v1.16b
	stp	q28, q29, [x0]
	stp	q16, q18, [x0, #192]
	stp	q3, q4, [x0, #128]
	stp	q20, q24, [x0, #64]
	stp	q30, q17, [x0, #32]
	stp	q23, q21, [x0, #224]
	stp	q6, q7, [x0, #160]
	stp	q22, q19, [x0, #96]
	ldr	q0, [x1, x9, lsl #4]
	ldrb	w9, [x8, #3]
	add	v0.4s, v0.4s, v28.4s
	str	q0, [x0]
	ldr	q1, [x1, x9, lsl #4]
	ldrb	w9, [x8, #5]
	add	v27.4s, v0.4s, v20.4s
	eor	v0.16b, v27.16b, v16.16b
	add	v1.4s, v1.4s, v29.4s
	str	q1, [x0, #16]
	ldr	q2, [x1, x9, lsl #4]
	add	v16.4s, v1.4s, v24.4s
	ldrb	w9, [x8, #7]
	add	v25.4s, v2.4s, v30.4s
	ushr	v2.4s, v0.4s, #8
	shl	v0.4s, v0.4s, #24
	orr	v5.16b, v0.16b, v2.16b
	add	v2.4s, v5.4s, v3.4s
	eor	v0.16b, v2.16b, v20.16b
	ushr	v1.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	eor	v3.16b, v16.16b, v18.16b
	orr	v0.16b, v0.16b, v1.16b
	ushr	v1.4s, v3.4s, #8
	shl	v3.4s, v3.4s, #24
	orr	v3.16b, v3.16b, v1.16b
	str	q25, [x0, #32]
	add	v1.4s, v3.4s, v4.4s
	ldr	q26, [x1, x9, lsl #4]
	eor	v4.16b, v1.16b, v24.16b
	add	v18.4s, v25.4s, v22.4s
	ushr	v20.4s, v4.4s, #7
	shl	v4.4s, v4.4s, #25
	eor	v23.16b, v18.16b, v23.16b
	orr	v20.16b, v4.16b, v20.16b
	ushr	v4.4s, v23.4s, #8
	shl	v23.4s, v23.4s, #24
	orr	v4.16b, v23.16b, v4.16b
	add	v23.4s, v4.4s, v6.4s
	add	v6.4s, v26.4s, v17.4s
	eor	v17.16b, v23.16b, v22.16b
	add	v6.4s, v6.4s, v19.4s
	ushr	v22.4s, v17.4s, #7
	shl	v17.4s, v17.4s, #25
	eor	v21.16b, v6.16b, v21.16b
	orr	v17.16b, v17.16b, v22.16b
	ushr	v22.4s, v21.4s, #8
	shl	v21.4s, v21.4s, #24
	orr	v21.16b, v21.16b, v22.16b
	add	v7.4s, v21.4s, v7.4s
	ldrb	w9, [x8, #8]
	eor	v19.16b, v7.16b, v19.16b
	ushr	v22.4s, v19.4s, #7
	shl	v19.4s, v19.4s, #25
	orr	v19.16b, v19.16b, v22.16b
	stp	q27, q16, [x0]
	stp	q5, q3, [x0, #192]
	stp	q2, q1, [x0, #128]
	stp	q0, q20, [x0, #64]
	stp	q18, q6, [x0, #32]
	stp	q4, q21, [x0, #224]
	stp	q23, q7, [x0, #160]
	stp	q17, q19, [x0, #96]
	ldr	q22, [x1, x9, lsl #4]
	ldrb	w9, [x8, #10]
	add	v22.4s, v22.4s, v27.4s
	str	q22, [x0]
	ldr	q24, [x1, x9, lsl #4]
	ldrb	w9, [x8, #12]
	add	v22.4s, v22.4s, v20.4s
	eor	v21.16b, v22.16b, v21.16b
	add	v16.4s, v24.4s, v16.4s
	ushr	v25.4s, v21.4s, #16
	shl	v21.4s, v21.4s, #16
	str	q16, [x0, #16]
	orr	v21.16b, v21.16b, v25.16b
	ldr	q24, [x1, x9, lsl #4]
	add	v23.4s, v21.4s, v23.4s
	eor	v20.16b, v23.16b, v20.16b
	add	v16.4s, v16.4s, v17.4s
	ldrb	w9, [x8, #14]
	ushr	v25.4s, v20.4s, #12
	shl	v20.4s, v20.4s, #20
	eor	v5.16b, v16.16b, v5.16b
	orr	v20.16b, v20.16b, v25.16b
	ushr	v25.4s, v5.4s, #16
	shl	v5.4s, v5.4s, #16
	add	v18.4s, v24.4s, v18.4s
	orr	v5.16b, v5.16b, v25.16b
	str	q18, [x0, #32]
	add	v7.4s, v5.4s, v7.4s
	ldr	q24, [x1, x9, lsl #4]
	eor	v17.16b, v7.16b, v17.16b
	add	v18.4s, v18.4s, v19.4s
	ushr	v25.4s, v17.4s, #12
	shl	v17.4s, v17.4s, #20
	eor	v3.16b, v18.16b, v3.16b
	orr	v17.16b, v17.16b, v25.16b
	ushr	v25.4s, v3.4s, #16
	shl	v3.4s, v3.4s, #16
	orr	v3.16b, v3.16b, v25.16b
	add	v2.4s, v3.4s, v2.4s
	add	v6.4s, v24.4s, v6.4s
	eor	v19.16b, v2.16b, v19.16b
	add	v6.4s, v6.4s, v0.4s
	ushr	v24.4s, v19.4s, #12
	shl	v19.4s, v19.4s, #20
	eor	v4.16b, v6.16b, v4.16b
	orr	v19.16b, v19.16b, v24.16b
	ushr	v24.4s, v4.4s, #16
	shl	v4.4s, v4.4s, #16
	orr	v4.16b, v4.16b, v24.16b
	add	v1.4s, v4.4s, v1.4s
	ldrb	w9, [x8, #9]
	eor	v0.16b, v1.16b, v0.16b
	ushr	v24.4s, v0.4s, #12
	shl	v0.4s, v0.4s, #20
	orr	v0.16b, v0.16b, v24.16b
	stp	q22, q16, [x0]
	stp	q23, q7, [x0, #160]
	stp	q5, q3, [x0, #192]
	stp	q18, q6, [x0, #32]
	stp	q17, q19, [x0, #96]
	stp	q4, q21, [x0, #224]
	stp	q2, q1, [x0, #128]
	stp	q0, q20, [x0, #64]
	ldr	q24, [x1, x9, lsl #4]
	ldrb	w9, [x8, #11]
	add	v22.4s, v24.4s, v22.4s
	str	q22, [x0]
	ldr	q24, [x1, x9, lsl #4]
	ldrb	w9, [x8, #13]
	add	v22.4s, v22.4s, v20.4s
	eor	v21.16b, v22.16b, v21.16b
	add	v16.4s, v24.4s, v16.4s
	ushr	v25.4s, v21.4s, #8
	shl	v21.4s, v21.4s, #24
	str	q16, [x0, #16]
	orr	v21.16b, v21.16b, v25.16b
	ldr	q25, [x1, x9, lsl #4]
	ldrb	w8, [x8, #15]
	add	v23.4s, v21.4s, v23.4s
	eor	v20.16b, v23.16b, v20.16b
	add	v18.4s, v25.4s, v18.4s
	str	q18, [x0, #32]
	add	v16.4s, v16.4s, v17.4s
	add	v18.4s, v18.4s, v19.4s
	ldr	q25, [x1, x8, lsl #4]
	ushr	v24.4s, v20.4s, #7
	shl	v20.4s, v20.4s, #25
	eor	v5.16b, v16.16b, v5.16b
	eor	v3.16b, v18.16b, v3.16b
	orr	v20.16b, v20.16b, v24.16b
	ushr	v24.4s, v5.4s, #8
	shl	v5.4s, v5.4s, #24
	stp	q22, q16, [x0]
	ushr	v16.4s, v3.4s, #8
	shl	v3.4s, v3.4s, #24
	orr	v5.16b, v5.16b, v24.16b
	orr	v3.16b, v3.16b, v16.16b
	stp	q5, q3, [x0, #192]
	add	v2.4s, v3.4s, v2.4s
	add	v3.4s, v25.4s, v6.4s
	add	v7.4s, v5.4s, v7.4s
	eor	v5.16b, v2.16b, v19.16b
	add	v3.4s, v3.4s, v0.4s
	ushr	v6.4s, v5.4s, #7
	shl	v5.4s, v5.4s, #25
	stp	q18, q3, [x0, #32]
	eor	v3.16b, v3.16b, v4.16b
	orr	v4.16b, v5.16b, v6.16b
	ushr	v5.4s, v3.4s, #8
	shl	v3.4s, v3.4s, #24
	orr	v3.16b, v3.16b, v5.16b
	add	v1.4s, v3.4s, v1.4s
	eor	v17.16b, v7.16b, v17.16b
	eor	v0.16b, v1.16b, v0.16b
	ushr	v24.4s, v17.4s, #7
	shl	v17.4s, v17.4s, #25
	stp	q2, q1, [x0, #128]
	ushr	v1.4s, v0.4s, #7
	shl	v0.4s, v0.4s, #25
	stp	q23, q7, [x0, #160]
	orr	v7.16b, v17.16b, v24.16b
	orr	v0.16b, v0.16b, v1.16b
	stp	q7, q4, [x0, #96]
	stp	q3, q21, [x0, #224]
	stp	q0, q20, [x0, #64]
	ret
.Lfunc_end4:
	.size	round_fn4, .Lfunc_end4-round_fn4
                                        // -- End function

	.type	MSG_SCHEDULE,@object            // @MSG_SCHEDULE
MSG_SCHEDULE:
	.ascii	"\000\001\002\003\004\005\006\007\b\t\n\013\f\r\016\017"
	.ascii	"\002\006\003\n\007\000\004\r\001\013\f\005\t\016\017\b"
	.ascii	"\003\004\n\f\r\002\007\016\006\005\t\000\013\017\b\001"
	.ascii	"\n\007\f\t\016\003\r\017\004\000\013\002\005\b\001\006"
	.ascii	"\f\r\t\013\017\n\016\b\007\002\005\003\000\001\006\004"
	.ascii	"\t\016\013\005\b\f\017\001\r\003\000\n\002\006\004\007"
	.ascii	"\013\017\005\000\001\t\b\006\016\n\002\f\003\004\007\r"
	.size	MSG_SCHEDULE, 112

	.ident	"Debian clang version 11.0.1-2"
	.section	".note.GNU-stack","",@progbits
#endif /* __AARCH64__ */
