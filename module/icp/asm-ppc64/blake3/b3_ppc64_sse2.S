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
 * Based on BLAKE3 v1.3.1, https://github.com/BLAKE3-team/BLAKE3
 * Copyright (c) 2019-2022 Samuel Neves and Matthew Krupcale
 * Copyright (c) 2022 Tino Reichardt <milky-zfs@mcmilk.de>
 *
 * This is converted assembly: SSE2 -> POWER7 PPC64
 * Used tools: SIMDe https://github.com/simd-everywhere/simde
 */

#if (defined(__powerpc__) && defined(__BIG_ENDIAN__))

.text
	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4
.LCPI0_0:
	.byte	2
	.byte	3
	.byte	0
	.byte	1
	.byte	6
	.byte	7
	.byte	4
	.byte	5
	.byte	10
	.byte	11
	.byte	8
	.byte	9
	.byte	14
	.byte	15
	.byte	12
	.byte	13
.LCPI0_1:
	.long	1779033703
	.long	3144134277
	.long	1013904242
	.long	2773480762
.LCPI0_2:
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.byte	20
	.byte	21
	.byte	22
	.byte	23
	.byte	28
	.byte	29
	.byte	30
	.byte	31
.LCPI0_3:
	.short	1
	.short	2
	.short	4
	.short	8
	.short	16
	.short	32
	.short	64
	.short	128
.LCPI0_4:
	.short	0
	.short	0
	.short	4
	.short	8
	.short	0
	.short	0
	.short	64
	.short	128
.LCPI0_5:
	.short	0
	.short	0
	.short	0
	.short	0
	.short	0
	.short	0
	.short	64
	.short	128
	.text
	.globl	_blake3_compress_in_place_sse2
	.p2align	2
	.type	_blake3_compress_in_place_sse2,@function
_blake3_compress_in_place_sse2:
.Lfunc_begin0:
	stwu 1, -80(1)
	li 6, 16
	li 10, 31
	lvsl 5, 0, 4
	lvsl 12, 0, 3
	lvx 2, 3, 6
	lvx 3, 0, 3
	vspltisw 13, -16
	lvx 4, 3, 10
	stw 9, 64(1)
	addi 10, 1, 64
	vspltisw 14, 9
	stw 5, 48(1)
	stw 7, 32(1)
	vperm 3, 3, 2, 12
	addi 5, 1, 48
	stw 8, 16(1)
	addi 7, 1, 32
	vperm 4, 2, 4, 12
	addi 8, 1, 16
	lxvw4x 33, 0, 5
	li 5, 32
	lxvw4x 32, 0, 10
	lxvw4x 38, 0, 7
	lxvw4x 39, 0, 8
	lis 7, .LCPI0_0@ha
	lis 8, .LCPI0_4@ha
	lvx 8, 4, 6
	lvx 9, 0, 4
	lvx 10, 4, 5
	vmrghw 2, 1, 0
	li 5, .LCPI0_0@l
	vperm 9, 9, 8, 5
	vperm 8, 8, 10, 5
	vmrghw 0, 7, 6
	vadduwm 3, 4, 3
	vmrglw 11, 9, 8
	vmrghw 8, 9, 8
	xxmrghd	32, 32, 34
	lxvw4x 34, 7, 5
	li 5, .LCPI0_1@l
	lis 7, .LCPI0_1@ha
	lxvw4x 39, 7, 5
	li 5, 48
	li 7, .LCPI0_4@l
	lvx 12, 4, 5
	li 5, 63
	lxvw4x 48, 8, 7
	vperm 10, 10, 12, 5
	vmrghw 1, 8, 11
	vadduwm 6, 3, 1
	xxsldwi 49, 33, 33, 1
	xxlxor 35, 38, 32
	vperm 0, 3, 3, 2
	vspltisw 3, 10
	vadduwm 3, 3, 3
	vadduwm 9, 0, 7
	vmrglw 7, 8, 11
	lvx 8, 4, 5
	li 4, .LCPI0_2@l
	lis 5, .LCPI0_2@ha
	xxlxor 36, 41, 36
	vperm 8, 12, 8, 5
	vrlw 11, 4, 3
	vspltisw 4, 12
	vadduwm 5, 6, 7
	vadduwm 4, 4, 4
	vmrghw 12, 10, 8
	vadduwm 6, 5, 11
	vmrglw 5, 10, 8
	xxlxor 32, 38, 32
	vmrglw 8, 8, 10
	vrlw 0, 0, 4
	vmrghw 15, 12, 5
	vsubuwm 5, 14, 13
	vmrglw 8, 8, 12
	vadduwm 9, 0, 9
	xxswapd	0, 32
	xxlxor 43, 41, 43
	xxsldwi 41, 41, 41, 1
	vadduwm 6, 6, 15
	vrlw 11, 11, 5
	xxsldwi 38, 38, 38, 3
	vadduwm 0, 11, 6
	xxlxor 38, 32, 0
	vadduwm 0, 0, 8
	vperm 6, 6, 6, 2
	vadduwm 9, 9, 6
	xxlxor 42, 41, 43
	vrlw 10, 10, 3
	vadduwm 11, 0, 10
	xxlxor 32, 43, 38
	vrlw 6, 0, 4
	lxvw4x 32, 5, 4
	li 4, .LCPI0_3@l
	lis 5, .LCPI0_3@ha
	lxvw4x 46, 5, 4
	li 4, .LCPI0_5@l
	lis 5, .LCPI0_5@ha
	vperm 12, 1, 7, 0
	vcmpequh 1, 16, 14
	vmrglw 16, 17, 17
	lxvw4x 49, 5, 4
	vadduwm 9, 6, 9
	xxswapd	0, 38
	xxspltw 38, 47, 1
	xxlxor 42, 41, 42
	xxsldwi 41, 41, 41, 3
	vadduwm 11, 11, 12
	xxsldwi 44, 44, 44, 1
	vrlw 10, 10, 5
	xxsldwi 43, 43, 43, 1
	vmrglw 6, 6, 8
	vadduwm 11, 10, 11
	vmrglw 6, 6, 6
	xxlxor 45, 43, 0
	vperm 13, 13, 13, 2
	xxsel 48, 48, 38, 33
	vcmpequh 6, 17, 14
	xxsldwi 46, 47, 47, 3
	xxmrghd	47, 40, 39
	vmrglw 7, 7, 8
	vadduwm 9, 9, 13
	vadduwm 11, 11, 16
	xxlxor 42, 41, 42
	xxsel 0, 47, 46, 38
	vrlw 10, 10, 3
	xxsldwi 1, 0, 0, 1
	xxsldwi 0, 0, 1, 2
	vadduwm 11, 11, 10
	xxlxor 45, 43, 45
	xxsldwi 47, 1, 0, 3
	xxsldwi 43, 43, 43, 3
	vrlw 13, 13, 4
	vadduwm 11, 11, 15
	vadduwm 9, 13, 9
	xxswapd	0, 45
	vmrghw 13, 14, 7
	xxlxor 42, 41, 42
	xxsldwi 41, 41, 41, 1
	vrlw 10, 10, 5
	vadduwm 8, 11, 10
	xxlxor 43, 40, 0
	xxsldwi 0, 45, 39, 1
	vperm 13, 12, 16, 0
	vperm 11, 11, 11, 2
	xxsldwi 44, 44, 44, 1
	vmrglw 12, 12, 12
	vadduwm 9, 9, 11
	xxlxor 39, 41, 42
	xxsldwi 42, 0, 46, 1
	vrlw 7, 7, 3
	vadduwm 8, 8, 10
	vadduwm 8, 8, 7
	xxlxor 43, 40, 43
	vadduwm 8, 8, 13
	xxsldwi 45, 45, 45, 1
	vrlw 11, 11, 4
	xxsldwi 40, 40, 40, 1
	vadduwm 9, 11, 9
	xxswapd	0, 43
	xxspltw 43, 47, 2
	xxlxor 39, 41, 39
	xxsldwi 41, 41, 41, 3
	vrlw 7, 7, 5
	vmrglw 11, 11, 10
	vadduwm 8, 7, 8
	vmrglw 11, 11, 11
	xxlxor 46, 40, 0
	vperm 14, 14, 14, 2
	vadduwm 9, 9, 14
	xxlxor 39, 41, 39
	vrlw 17, 7, 3
	xxsel 39, 44, 43, 33
	xxmrghd	43, 42, 48
	vmrglw 10, 16, 10
	vadduwm 8, 8, 7
	xxsel 0, 43, 47, 38
	vadduwm 8, 8, 17
	xxlxor 44, 40, 46
	xxsldwi 1, 0, 0, 1
	xxsldwi 40, 40, 40, 3
	vmrghw 16, 15, 10
	vrlw 11, 12, 4
	xxsldwi 0, 0, 1, 2
	xxsldwi 46, 1, 0, 3
	vadduwm 9, 11, 9
	xxswapd	0, 43
	vadduwm 8, 8, 14
	xxlxor 44, 41, 49
	xxsldwi 41, 41, 41, 1
	vrlw 12, 12, 5
	vadduwm 8, 8, 12
	xxlxor 43, 40, 0
	xxsldwi 0, 48, 42, 1
	vperm 11, 11, 11, 2
	vadduwm 9, 9, 11
	xxlxor 42, 41, 44
	xxsldwi 44, 0, 47, 1
	vperm 15, 13, 7, 0
	vrlw 10, 10, 3
	vadduwm 8, 8, 12
	vadduwm 8, 8, 10
	xxlxor 43, 40, 43
	vadduwm 8, 8, 15
	vrlw 11, 11, 4
	xxsldwi 40, 40, 40, 1
	vadduwm 9, 11, 9
	xxswapd	0, 43
	xxspltw 43, 46, 2
	xxlxor 42, 41, 42
	xxsldwi 41, 41, 41, 3
	vrlw 10, 10, 5
	vmrglw 11, 11, 12
	vadduwm 16, 10, 8
	vmrglw 11, 11, 11
	xxlxor 40, 48, 0
	vperm 17, 8, 8, 2
	xxsldwi 40, 45, 45, 1
	xxmrghd	45, 44, 39
	vmrglw 7, 7, 12
	vmrglw 8, 8, 8
	xxsel 0, 45, 46, 38
	vadduwm 9, 9, 17
	xxlxor 42, 41, 42
	xxsldwi 1, 0, 0, 1
	vrlw 10, 10, 3
	xxsel 40, 40, 43, 33
	xxsldwi 0, 0, 1, 2
	vadduwm 11, 16, 8
	vadduwm 11, 11, 10
	xxlxor 48, 43, 49
	xxsldwi 43, 43, 43, 3
	vrlw 13, 16, 4
	xxsldwi 48, 1, 0, 3
	vadduwm 11, 11, 16
	vadduwm 9, 13, 9
	xxswapd	0, 45
	vmrghw 13, 14, 7
	xxlxor 42, 41, 42
	xxsldwi 41, 41, 41, 1
	vrlw 10, 10, 5
	vadduwm 11, 11, 10
	xxlxor 44, 43, 0
	xxsldwi 0, 45, 39, 1
	xxsldwi 45, 47, 47, 1
	vperm 12, 12, 12, 2
	vadduwm 9, 9, 12
	xxlxor 39, 41, 42
	xxsldwi 42, 0, 46, 1
	vperm 14, 13, 8, 0
	vrlw 7, 7, 3
	vadduwm 11, 11, 10
	xxsldwi 45, 45, 45, 1
	vmrglw 13, 13, 13
	vadduwm 11, 11, 7
	xxlxor 44, 43, 44
	vadduwm 11, 11, 14
	vrlw 12, 12, 4
	xxsldwi 43, 43, 43, 1
	vadduwm 9, 12, 9
	xxswapd	0, 44
	xxspltw 44, 48, 2
	xxlxor 39, 41, 39
	xxsldwi 41, 41, 41, 3
	vrlw 7, 7, 5
	vmrglw 12, 12, 10
	vadduwm 11, 7, 11
	vmrglw 12, 12, 12
	xxlxor 47, 43, 0
	vperm 15, 15, 15, 2
	vadduwm 9, 9, 15
	xxlxor 39, 41, 39
	vrlw 17, 7, 3
	xxsel 39, 45, 44, 33
	xxmrghd	44, 42, 40
	vmrglw 8, 8, 10
	vadduwm 11, 11, 7
	xxsel 0, 44, 48, 38
	vadduwm 11, 11, 17
	xxlxor 45, 43, 47
	xxsldwi 1, 0, 0, 1
	xxsldwi 43, 43, 43, 3
	vrlw 12, 13, 4
	xxsldwi 0, 0, 1, 2
	xxsldwi 47, 1, 0, 3
	vadduwm 9, 12, 9
	xxswapd	0, 44
	vadduwm 11, 11, 15
	xxlxor 45, 41, 49
	xxsldwi 41, 41, 41, 1
	vmrghw 12, 16, 8
	vrlw 13, 13, 5
	vadduwm 10, 11, 13
	xxlxor 43, 42, 0
	xxsldwi 0, 44, 40, 1
	vperm 11, 11, 11, 2
	xxsldwi 44, 0, 48, 1
	vadduwm 10, 10, 12
	vadduwm 9, 9, 11
	xxlxor 40, 41, 45
	xxsldwi 45, 46, 46, 1
	vrlw 8, 8, 3
	vperm 14, 13, 7, 0
	xxsldwi 45, 45, 45, 1
	vmrglw 13, 13, 13
	vadduwm 10, 10, 8
	xxlxor 43, 42, 43
	vadduwm 10, 10, 14
	vrlw 11, 11, 4
	xxsldwi 42, 42, 42, 1
	vadduwm 9, 11, 9
	xxswapd	0, 43
	xxspltw 43, 47, 2
	xxlxor 40, 41, 40
	xxsldwi 41, 41, 41, 3
	vrlw 8, 8, 5
	vmrglw 11, 11, 12
	vadduwm 10, 8, 10
	vmrglw 11, 11, 11
	xxlxor 48, 42, 0
	vperm 16, 16, 16, 2
	vadduwm 9, 9, 16
	xxlxor 40, 41, 40
	vrlw 17, 8, 3
	xxsel 40, 45, 43, 33
	xxmrghd	43, 44, 39
	vmrglw 7, 7, 12
	vadduwm 10, 10, 8
	xxsel 0, 43, 47, 38
	vadduwm 10, 10, 17
	xxlxor 45, 42, 48
	xxsldwi 1, 0, 0, 1
	xxsldwi 42, 42, 42, 3
	vmrghw 12, 15, 7
	vrlw 11, 13, 4
	xxsldwi 0, 0, 1, 2
	xxsldwi 48, 1, 0, 3
	vadduwm 9, 11, 9
	xxswapd	0, 43
	vadduwm 10, 10, 16
	xxlxor 45, 41, 49
	xxsldwi 41, 41, 41, 1
	vrlw 13, 13, 5
	vadduwm 10, 10, 13
	xxlxor 43, 42, 0
	xxsldwi 0, 44, 39, 1
	vperm 11, 11, 11, 2
	xxsldwi 44, 0, 47, 1
	vadduwm 10, 10, 12
	vadduwm 9, 9, 11
	xxlxor 39, 41, 45
	xxsldwi 45, 46, 46, 1
	vrlw 7, 7, 3
	vperm 0, 13, 8, 0
	xxsldwi 45, 45, 45, 1
	vmrglw 13, 13, 13
	vadduwm 10, 10, 7
	xxlxor 43, 42, 43
	vadduwm 0, 10, 0
	xxspltw 42, 48, 2
	vrlw 11, 11, 4
	xxsldwi 32, 32, 32, 1
	vmrglw 10, 10, 12
	vadduwm 9, 11, 9
	xxswapd	0, 43
	xxlxor 39, 41, 39
	xxsldwi 41, 41, 41, 3
	vmrglw 10, 10, 10
	vrlw 7, 7, 5
	xxsel 33, 45, 42, 33
	vadduwm 0, 7, 0
	xxlxor 43, 32, 0
	vadduwm 0, 0, 1
	xxmrghd	33, 44, 40
	vperm 11, 11, 11, 2
	xxsel 0, 33, 48, 38
	xxsldwi 1, 0, 0, 1
	vadduwm 9, 9, 11
	xxlxor 39, 41, 39
	xxsldwi 0, 0, 1, 2
	vrlw 7, 7, 3
	vadduwm 0, 0, 7
	xxlxor 42, 32, 43
	xxsldwi 32, 32, 32, 3
	vrlw 1, 10, 4
	vadduwm 6, 1, 9
	xxsldwi 41, 1, 0, 3
	xxswapd	0, 33
	vmrglw 1, 8, 12
	xxlxor 39, 38, 39
	xxsldwi 38, 38, 38, 1
	vadduwm 0, 0, 9
	vrlw 7, 7, 5
	vadduwm 0, 0, 7
	xxlxor 40, 32, 0
	vperm 2, 8, 8, 2
	vmrghw 8, 16, 1
	vadduwm 6, 6, 2
	xxsldwi 0, 40, 33, 1
	xxlxor 39, 38, 39
	vrlw 3, 7, 3
	xxsldwi 33, 0, 48, 1
	vadduwm 0, 0, 1
	vadduwm 0, 0, 3
	xxlxor 34, 32, 34
	xxsldwi 0, 32, 32, 1
	vrlw 2, 2, 4
	vadduwm 4, 2, 6
	xxswapd	2, 34
	xxlxor 35, 36, 35
	xxsldwi 1, 36, 36, 3
	vrlw 3, 3, 5
	xxlxor 0, 1, 0
	stxvw4x 0, 0, 3
	xxlxor 1, 35, 2
	stxvw4x 1, 3, 6
	addi 1, 1, 80
	blr
.Lfunc_end0:
	.size	_blake3_compress_in_place_sse2, .Lfunc_end0-.Lfunc_begin0

	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4
.LCPI1_0:
	.byte	2
	.byte	3
	.byte	0
	.byte	1
	.byte	6
	.byte	7
	.byte	4
	.byte	5
	.byte	10
	.byte	11
	.byte	8
	.byte	9
	.byte	14
	.byte	15
	.byte	12
	.byte	13
.LCPI1_1:
	.long	1779033703
	.long	3144134277
	.long	1013904242
	.long	2773480762
.LCPI1_2:
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.byte	20
	.byte	21
	.byte	22
	.byte	23
	.byte	28
	.byte	29
	.byte	30
	.byte	31
.LCPI1_3:
	.short	1
	.short	2
	.short	4
	.short	8
	.short	16
	.short	32
	.short	64
	.short	128
.LCPI1_4:
	.short	0
	.short	0
	.short	4
	.short	8
	.short	0
	.short	0
	.short	64
	.short	128
.LCPI1_5:
	.short	0
	.short	0
	.short	0
	.short	0
	.short	0
	.short	0
	.short	64
	.short	128
	.text
	.globl	_blake3_compress_xof_sse2
	.p2align	2
	.type	_blake3_compress_xof_sse2,@function
_blake3_compress_xof_sse2:
.Lfunc_begin1:
	stwu 1, -80(1)
	li 6, 16
	li 11, 31
	addi 12, 1, 64
	lvsl 0, 0, 4
	lvx 3, 3, 6
	lvx 4, 0, 3
	vspltisw 14, -16
	lvx 5, 3, 11
	stw 9, 64(1)
	vspltisw 15, 9
	li 9, .LCPI1_4@l
	stw 5, 48(1)
	stw 7, 32(1)
	addi 5, 1, 48
	stw 8, 16(1)
	addi 7, 1, 32
	addi 8, 1, 16
	lxvw4x 38, 0, 5
	li 5, 32
	lxvw4x 33, 0, 12
	lxvw4x 39, 0, 7
	lxvw4x 40, 0, 8
	li 7, .LCPI1_0@l
	lis 8, .LCPI1_0@ha
	lvx 2, 4, 6
	lvx 9, 0, 4
	lis 12, .LCPI1_4@ha
	lvx 10, 4, 5
	lxvw4x 49, 12, 9
	vperm 9, 9, 2, 0
	vperm 11, 2, 10, 0
	lvsl 2, 0, 3
	vperm 4, 4, 3, 2
	vperm 5, 3, 5, 2
	vmrghw 3, 6, 1
	vmrghw 1, 8, 7
	vmrglw 12, 9, 11
	vmrghw 9, 9, 11
	vadduwm 4, 5, 4
	xxmrghd	33, 33, 35
	lxvw4x 35, 8, 7
	li 7, .LCPI1_1@l
	lis 8, .LCPI1_1@ha
	lxvw4x 40, 8, 7
	li 7, 48
	li 8, 63
	vmrghw 6, 9, 12
	lvx 13, 4, 7
	vperm 10, 10, 13, 0
	vadduwm 7, 4, 6
	xxsldwi 50, 38, 38, 1
	xxlxor 36, 39, 33
	vperm 1, 4, 4, 3
	vspltisw 4, 10
	vadduwm 4, 4, 4
	vadduwm 11, 1, 8
	vmrglw 8, 9, 12
	lvx 9, 4, 8
	li 4, .LCPI1_2@l
	lis 8, .LCPI1_2@ha
	xxlxor 37, 43, 37
	vperm 9, 13, 9, 0
	vrlw 12, 5, 4
	vspltisw 5, 12
	vadduwm 0, 7, 8
	vadduwm 5, 5, 5
	vmrghw 13, 10, 9
	vadduwm 7, 0, 12
	vmrglw 0, 10, 9
	xxlxor 33, 39, 33
	vmrglw 9, 9, 10
	vrlw 1, 1, 5
	vmrghw 16, 13, 0
	vsubuwm 0, 15, 14
	vmrglw 9, 9, 13
	vadduwm 11, 1, 11
	xxswapd	0, 33
	xxlxor 44, 43, 44
	xxsldwi 42, 43, 43, 1
	vadduwm 7, 7, 16
	vrlw 12, 12, 0
	xxsldwi 39, 39, 39, 3
	vadduwm 1, 12, 7
	xxlxor 39, 33, 0
	vadduwm 1, 1, 9
	vperm 7, 7, 7, 3
	vadduwm 10, 10, 7
	xxlxor 43, 42, 44
	vrlw 11, 11, 4
	vadduwm 12, 1, 11
	xxlxor 33, 44, 39
	vrlw 7, 1, 5
	lxvw4x 33, 8, 4
	li 4, .LCPI1_3@l
	lis 8, .LCPI1_3@ha
	lxvw4x 47, 8, 4
	li 4, .LCPI1_5@l
	lis 8, .LCPI1_5@ha
	vperm 13, 6, 8, 1
	vcmpequh 6, 17, 15
	vmrglw 17, 18, 18
	lxvw4x 50, 8, 4
	vadduwm 10, 7, 10
	xxswapd	0, 39
	xxspltw 39, 48, 1
	xxlxor 43, 42, 43
	xxsldwi 42, 42, 42, 3
	vadduwm 12, 12, 13
	xxsldwi 45, 45, 45, 1
	vrlw 11, 11, 0
	xxsldwi 44, 44, 44, 1
	vmrglw 7, 7, 9
	vadduwm 12, 11, 12
	vmrglw 7, 7, 7
	xxlxor 46, 44, 0
	vperm 14, 14, 14, 3
	xxsel 49, 49, 39, 38
	vcmpequh 7, 18, 15
	xxsldwi 47, 48, 48, 3
	xxmrghd	48, 41, 40
	vmrglw 8, 8, 9
	vadduwm 10, 10, 14
	vadduwm 12, 12, 17
	xxlxor 43, 42, 43
	xxsel 0, 48, 47, 39
	vrlw 11, 11, 4
	xxsldwi 1, 0, 0, 1
	xxsldwi 0, 0, 1, 2
	vadduwm 12, 12, 11
	xxlxor 46, 44, 46
	xxsldwi 48, 1, 0, 3
	xxsldwi 44, 44, 44, 3
	vrlw 14, 14, 5
	vadduwm 12, 12, 16
	vadduwm 10, 14, 10
	xxswapd	0, 46
	vmrghw 14, 15, 8
	xxlxor 43, 42, 43
	xxsldwi 42, 42, 42, 1
	vrlw 11, 11, 0
	vadduwm 9, 12, 11
	xxlxor 44, 41, 0
	xxsldwi 0, 46, 40, 1
	vperm 14, 13, 17, 1
	vperm 12, 12, 12, 3
	xxsldwi 45, 45, 45, 1
	vmrglw 13, 13, 13
	vadduwm 10, 10, 12
	xxlxor 40, 42, 43
	xxsldwi 43, 0, 47, 1
	vrlw 8, 8, 4
	vadduwm 9, 9, 11
	vadduwm 9, 9, 8
	xxlxor 44, 41, 44
	vadduwm 9, 9, 14
	xxsldwi 46, 46, 46, 1
	vrlw 12, 12, 5
	xxsldwi 41, 41, 41, 1
	vadduwm 10, 12, 10
	xxswapd	0, 44
	xxspltw 44, 48, 2
	xxlxor 40, 42, 40
	xxsldwi 42, 42, 42, 3
	vrlw 8, 8, 0
	vmrglw 12, 12, 11
	vadduwm 9, 8, 9
	vmrglw 12, 12, 12
	xxlxor 47, 41, 0
	vperm 15, 15, 15, 3
	vadduwm 10, 10, 15
	xxlxor 40, 42, 40
	vrlw 18, 8, 4
	xxsel 40, 45, 44, 38
	xxmrghd	44, 43, 49
	vmrglw 11, 17, 11
	vadduwm 9, 9, 8
	xxsel 0, 44, 48, 39
	vadduwm 9, 9, 18
	xxlxor 45, 41, 47
	xxsldwi 1, 0, 0, 1
	xxsldwi 41, 41, 41, 3
	vmrghw 17, 16, 11
	vrlw 12, 13, 5
	xxsldwi 0, 0, 1, 2
	xxsldwi 47, 1, 0, 3
	vadduwm 10, 12, 10
	xxswapd	0, 44
	vadduwm 9, 9, 15
	xxlxor 45, 42, 50
	xxsldwi 42, 42, 42, 1
	vrlw 13, 13, 0
	vadduwm 9, 9, 13
	xxlxor 44, 41, 0
	xxsldwi 0, 49, 43, 1
	vperm 12, 12, 12, 3
	vadduwm 10, 10, 12
	xxlxor 43, 42, 45
	xxsldwi 45, 0, 48, 1
	vperm 16, 14, 8, 1
	vrlw 11, 11, 4
	vadduwm 9, 9, 13
	vadduwm 9, 9, 11
	xxlxor 44, 41, 44
	vadduwm 9, 9, 16
	vrlw 12, 12, 5
	xxsldwi 41, 41, 41, 1
	vadduwm 10, 12, 10
	xxswapd	0, 44
	xxspltw 44, 47, 2
	xxlxor 43, 42, 43
	xxsldwi 42, 42, 42, 3
	vrlw 11, 11, 0
	vmrglw 12, 12, 13
	vadduwm 17, 11, 9
	vmrglw 12, 12, 12
	xxlxor 41, 49, 0
	vperm 18, 9, 9, 3
	xxsldwi 41, 46, 46, 1
	xxmrghd	46, 45, 40
	vmrglw 8, 8, 13
	vmrglw 9, 9, 9
	xxsel 0, 46, 47, 39
	vadduwm 10, 10, 18
	xxlxor 43, 42, 43
	xxsldwi 1, 0, 0, 1
	vrlw 11, 11, 4
	xxsel 41, 41, 44, 38
	xxsldwi 0, 0, 1, 2
	vadduwm 12, 17, 9
	vadduwm 12, 12, 11
	xxlxor 49, 44, 50
	xxsldwi 44, 44, 44, 3
	vrlw 14, 17, 5
	xxsldwi 49, 1, 0, 3
	vadduwm 12, 12, 17
	vadduwm 10, 14, 10
	xxswapd	0, 46
	vmrghw 14, 15, 8
	xxlxor 43, 42, 43
	xxsldwi 42, 42, 42, 1
	vrlw 11, 11, 0
	vadduwm 12, 12, 11
	xxlxor 45, 44, 0
	xxsldwi 0, 46, 40, 1
	xxsldwi 46, 48, 48, 1
	vperm 13, 13, 13, 3
	vadduwm 10, 10, 13
	xxlxor 40, 42, 43
	xxsldwi 43, 0, 47, 1
	vperm 15, 14, 9, 1
	vrlw 8, 8, 4
	vadduwm 12, 12, 11
	xxsldwi 46, 46, 46, 1
	vmrglw 14, 14, 14
	vadduwm 12, 12, 8
	xxlxor 45, 44, 45
	vadduwm 12, 12, 15
	vrlw 13, 13, 5
	xxsldwi 44, 44, 44, 1
	vadduwm 10, 13, 10
	xxswapd	0, 45
	xxspltw 45, 49, 2
	xxlxor 40, 42, 40
	xxsldwi 42, 42, 42, 3
	vrlw 8, 8, 0
	vmrglw 13, 13, 11
	vadduwm 12, 8, 12
	vmrglw 13, 13, 13
	xxlxor 48, 44, 0
	vperm 16, 16, 16, 3
	vadduwm 10, 10, 16
	xxlxor 40, 42, 40
	vrlw 18, 8, 4
	xxsel 40, 46, 45, 38
	xxmrghd	45, 43, 41
	vmrglw 9, 9, 11
	vadduwm 12, 12, 8
	xxsel 0, 45, 49, 39
	vadduwm 12, 12, 18
	xxlxor 46, 44, 48
	xxsldwi 1, 0, 0, 1
	xxsldwi 44, 44, 44, 3
	vrlw 13, 14, 5
	xxsldwi 0, 0, 1, 2
	xxsldwi 48, 1, 0, 3
	vadduwm 10, 13, 10
	xxswapd	0, 45
	vadduwm 12, 12, 16
	xxlxor 46, 42, 50
	xxsldwi 42, 42, 42, 1
	vmrghw 13, 17, 9
	vrlw 14, 14, 0
	vadduwm 11, 12, 14
	xxlxor 44, 43, 0
	xxsldwi 0, 45, 41, 1
	vperm 12, 12, 12, 3
	xxsldwi 45, 0, 49, 1
	vadduwm 11, 11, 13
	vadduwm 10, 10, 12
	xxlxor 41, 42, 46
	xxsldwi 46, 47, 47, 1
	vrlw 9, 9, 4
	vperm 15, 14, 8, 1
	xxsldwi 46, 46, 46, 1
	vmrglw 14, 14, 14
	vadduwm 11, 11, 9
	xxlxor 44, 43, 44
	vadduwm 11, 11, 15
	vrlw 12, 12, 5
	xxsldwi 43, 43, 43, 1
	vadduwm 10, 12, 10
	xxswapd	0, 44
	xxspltw 44, 48, 2
	xxlxor 41, 42, 41
	xxsldwi 42, 42, 42, 3
	vrlw 9, 9, 0
	vmrglw 12, 12, 13
	vadduwm 11, 9, 11
	vmrglw 12, 12, 12
	xxlxor 49, 43, 0
	vperm 17, 17, 17, 3
	vadduwm 10, 10, 17
	xxlxor 41, 42, 41
	vrlw 18, 9, 4
	xxsel 41, 46, 44, 38
	xxmrghd	44, 45, 40
	vmrglw 8, 8, 13
	vadduwm 11, 11, 9
	xxsel 0, 44, 48, 39
	vadduwm 11, 11, 18
	xxlxor 46, 43, 49
	xxsldwi 1, 0, 0, 1
	xxsldwi 43, 43, 43, 3
	vmrghw 13, 16, 8
	vrlw 12, 14, 5
	xxsldwi 0, 0, 1, 2
	xxsldwi 49, 1, 0, 3
	vadduwm 10, 12, 10
	xxswapd	0, 44
	vadduwm 11, 11, 17
	xxlxor 46, 42, 50
	xxsldwi 42, 42, 42, 1
	vrlw 14, 14, 0
	vadduwm 11, 11, 14
	xxlxor 44, 43, 0
	xxsldwi 0, 45, 40, 1
	vperm 12, 12, 12, 3
	xxsldwi 45, 0, 48, 1
	vadduwm 11, 11, 13
	vadduwm 10, 10, 12
	xxlxor 40, 42, 46
	xxsldwi 46, 47, 47, 1
	vrlw 8, 8, 4
	vperm 1, 14, 9, 1
	xxsldwi 46, 46, 46, 1
	vmrglw 14, 14, 14
	vadduwm 11, 11, 8
	xxlxor 44, 43, 44
	vadduwm 1, 11, 1
	xxspltw 43, 49, 2
	vrlw 12, 12, 5
	xxsldwi 33, 33, 33, 1
	vmrglw 11, 11, 13
	vadduwm 10, 12, 10
	xxswapd	0, 44
	xxlxor 40, 42, 40
	xxsldwi 42, 42, 42, 3
	vmrglw 11, 11, 11
	vrlw 8, 8, 0
	xxsel 38, 46, 43, 38
	vadduwm 1, 8, 1
	xxlxor 44, 33, 0
	vadduwm 1, 1, 6
	xxmrghd	38, 45, 41
	vperm 12, 12, 12, 3
	xxsel 0, 38, 49, 39
	xxsldwi 1, 0, 0, 1
	vadduwm 10, 10, 12
	xxlxor 40, 42, 40
	xxsldwi 0, 0, 1, 2
	vrlw 8, 8, 4
	vadduwm 1, 1, 8
	xxlxor 43, 33, 44
	xxsldwi 33, 33, 33, 3
	vrlw 6, 11, 5
	vadduwm 7, 6, 10
	xxsldwi 42, 1, 0, 3
	xxswapd	0, 38
	vmrglw 6, 9, 13
	xxlxor 40, 39, 40
	xxsldwi 39, 39, 39, 1
	vadduwm 1, 1, 10
	vrlw 8, 8, 0
	vadduwm 1, 1, 8
	xxlxor 41, 33, 0
	vperm 3, 9, 9, 3
	vmrghw 9, 17, 6
	vadduwm 7, 7, 3
	xxsldwi 0, 41, 38, 1
	xxlxor 40, 39, 40
	vrlw 4, 8, 4
	xxsldwi 38, 0, 49, 1
	vadduwm 1, 1, 6
	vadduwm 1, 1, 4
	xxlxor 35, 33, 35
	xxsldwi 0, 33, 33, 1
	vrlw 3, 3, 5
	vadduwm 5, 3, 7
	xxswapd	2, 35
	xxlxor 36, 37, 36
	xxsldwi 1, 37, 37, 3
	vrlw 4, 4, 0
	xxlxor 0, 1, 0
	stxvw4x 0, 0, 10
	xxlxor 3, 36, 2
	stxvw4x 3, 10, 6
	lvx 3, 3, 6
	lvx 4, 0, 3
	vperm 3, 4, 3, 2
	xxlxor 0, 1, 35
	stxvw4x 0, 10, 5
	lvx 3, 3, 11
	lvx 4, 3, 6
	vperm 2, 4, 3, 2
	xxlxor 0, 2, 34
	stxvw4x 0, 10, 7
	addi 1, 1, 80
	blr
.Lfunc_end1:
	.size	_blake3_compress_xof_sse2, .Lfunc_end1-.Lfunc_begin1

	.section	.rodata.cst16,"aM",@progbits,16
	.p2align	4
.LCPI2_0:
	.long	0
	.long	1
	.long	2
	.long	3
.LCPI2_1:
	.byte	2
	.byte	3
	.byte	0
	.byte	1
	.byte	6
	.byte	7
	.byte	4
	.byte	5
	.byte	10
	.byte	11
	.byte	8
	.byte	9
	.byte	14
	.byte	15
	.byte	12
	.byte	13
.LCPI2_2:
	.long	1779033703
	.long	1779033703
	.long	1779033703
	.long	1779033703
.LCPI2_3:
	.long	3144134277
	.long	3144134277
	.long	3144134277
	.long	3144134277
.LCPI2_4:
	.long	1013904242
	.long	1013904242
	.long	1013904242
	.long	1013904242
.LCPI2_5:
	.long	2773480762
	.long	2773480762
	.long	2773480762
	.long	2773480762
	.text
	.globl	_blake3_hash_many_sse2
	.p2align	2
	.type	_blake3_hash_many_sse2,@function
_blake3_hash_many_sse2:
.Lfunc_begin2:
	mflr 0
	stw 0, 4(1)
	stwu 1, -592(1)
	li 11, 304
	stw 21, 524(1)
	lwz 21, 604(1)
	stxvd2x 52, 1, 11
	li 11, 320
	stw 24, 536(1)
	stxvd2x 53, 1, 11
	li 11, 336
	stw 26, 544(1)
	stxvd2x 54, 1, 11
	li 11, 352
	mr	26, 5
	lwz 24, 608(1)
	stxvd2x 55, 1, 11
	li 11, 368
	lwz 5, 600(1)
	cmplwi 1, 4, 4
	stxvd2x 56, 1, 11
	li 11, 384
	stw 14, 496(1)
	stxvd2x 57, 1, 11
	li 11, 400
	stw 20, 520(1)
	stxvd2x 58, 1, 11
	li 11, 416
	stw 25, 540(1)
	stxvd2x 59, 1, 11
	li 11, 432
	stw 28, 552(1)
	stxvd2x 60, 1, 11
	li 11, 448
	stw 29, 556(1)
	stxvd2x 61, 1, 11
	li 11, 464
	stw 30, 560(1)
	stxvd2x 62, 1, 11
	li 11, 480
	mr	30, 10
	mr	29, 8
	mr	28, 7
	mr	14, 6
	mr	25, 4
	mr	20, 3
	andi. 4, 9, 1
	stw 15, 500(1)
	stfd 29, 568(1)
	stw 16, 504(1)
	stw 17, 508(1)
	stw 18, 512(1)
	stw 19, 516(1)
	stw 22, 528(1)
	stw 23, 532(1)
	stw 27, 548(1)
	stw 31, 564(1)
	stfd 30, 576(1)
	stfd 31, 584(1)
	stxvd2x 63, 1, 11
	stw 5, 20(1)
	blt	1, .LBB2_8
	li 3, -1
	li 4, 0
	vspltisb 2, -1
	or 5, 5, 30
	iselgt	3, 3, 4
	addi 4, 1, 256
	li 18, 16
	li 17, 32
	stw 3, 256(1)
	li 3, .LCPI2_0@l
	li 16, 48
	lxvw4x 0, 0, 4
	lis 4, .LCPI2_0@ha
	vslw 2, 2, 2
	stw 5, 28(1)
	lxvw4x 1, 4, 3
	addi 3, 1, 144
	addi 5, 1, 224
	li 15, 63
	stw 3, 52(1)
	addi 3, 1, 160
	li 8, .LCPI2_4@l
	xxspltw 0, 0, 0
	stw 3, 48(1)
	addi 3, 1, 176
	lis 9, .LCPI2_4@ha
	stw 3, 44(1)
	addi 3, 1, 192
	li 10, .LCPI2_5@l
	stw 5, 68(1)
	addi 5, 1, 96
	lis 11, .LCPI2_5@ha
	xxland 0, 0, 1
	stw 3, 40(1)
	addi 3, 1, 208
	li 6, 0
	stw 5, 64(1)
	addi 5, 1, 112
	xxlor 8, 34, 34
	stw 3, 36(1)
	addi 3, 1, 240
	xxlor 9, 0, 0
	xxlor 10, 0, 34
	cmpwi 1, 26, 0
	stw 5, 60(1)
	addi 5, 1, 128
	stw 3, 24(1)
	lis 3, .LCPI2_3@ha
	stw 5, 56(1)
	stw 20, 32(1)
	stw 14, 72(1)
.LBB2_2:
	lwz 4, 0(14)
	lwz 5, 68(1)
	stw 4, 224(1)
	lwz 4, 4(14)
	lxvw4x 0, 0, 5
	lwz 5, 64(1)
	stw 4, 96(1)
	lwz 4, 8(14)
	lxvw4x 1, 0, 5
	xxspltw 40, 0, 0
	lwz 5, 60(1)
	stw 4, 112(1)
	lwz 4, 12(14)
	lxvw4x 2, 0, 5
	xxspltw 39, 1, 0
	lwz 5, 56(1)
	stw 4, 128(1)
	lwz 4, 16(14)
	lxvw4x 3, 0, 5
	xxspltw 38, 2, 0
	lwz 5, 52(1)
	stw 4, 144(1)
	lwz 4, 20(14)
	lxvw4x 4, 0, 5
	xxspltw 33, 3, 0
	lwz 5, 48(1)
	stw 4, 160(1)
	lwz 4, 24(14)
	lxvw4x 0, 0, 5
	xxspltw 45, 4, 0
	lwz 5, 44(1)
	stw 4, 176(1)
	lwz 4, 28(14)
	lxvw4x 1, 0, 5
	xxspltw 48, 0, 0
	stw 4, 192(1)
	lwz 4, 40(1)
	xxspltw 46, 1, 0
	lxvw4x 2, 0, 4
	lwz 4, 36(1)
	stw 29, 208(1)
	lxvw4x 0, 0, 4
	stw 28, 240(1)
	xxspltw 43, 2, 0
	stw 6, 76(1)
	bc 12, 6, .LBB2_7
	xxspltw 36, 0, 0
	xxlor 34, 9, 9
	lwz 4, 24(1)
	lwz 5, 32(1)
	xxlor 0, 8, 8
	lwz 23, 0(20)
	lwz 22, 4(20)
	lxvw4x 0, 0, 4
	slwi 4, 6, 4
	lwz 12, 8(20)
	vadduwm 2, 4, 2
	add 4, 4, 5
	lwz 27, 12(20)
	lwz 14, 28(1)
	addi 0, 4, -4
	li 5, 0
	xxlor 1, 34, 34
	xxspltw 32, 0, 0
	xxlxor 36, 34, 8
	xxlor 34, 10, 10
	vcmpgtsw 4, 2, 4
	vsubuwm 2, 0, 4
	xxlor 3, 34, 34
.LBB2_4:
	slwi 31, 5, 6
	addi 5, 5, 1
	add 4, 23, 31
	add 19, 22, 31
	add 6, 12, 31
	add 7, 27, 31
	lvsl 9, 23, 31
	lvx 4, 23, 31
	cmplw 5, 5, 26
	lvsl 17, 27, 31
	lvx 19, 4, 18
	lvx 12, 22, 31
	lvx 30, 19, 18
	lvx 18, 12, 31
	lvx 28, 6, 18
	vperm 4, 4, 19, 9
	lvx 31, 27, 31
	lvx 27, 7, 18
	lvx 26, 4, 17
	lvsl 15, 12, 31
	lvx 24, 19, 17
	vperm 29, 31, 27, 17
	lvx 22, 6, 17
	vperm 31, 19, 26, 9
	lvx 19, 7, 17
	lvx 21, 4, 16
	lvx 20, 19, 16
	lvx 2, 6, 16
	vperm 18, 18, 28, 15
	lvx 3, 7, 16
	lvx 0, 4, 15
	vperm 25, 28, 22, 15
	li 4, 0
	lvsl 10, 22, 31
	vperm 28, 26, 21, 9
	vperm 9, 21, 0, 9
	lvx 0, 19, 15
	vperm 12, 12, 30, 10
	vperm 30, 30, 24, 10
	vperm 23, 27, 19, 17
	vperm 27, 24, 20, 10
	vperm 26, 22, 2, 15
	lvx 22, 6, 15
	vperm 10, 20, 0, 10
	lvx 0, 7, 15
	vperm 24, 19, 3, 17
	vperm 15, 2, 22, 15
	vperm 17, 3, 0, 17
	isel 4, 21, 4, 22
	or 4, 4, 14
	clrlwi	14, 4, 24
	li 4, 4
	mtctr 4
	mr	4, 0
.LBB2_5:
	lwzu 6, 4(4)
	add 6, 6, 31
	addi 6, 6, 256
	dcbt 0, 6
	bdnz .LBB2_5
	vmrghw 2, 9, 10
	stw 14, 80(1)
	addi 4, 1, 80
	lis 6, .LCPI2_1@ha
	vmrghw 19, 4, 12
	lxvw4x 0, 0, 4
	li 4, .LCPI2_1@l
	mr	14, 30
	vmrglw 12, 4, 12
	vmrghw 4, 18, 29
	vmrglw 20, 18, 29
	vmrghw 18, 31, 30
	xxlor 30, 34, 34
	vspltisw 0, 10
	vmrglw 2, 9, 10
	vmrglw 29, 31, 30
	vmrghw 31, 25, 23
	vmrglw 21, 25, 23
	vadduwm 3, 13, 8
	vspltisw 8, 12
	vadduwm 9, 16, 7
	xxspltw 0, 0, 0
	xxlor 29, 34, 34
	vspltisw 2, 4
	vadduwm 5, 6, 14
	vadduwm 10, 1, 11
	vspltisw 1, 9
	vslw 2, 2, 2
	vadduwm 7, 0, 0
	xxmrghd	32, 44, 52
	xxlor 12, 43, 43
	xxmrghd	43, 51, 36
	vadduwm 6, 8, 8
	xxmrghd	40, 50, 63
	xxlor 6, 45, 45
	xxmrghd	45, 61, 53
	vadduwm 3, 3, 11
	xxmrgld	63, 50, 63
	xxlor 31, 43, 43
	xxmrgld	62, 61, 53
	vadduwm 11, 9, 0
	lxvw4x 41, 6, 4
	li 4, .LCPI2_2@l
	lis 6, .LCPI2_2@ha
	xxlor 5, 32, 32
	vadduwm 0, 5, 8
	xxmrgld	37, 44, 52
	vadduwm 10, 10, 13
	vmrghw 25, 28, 27
	vmrglw 28, 28, 27
	xxlor 11, 45, 45
	xxmrgld	59, 51, 36
	xxlxor 34, 32, 34
	xxlxor 36, 35, 1
	xxlxor 45, 43, 3
	xxlxor 52, 42, 0
	vmrghw 23, 26, 24
	vmrglw 22, 26, 24
	vmrghw 26, 15, 17
	vmrglw 24, 15, 17
	vspltisw 15, -16
	xxlor 4, 40, 40
	vperm 8, 4, 4, 9
	vperm 13, 13, 13, 9
	vperm 4, 2, 2, 9
	lxvw4x 34, 11, 10
	vperm 20, 20, 20, 9
	xxlor 0, 46, 46
	lxvw4x 46, 6, 4
	li 4, .LCPI2_3@l
	xxmrgld	53, 60, 54
	vsubuwm 1, 1, 15
	xxlor 7, 48, 48
	lxvw4x 48, 3, 4
	vadduwm 15, 3, 27
	lxvw4x 35, 9, 8
	vadduwm 19, 8, 14
	vadduwm 16, 13, 16
	vadduwm 17, 4, 3
	vadduwm 14, 20, 2
	xxlxor 35, 48, 7
	xxlxor 50, 49, 0
	xxlxor 61, 46, 12
	xxlor 2, 1, 1
	xxlxor 34, 51, 6
	vrlw 3, 3, 7
	vrlw 18, 18, 7
	vrlw 29, 29, 7
	xxlor 2, 3, 3
	vadduwm 12, 11, 5
	xxlor 2, 37, 37
	vrlw 5, 2, 7
	vadduwm 0, 0, 31
	vadduwm 10, 10, 30
	vadduwm 12, 12, 3
	vadduwm 0, 0, 18
	vadduwm 10, 10, 29
	vadduwm 15, 15, 5
	xxlxor 45, 44, 45
	xxlxor 36, 32, 36
	xxlxor 52, 42, 52
	xxlxor 34, 47, 40
	vrlw 11, 13, 6
	vrlw 4, 4, 6
	vrlw 20, 20, 6
	vrlw 8, 2, 6
	xxlor 13, 63, 63
	xxmrghd	45, 57, 55
	xxmrghd	34, 60, 54
	xxlor 60, 11, 11
	vadduwm 31, 11, 16
	vadduwm 17, 4, 17
	vadduwm 16, 20, 14
	vadduwm 19, 8, 19
	xxlxor 35, 63, 35
	xxlxor 50, 49, 50
	xxlxor 61, 48, 61
	vadduwm 15, 15, 13
	xxlor 7, 45, 45
	vadduwm 13, 12, 2
	xxlxor 44, 51, 37
	xxmrghd	37, 30, 58
	vrlw 3, 3, 1
	vrlw 18, 18, 1
	vrlw 14, 29, 1
	vrlw 12, 12, 1
	xxlor 0, 34, 34
	xxmrghd	34, 29, 56
	vadduwm 0, 0, 5
	vadduwm 15, 15, 3
	vadduwm 10, 10, 2
	vadduwm 13, 13, 18
	vadduwm 0, 0, 14
	vmr	29, 5
	vadduwm 10, 10, 12
	xxlxor 52, 47, 52
	xxlxor 37, 45, 40
	xxlxor 40, 32, 43
	xxlor 6, 34, 34
	xxmrgld	34, 57, 55
	xxlxor 36, 42, 36
	vperm 23, 20, 20, 9
	vperm 8, 8, 8, 9
	vperm 5, 5, 5, 9
	vperm 4, 4, 4, 9
	vadduwm 15, 15, 2
	xxlor 12, 34, 34
	vadduwm 20, 17, 23
	vadduwm 17, 19, 8
	vadduwm 25, 16, 5
	xxmrgld	48, 30, 58
	vadduwm 22, 31, 4
	xxlxor 43, 49, 46
	xxmrgld	46, 29, 56
	xxlxor 35, 52, 35
	xxlxor 50, 57, 50
	xxlxor 34, 54, 44
	vrlw 11, 11, 7
	vrlw 3, 3, 7
	vrlw 18, 18, 7
	vrlw 2, 2, 7
	vadduwm 0, 0, 16
	vadduwm 13, 13, 21
	vadduwm 10, 10, 14
	vadduwm 0, 0, 11
	vadduwm 15, 15, 3
	vadduwm 13, 13, 18
	vadduwm 10, 10, 2
	xxlxor 40, 32, 40
	xxlxor 58, 47, 55
	xxlxor 37, 45, 37
	xxlxor 36, 42, 36
	vrlw 8, 8, 6
	vrlw 26, 26, 6
	vrlw 5, 5, 6
	vrlw 4, 4, 6
	vmr	31, 14
	xxlor 56, 4, 4
	vadduwm 17, 8, 17
	vadduwm 12, 26, 20
	vadduwm 14, 5, 25
	vadduwm 25, 4, 22
	xxlxor 43, 49, 43
	xxlxor 35, 44, 35
	xxlxor 50, 46, 50
	xxlxor 34, 57, 34
	vrlw 11, 11, 1
	vrlw 2, 2, 1
	vrlw 3, 3, 1
	vrlw 18, 18, 1
	xxlor 55, 5, 5
	xxlor 51, 2, 2
	vadduwm 10, 10, 24
	vadduwm 15, 15, 23
	vadduwm 13, 13, 19
	vadduwm 0, 0, 30
	vadduwm 10, 10, 11
	vadduwm 15, 15, 2
	vadduwm 13, 13, 3
	vadduwm 0, 0, 18
	xxlxor 58, 42, 58
	xxlxor 37, 47, 37
	xxlxor 40, 45, 40
	xxlxor 36, 32, 36
	vperm 26, 26, 26, 9
	vperm 5, 5, 5, 9
	vperm 8, 8, 8, 9
	vperm 4, 4, 4, 9
	xxlor 54, 0, 0
	xxlor 52, 31, 31
	vadduwm 14, 14, 26
	vadduwm 17, 17, 5
	vadduwm 25, 25, 8
	vadduwm 12, 12, 4
	xxlxor 43, 46, 43
	xxlxor 34, 49, 34
	xxlxor 35, 57, 35
	xxlxor 50, 44, 50
	vrlw 11, 11, 7
	vrlw 2, 2, 7
	vrlw 3, 3, 7
	vrlw 18, 18, 7
	vadduwm 10, 10, 16
	vadduwm 15, 15, 28
	vadduwm 13, 13, 22
	vadduwm 0, 0, 20
	vadduwm 10, 10, 11
	vadduwm 15, 15, 2
	vadduwm 13, 13, 3
	vadduwm 0, 0, 18
	xxlxor 58, 42, 58
	xxlxor 37, 47, 37
	xxlxor 40, 45, 40
	xxlxor 36, 32, 36
	vrlw 26, 26, 6
	vrlw 5, 5, 6
	vrlw 8, 8, 6
	vrlw 4, 4, 6
	vadduwm 15, 15, 27
	xxlor 11, 59, 59
	vadduwm 14, 26, 14
	vadduwm 17, 5, 17
	vadduwm 25, 8, 25
	vadduwm 12, 4, 12
	xxlxor 43, 46, 43
	xxlxor 34, 49, 34
	xxlxor 35, 57, 35
	xxlxor 50, 44, 50
	vrlw 11, 11, 1
	vrlw 3, 3, 1
	vrlw 18, 18, 1
	vrlw 2, 2, 1
	xxlor 59, 12, 12
	vadduwm 13, 13, 29
	vadduwm 0, 0, 27
	vadduwm 10, 10, 31
	vadduwm 0, 0, 11
	vadduwm 15, 15, 3
	vadduwm 13, 13, 18
	vadduwm 10, 10, 2
	xxlxor 40, 32, 40
	xxlxor 58, 47, 58
	xxlxor 37, 45, 37
	xxlxor 36, 42, 36
	vperm 8, 8, 8, 9
	vperm 26, 26, 26, 9
	vperm 5, 5, 5, 9
	vperm 4, 4, 4, 9
	vmr	20, 16
	xxlor 48, 13, 13
	vadduwm 17, 17, 8
	vadduwm 12, 12, 26
	vadduwm 14, 14, 5
	vadduwm 25, 25, 4
	xxlxor 43, 49, 43
	xxlxor 35, 44, 35
	xxlxor 50, 46, 50
	xxlxor 34, 57, 34
	vrlw 11, 11, 7
	vadduwm 13, 13, 16
	vrlw 3, 3, 7
	vrlw 18, 18, 7
	vrlw 2, 2, 7
	xxlor 48, 6, 6
	xxlor 2, 31, 31
	xxlor 31, 63, 63
	vadduwm 0, 0, 16
	xxlor 63, 7, 7
	vadduwm 15, 15, 21
	vadduwm 10, 10, 31
	vadduwm 0, 0, 11
	vadduwm 15, 15, 3
	vadduwm 13, 13, 18
	vadduwm 10, 10, 2
	xxlxor 40, 32, 40
	xxlxor 58, 47, 58
	xxlxor 37, 45, 37
	xxlxor 36, 42, 36
	vrlw 8, 8, 6
	vrlw 26, 26, 6
	vrlw 5, 5, 6
	vrlw 4, 4, 6
	vadduwm 10, 10, 30
	vadduwm 15, 15, 19
	vadduwm 17, 8, 17
	vadduwm 12, 26, 12
	vadduwm 14, 5, 14
	vadduwm 25, 4, 25
	xxlxor 43, 49, 43
	xxlxor 35, 44, 35
	xxlxor 50, 46, 50
	xxlxor 34, 57, 34
	vrlw 11, 11, 1
	vrlw 2, 2, 1
	vrlw 3, 3, 1
	vrlw 18, 18, 1
	vadduwm 13, 13, 22
	vadduwm 0, 0, 20
	vadduwm 10, 10, 11
	vadduwm 15, 15, 2
	vadduwm 13, 13, 3
	vadduwm 0, 0, 18
	xxlxor 58, 42, 58
	xxlxor 37, 47, 37
	xxlxor 40, 45, 40
	xxlxor 36, 32, 36
	vperm 26, 26, 26, 9
	vperm 5, 5, 5, 9
	vperm 8, 8, 8, 9
	vperm 4, 4, 4, 9
	vadduwm 10, 10, 16
	vadduwm 15, 15, 24
	vadduwm 14, 14, 26
	vadduwm 17, 17, 5
	vadduwm 25, 25, 8
	vadduwm 12, 12, 4
	xxlxor 43, 46, 43
	xxlxor 34, 49, 34
	xxlxor 35, 57, 35
	xxlxor 50, 44, 50
	vrlw 11, 11, 7
	vrlw 2, 2, 7
	vrlw 3, 3, 7
	vrlw 18, 18, 7
	vadduwm 13, 13, 29
	vadduwm 0, 0, 23
	vadduwm 10, 10, 11
	vadduwm 15, 15, 2
	vadduwm 13, 13, 3
	vadduwm 0, 0, 18
	xxlxor 58, 42, 58
	xxlxor 37, 47, 37
	xxlxor 40, 45, 40
	xxlxor 36, 32, 36
	vrlw 26, 26, 6
	vrlw 5, 5, 6
	vrlw 8, 8, 6
	vrlw 4, 4, 6
	vadduwm 0, 0, 21
	vadduwm 15, 15, 28
	vadduwm 14, 26, 14
	vadduwm 17, 5, 17
	vadduwm 25, 8, 25
	vadduwm 12, 4, 12
	xxlxor 43, 46, 43
	xxlxor 34, 49, 34
	xxlxor 35, 57, 35
	xxlxor 50, 44, 50
	vrlw 11, 11, 1
	vrlw 3, 3, 1
	vrlw 18, 18, 1
	vrlw 2, 2, 1
	vadduwm 13, 13, 27
	vadduwm 10, 10, 31
	vadduwm 0, 0, 11
	vadduwm 15, 15, 3
	vadduwm 13, 13, 18
	vadduwm 10, 10, 2
	xxlxor 40, 32, 40
	xxlxor 58, 47, 58
	xxlxor 37, 45, 37
	xxlxor 36, 42, 36
	vperm 8, 8, 8, 9
	vperm 26, 26, 26, 9
	vperm 5, 5, 5, 9
	vperm 4, 4, 4, 9
	xxlor 12, 5, 5
	xxlor 5, 60, 60
	vadduwm 17, 17, 8
	vadduwm 12, 12, 26
	vadduwm 14, 14, 5
	vadduwm 25, 25, 4
	xxlxor 43, 49, 43
	xxlxor 35, 44, 35
	xxlxor 50, 46, 50
	xxlxor 34, 57, 34
	vrlw 11, 11, 7
	vrlw 3, 3, 7
	vrlw 18, 18, 7
	vrlw 2, 2, 7
	xxlor 60, 31, 31
	vmr	24, 29
	vmr	29, 16
	xxlor 63, 13, 13
	xxlor 55, 2, 2
	vadduwm 0, 0, 28
	xxlor 48, 11, 11
	vadduwm 15, 15, 31
	vadduwm 13, 13, 23
	vadduwm 10, 10, 16
	vadduwm 0, 0, 11
	vadduwm 15, 15, 3
	vadduwm 13, 13, 18
	vadduwm 10, 10, 2
	xxlxor 40, 32, 40
	xxlxor 58, 47, 58
	xxlxor 37, 45, 37
	xxlxor 36, 42, 36
	vrlw 8, 8, 6
	vrlw 26, 26, 6
	vrlw 5, 5, 6
	vrlw 4, 4, 6
	xxlor 0, 52, 52
	vadduwm 15, 15, 22
	vadduwm 17, 8, 17
	vadduwm 12, 26, 12
	vadduwm 14, 5, 14
	vadduwm 25, 4, 25
	xxlxor 43, 49, 43
	xxlxor 35, 44, 35
	xxlxor 50, 46, 50
	xxlxor 34, 57, 34
	vrlw 11, 11, 1
	xxlor 2, 54, 54
	vrlw 2, 2, 1
	vrlw 3, 3, 1
	vrlw 18, 18, 1
	vadduwm 0, 0, 29
	vmr	22, 29
	xxlor 61, 0, 0
	vadduwm 13, 13, 24
	vadduwm 10, 10, 29
	vadduwm 15, 15, 2
	vadduwm 10, 10, 11
	vadduwm 13, 13, 3
	vadduwm 0, 0, 18
	xxlxor 58, 42, 58
	xxlxor 37, 47, 37
	xxlxor 40, 45, 40
	xxlxor 36, 32, 36
	vperm 26, 26, 26, 9
	vperm 5, 5, 5, 9
	vperm 8, 8, 8, 9
	vperm 4, 4, 4, 9
	vadduwm 10, 10, 28
	vadduwm 15, 15, 30
	vadduwm 14, 14, 26
	vadduwm 17, 17, 5
	vadduwm 25, 25, 8
	vadduwm 12, 12, 4
	xxlxor 43, 46, 43
	xxlxor 34, 49, 34
	xxlxor 35, 57, 35
	xxlxor 50, 44, 50
	vrlw 11, 11, 7
	vrlw 2, 2, 7
	vrlw 3, 3, 7
	vrlw 18, 18, 7
	vadduwm 13, 13, 27
	vadduwm 0, 0, 19
	vadduwm 10, 10, 11
	vadduwm 15, 15, 2
	vadduwm 13, 13, 3
	vadduwm 0, 0, 18
	xxlxor 58, 42, 58
	xxlxor 37, 47, 37
	xxlxor 40, 45, 40
	xxlxor 36, 32, 36
	vrlw 26, 26, 6
	vrlw 5, 5, 6
	vrlw 8, 8, 6
	vrlw 4, 4, 6
	xxlor 52, 4, 4
	vadduwm 0, 0, 31
	vadduwm 14, 26, 14
	vadduwm 17, 5, 17
	vadduwm 25, 8, 25
	vadduwm 12, 4, 12
	xxlxor 43, 46, 43
	xxlxor 34, 49, 34
	xxlxor 35, 57, 35
	xxlxor 50, 44, 50
	vrlw 11, 11, 1
	vrlw 3, 3, 1
	vrlw 18, 18, 1
	vrlw 2, 2, 1
	vadduwm 15, 15, 20
	vadduwm 13, 13, 21
	vadduwm 10, 10, 16
	vadduwm 0, 0, 11
	vadduwm 15, 15, 3
	vadduwm 13, 13, 18
	vadduwm 10, 10, 2
	xxlxor 40, 32, 40
	xxlxor 58, 47, 58
	xxlxor 37, 45, 37
	xxlxor 36, 42, 36
	vperm 8, 8, 8, 9
	vperm 26, 26, 26, 9
	vperm 5, 5, 5, 9
	vperm 4, 4, 4, 9
	xxlor 4, 7, 7
	xxlor 7, 62, 62
	vadduwm 17, 17, 8
	vadduwm 12, 12, 26
	vadduwm 14, 14, 5
	vadduwm 25, 25, 4
	xxlxor 43, 49, 43
	xxlxor 35, 44, 35
	xxlxor 50, 46, 50
	xxlxor 34, 57, 34
	vrlw 11, 11, 7
	vrlw 3, 3, 7
	vrlw 18, 18, 7
	vrlw 2, 2, 7
	xxlor 60, 4, 4
	vmr	30, 31
	xxlor 11, 48, 48
	vmr	31, 23
	vadduwm 15, 15, 23
	xxlor 55, 12, 12
	vadduwm 0, 0, 28
	xxlor 48, 5, 5
	vadduwm 13, 13, 23
	vadduwm 10, 10, 16
	vadduwm 0, 0, 11
	vadduwm 15, 15, 3
	vadduwm 13, 13, 18
	vadduwm 10, 10, 2
	xxlxor 40, 32, 40
	xxlxor 58, 47, 58
	xxlxor 37, 45, 37
	xxlxor 36, 42, 36
	vrlw 8, 8, 6
	vrlw 26, 26, 6
	vrlw 5, 5, 6
	vrlw 4, 4, 6
	xxlor 6, 51, 51
	xxlor 13, 51, 51
	vadduwm 17, 8, 17
	vadduwm 12, 26, 12
	vadduwm 14, 5, 14
	vadduwm 25, 4, 25
	xxlxor 43, 49, 43
	xxlxor 35, 44, 35
	xxlxor 50, 46, 50
	xxlxor 34, 57, 34
	vrlw 11, 11, 1
	vrlw 2, 2, 1
	vrlw 3, 3, 1
	vrlw 18, 18, 1
	xxlor 51, 31, 31
	vadduwm 10, 10, 22
	vadduwm 15, 15, 24
	vadduwm 13, 13, 27
	vadduwm 0, 0, 19
	vadduwm 10, 10, 11
	vadduwm 15, 15, 2
	vadduwm 13, 13, 3
	vadduwm 0, 0, 18
	xxlxor 58, 42, 58
	xxlxor 37, 47, 37
	xxlxor 40, 45, 40
	xxlxor 36, 32, 36
	vperm 26, 26, 26, 9
	vperm 5, 5, 5, 9
	vperm 8, 8, 8, 9
	vperm 4, 4, 4, 9
	xxlor 51, 2, 2
	vadduwm 10, 10, 28
	vadduwm 14, 14, 26
	vadduwm 17, 17, 5
	vadduwm 25, 25, 8
	vadduwm 12, 12, 4
	xxlxor 43, 46, 43
	xxlxor 34, 49, 34
	xxlxor 35, 57, 35
	xxlxor 50, 44, 50
	vrlw 11, 11, 7
	vrlw 2, 2, 7
	vrlw 3, 3, 7
	vrlw 18, 18, 7
	vadduwm 15, 15, 29
	vadduwm 13, 13, 21
	vadduwm 0, 0, 19
	vadduwm 10, 10, 11
	vadduwm 15, 15, 2
	vadduwm 13, 13, 3
	vadduwm 0, 0, 18
	xxlxor 58, 42, 58
	xxlxor 37, 47, 37
	xxlxor 40, 45, 40
	xxlxor 36, 32, 36
	vrlw 26, 26, 6
	vrlw 5, 5, 6
	vrlw 8, 8, 6
	vrlw 4, 4, 6
	xxlor 12, 61, 61
	xxlor 61, 7, 7
	vadduwm 14, 26, 14
	vadduwm 17, 5, 17
	vadduwm 25, 8, 25
	vadduwm 12, 4, 12
	xxlxor 43, 46, 43
	xxlxor 34, 49, 34
	xxlxor 35, 57, 35
	xxlxor 50, 44, 50
	vrlw 11, 11, 1
	vrlw 3, 3, 1
	vrlw 18, 18, 1
	vrlw 2, 2, 1
	vadduwm 0, 0, 31
	vadduwm 15, 15, 29
	vadduwm 13, 13, 30
	vadduwm 10, 10, 16
	vadduwm 0, 0, 11
	vadduwm 15, 15, 3
	vadduwm 13, 13, 18
	vadduwm 10, 10, 2
	xxlxor 40, 32, 40
	xxlxor 58, 47, 58
	xxlxor 37, 45, 37
	xxlxor 36, 42, 36
	vperm 8, 8, 8, 9
	vperm 26, 26, 26, 9
	vperm 5, 5, 5, 9
	vperm 4, 4, 4, 9
	xxlor 0, 56, 56
	vmr	24, 27
	vadduwm 17, 17, 8
	vadduwm 12, 12, 26
	vadduwm 14, 14, 5
	vadduwm 25, 25, 4
	xxlxor 43, 49, 43
	xxlxor 35, 44, 35
	xxlxor 50, 46, 50
	xxlxor 34, 57, 34
	vrlw 11, 11, 7
	vrlw 3, 3, 7
	vrlw 18, 18, 7
	vrlw 2, 2, 7
	xxlor 59, 11, 11
	xxlor 61, 13, 13
	vadduwm 0, 0, 27
	vadduwm 15, 15, 23
	vadduwm 13, 13, 29
	vadduwm 10, 10, 20
	vadduwm 0, 0, 11
	vadduwm 15, 15, 3
	vadduwm 13, 13, 18
	vadduwm 10, 10, 2
	xxlxor 40, 32, 40
	xxlxor 58, 47, 58
	xxlxor 37, 45, 37
	xxlxor 36, 42, 36
	vrlw 8, 8, 6
	vrlw 26, 26, 6
	vrlw 5, 5, 6
	vrlw 4, 4, 6
	vadduwm 0, 0, 28
	xxlor 11, 60, 60
	vadduwm 17, 8, 17
	vadduwm 12, 26, 12
	vadduwm 14, 5, 14
	vadduwm 25, 4, 25
	xxlxor 43, 49, 43
	xxlxor 35, 44, 35
	xxlxor 50, 46, 50
	xxlxor 34, 57, 34
	vrlw 11, 11, 1
	vrlw 2, 2, 1
	vrlw 3, 3, 1
	vrlw 18, 18, 1
	xxlor 60, 31, 31
	vadduwm 15, 15, 24
	vadduwm 10, 10, 28
	vadduwm 13, 13, 21
	vadduwm 10, 10, 11
	vadduwm 15, 15, 2
	vadduwm 13, 13, 3
	vadduwm 0, 0, 18
	xxlxor 58, 42, 58
	xxlxor 37, 47, 37
	xxlxor 40, 45, 40
	xxlxor 36, 32, 36
	vperm 26, 26, 26, 9
	vperm 5, 5, 5, 9
	vperm 8, 8, 8, 9
	vperm 4, 4, 4, 9
	xxlor 4, 31, 31
	vadduwm 15, 15, 22
	vadduwm 14, 14, 26
	vadduwm 17, 17, 5
	vadduwm 25, 25, 8
	vadduwm 12, 12, 4
	xxlxor 43, 46, 43
	xxlxor 34, 49, 34
	xxlxor 35, 57, 35
	xxlxor 50, 44, 50
	vrlw 11, 11, 7
	vrlw 2, 2, 7
	vrlw 3, 3, 7
	vrlw 18, 18, 7
	xxlor 4, 54, 54
	xxlor 54, 0, 0
	vadduwm 10, 10, 27
	vadduwm 13, 13, 30
	vadduwm 0, 0, 22
	vadduwm 10, 10, 11
	vadduwm 15, 15, 2
	vadduwm 13, 13, 3
	vadduwm 0, 0, 18
	xxlxor 58, 42, 58
	xxlxor 37, 47, 37
	xxlxor 40, 45, 40
	xxlxor 36, 32, 36
	vrlw 26, 26, 6
	vrlw 5, 5, 6
	vrlw 8, 8, 6
	vrlw 4, 4, 6
	xxlor 5, 63, 63
	xxlor 63, 12, 12
	vadduwm 14, 26, 14
	vadduwm 17, 5, 17
	vadduwm 25, 8, 25
	vadduwm 12, 4, 12
	xxlxor 43, 46, 43
	xxlxor 34, 49, 34
	xxlxor 35, 57, 35
	xxlxor 50, 44, 50
	vrlw 11, 11, 1
	vrlw 3, 3, 1
	vrlw 18, 18, 1
	vrlw 2, 2, 1
	vadduwm 15, 15, 31
	xxlor 63, 5, 5
	vadduwm 0, 0, 23
	vadduwm 13, 13, 31
	vadduwm 10, 10, 20
	vadduwm 0, 0, 11
	vadduwm 15, 15, 3
	vadduwm 13, 13, 18
	vadduwm 10, 10, 2
	xxlxor 40, 32, 40
	xxlxor 58, 47, 58
	xxlxor 37, 45, 37
	xxlxor 36, 42, 36
	vperm 8, 8, 8, 9
	vperm 26, 26, 26, 9
	vperm 5, 5, 5, 9
	vperm 4, 4, 4, 9
	vadduwm 15, 15, 29
	vadduwm 0, 0, 16
	vadduwm 17, 17, 8
	vadduwm 12, 12, 26
	vadduwm 14, 14, 5
	vadduwm 25, 25, 4
	xxlxor 43, 49, 43
	xxlxor 35, 44, 35
	xxlxor 50, 46, 50
	xxlxor 34, 57, 34
	vrlw 11, 11, 7
	vrlw 3, 3, 7
	vrlw 18, 18, 7
	vrlw 2, 2, 7
	xxlor 61, 7, 7
	vadduwm 13, 13, 19
	vadduwm 10, 10, 29
	vadduwm 0, 0, 11
	vadduwm 15, 15, 3
	vadduwm 13, 13, 18
	vadduwm 10, 10, 2
	xxlxor 40, 32, 40
	xxlxor 58, 47, 58
	xxlxor 37, 45, 37
	xxlxor 36, 42, 36
	vrlw 8, 8, 6
	vrlw 26, 26, 6
	vrlw 5, 5, 6
	vrlw 4, 4, 6
	vadduwm 13, 13, 30
	xxlor 51, 11, 11
	vadduwm 17, 8, 17
	vadduwm 12, 26, 12
	vadduwm 14, 5, 14
	vadduwm 30, 4, 25
	xxlxor 43, 49, 43
	xxlxor 35, 44, 35
	xxlxor 50, 46, 50
	xxlxor 34, 62, 34
	vrlw 11, 11, 1
	vrlw 2, 2, 1
	vrlw 3, 3, 1
	vrlw 18, 18, 1
	vadduwm 10, 10, 19
	vadduwm 15, 15, 21
	vadduwm 0, 0, 27
	vadduwm 10, 10, 11
	vadduwm 15, 15, 2
	vadduwm 13, 13, 3
	vadduwm 0, 0, 18
	xxlxor 51, 42, 58
	xxlxor 37, 47, 37
	xxlxor 40, 45, 40
	xxlxor 36, 32, 36
	vperm 19, 19, 19, 9
	vperm 5, 5, 5, 9
	vperm 8, 8, 8, 9
	vperm 4, 4, 4, 9
	xxlor 6, 56, 56
	vadduwm 13, 13, 31
	vadduwm 14, 14, 19
	vadduwm 17, 17, 5
	vadduwm 30, 30, 8
	vadduwm 12, 12, 4
	xxlxor 43, 46, 43
	xxlxor 34, 49, 34
	xxlxor 35, 62, 35
	xxlxor 50, 44, 50
	vrlw 11, 11, 7
	vrlw 2, 2, 7
	vrlw 3, 3, 7
	vrlw 18, 18, 7
	xxlor 63, 6, 6
	vadduwm 10, 10, 16
	vadduwm 15, 15, 28
	vadduwm 0, 0, 31
	vadduwm 10, 10, 11
	vadduwm 15, 15, 2
	vadduwm 13, 13, 3
	vadduwm 0, 0, 18
	xxlxor 51, 42, 51
	xxlxor 37, 47, 37
	xxlxor 40, 45, 40
	xxlxor 36, 32, 36
	vrlw 19, 19, 6
	vrlw 5, 5, 6
	vrlw 8, 8, 6
	vrlw 4, 4, 6
	xxlor 56, 13, 13
	xxlor 48, 4, 4
	vadduwm 14, 19, 14
	vadduwm 17, 5, 17
	vadduwm 31, 8, 30
	vadduwm 12, 4, 12
	xxlxor 43, 46, 43
	xxlxor 34, 49, 34
	xxlxor 35, 63, 35
	xxlxor 50, 44, 50
	vrlw 11, 11, 1
	vrlw 3, 3, 1
	vrlw 18, 18, 1
	vrlw 2, 2, 1
	vadduwm 0, 0, 24
	vadduwm 15, 15, 16
	vadduwm 13, 13, 23
	vadduwm 10, 10, 29
	vadduwm 0, 0, 11
	vadduwm 15, 15, 3
	vadduwm 13, 13, 18
	vadduwm 10, 10, 2
	xxlxor 40, 32, 40
	xxlxor 51, 47, 51
	xxlxor 37, 45, 37
	xxlxor 36, 42, 36
	vperm 8, 8, 8, 9
	vperm 19, 19, 19, 9
	vperm 5, 5, 5, 9
	vperm 4, 4, 4, 9
	xxlor 0, 52, 52
	xxlor 52, 2, 2
	vadduwm 13, 13, 22
	vadduwm 9, 15, 20
	vadduwm 15, 17, 8
	vadduwm 12, 12, 19
	vadduwm 14, 14, 5
	vadduwm 17, 31, 4
	xxlxor 43, 47, 43
	xxlxor 35, 44, 35
	xxlxor 50, 46, 50
	xxlxor 34, 49, 34
	vrlw 11, 11, 7
	vrlw 3, 3, 7
	vrlw 18, 18, 7
	vrlw 2, 2, 7
	xxlor 39, 0, 0
	vadduwm 0, 0, 7
	xxlor 39, 12, 12
	vadduwm 0, 0, 11
	vadduwm 7, 10, 7
	vadduwm 9, 9, 3
	vadduwm 10, 13, 18
	vadduwm 13, 7, 2
	xxlxor 39, 32, 40
	xxlxor 36, 45, 36
	vrlw 16, 7, 6
	xxlxor 39, 41, 51
	xxlxor 37, 42, 37
	vrlw 4, 4, 6
	vrlw 19, 7, 6
	vrlw 5, 5, 6
	vadduwm 6, 16, 15
	xxlxor 43, 38, 43
	vadduwm 7, 4, 17
	xxlxor 40, 38, 41
	vadduwm 6, 19, 12
	vadduwm 9, 5, 14
	xxlxor 34, 39, 34
	xxlxor 39, 39, 42
	xxlxor 35, 38, 35
	xxlxor 42, 41, 50
	vrlw 2, 2, 1
	vrlw 3, 3, 1
	vrlw 10, 10, 1
	vrlw 11, 11, 1
	xxlxor 38, 38, 32
	xxlxor 33, 41, 45
	xxlxor 45, 37, 34
	xxlxor 48, 48, 35
	xxlxor 46, 42, 36
	xxlxor 43, 43, 51
	bne	5, .LBB2_4
.LBB2_7:
	vmrglw 4, 8, 7
	addic 4, 29, 4
	lwz 6, 76(1)
	addi 25, 25, -4
	vmrglw 5, 6, 1
	addze 5, 28
	lwz 14, 72(1)
	cmplwi 5, 25, 3
	vmrghw 2, 8, 7
	addi 20, 20, 16
	addi 6, 6, 1
	vmrghw 3, 6, 1
	vmrglw 6, 13, 16
	vmrglw 7, 14, 11
	vmrghw 0, 13, 16
	vmrghw 1, 14, 11
	xxmrghd	2, 36, 37
	iselgt	29, 4, 29
	li 4, 64
	xxmrgld	3, 36, 37
	iselgt	28, 5, 28
	xxmrghd	0, 34, 35
	xxmrghd	6, 38, 39
	stxvd2x 2, 24, 4
	li 4, 80
	xxmrgld	1, 34, 35
	xxmrghd	4, 32, 33
	stxvd2x 0, 0, 24
	xxmrgld	5, 32, 33
	stxvd2x 6, 24, 4
	li 4, 96
	xxmrgld	7, 38, 39
	stxvd2x 3, 24, 4
	li 4, 112
	stxvd2x 4, 24, 18
	stxvd2x 1, 24, 17
	stxvd2x 5, 24, 16
	stxvd2x 7, 24, 4
	addi 24, 24, 128
	bgt	5, .LBB2_2
.LBB2_8:
	cmplwi 1, 25, 0
	beq	1, .LBB2_16
	lwz 5, 20(1)
	li 3, 0
	li 4, 1
	addi 23, 1, 272
	iselgt	19, 4, 3
	or 27, 5, 30
.LBB2_10:
	lwz 22, 0(20)
	mr	3, 23
	mr	4, 14
	li 5, 32
	bl memcpy
	mr	18, 26
	mr	3, 27
.LBB2_11:
	cmplwi	18, 1
	beq	0, .LBB2_13
	cmplwi	18, 0
	bne	0, .LBB2_14
	b .LBB2_15
.LBB2_13:
	or 3, 3, 21
.LBB2_14:
	clrlwi	9, 3, 24
	mr	3, 23
	mr	4, 22
	li 5, 64
	mr	7, 28
	mr	8, 29
	bl _blake3_compress_in_place_sse2
	addi 22, 22, 64
	addi 18, 18, -1
	mr	3, 30
	b .LBB2_11
.LBB2_15:
	mr	3, 24
	mr	4, 23
	li 5, 32
	bl memcpy
	addi 25, 25, -1
	addc 29, 29, 19
	addi 20, 20, 4
	addi 24, 24, 32
	cmplwi	25, 0
	addze 28, 28
	bne	0, .LBB2_10
.LBB2_16:
	li 3, 480
	lfd 31, 584(1)
	lfd 30, 576(1)
	lxvd2x 63, 1, 3
	li 3, 464
	lfd 29, 568(1)
	lxvd2x 62, 1, 3
	li 3, 448
	lwz 31, 564(1)
	lxvd2x 61, 1, 3
	li 3, 432
	lwz 30, 560(1)
	lxvd2x 60, 1, 3
	li 3, 416
	lwz 29, 556(1)
	lxvd2x 59, 1, 3
	li 3, 400
	lwz 28, 552(1)
	lxvd2x 58, 1, 3
	li 3, 384
	lwz 27, 548(1)
	lxvd2x 57, 1, 3
	li 3, 368
	lwz 26, 544(1)
	lxvd2x 56, 1, 3
	li 3, 352
	lwz 25, 540(1)
	lxvd2x 55, 1, 3
	li 3, 336
	lwz 24, 536(1)
	lxvd2x 54, 1, 3
	li 3, 320
	lwz 23, 532(1)
	lxvd2x 53, 1, 3
	li 3, 304
	lwz 22, 528(1)
	lxvd2x 52, 1, 3
	lwz 21, 524(1)
	lwz 20, 520(1)
	lwz 19, 516(1)
	lwz 18, 512(1)
	lwz 17, 508(1)
	lwz 16, 504(1)
	lwz 15, 500(1)
	lwz 14, 496(1)
	lwz 0, 596(1)
	addi 1, 1, 592
	mtlr 0
	blr
.Lfunc_end2:
	.size	_blake3_hash_many_sse2, .Lfunc_end2-.Lfunc_begin2

#endif
