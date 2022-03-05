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
 * Copyright (c) 2019-2022 Samuel Neves
 * Copyright (c) 2022 Tino Reichardt <milky-zfs@mcmilk.de>
 *
 * This is converted assembly: SSE4.1 -> POWER7 PPC64
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
	.byte	1
	.byte	2
	.byte	3
	.byte	0
	.byte	5
	.byte	6
	.byte	7
	.byte	4
	.byte	9
	.byte	10
	.byte	11
	.byte	8
	.byte	13
	.byte	14
	.byte	15
	.byte	12
.LCPI0_3:
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
.LCPI0_4:
	.byte	12
	.byte	13
	.byte	14
	.byte	15
	.byte	20
	.byte	21
	.byte	22
	.byte	23
	.byte	0
	.byte	1
	.byte	2
	.byte	3
	.byte	28
	.byte	29
	.byte	30
	.byte	31
.LCPI0_5:
	.byte	0
	.byte	1
	.byte	2
	.byte	3
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	28
	.byte	29
	.byte	30
	.byte	31
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.text
	.globl	_blake3_compress_in_place_sse41
	.p2align	2
	.type	_blake3_compress_in_place_sse41,@function
_blake3_compress_in_place_sse41:
.Lfunc_begin0:
	stwu 1, -80(1)
	li 6, 16
	li 10, 31
	lvsl 5, 0, 4
	lvsl 12, 0, 3
	lvx 2, 3, 6
	lvx 3, 0, 3
	vspltisw 15, -16
	lvx 4, 3, 10
	stw 9, 64(1)
	addi 10, 1, 64
	vspltisw 16, 9
	stw 5, 48(1)
	stw 7, 32(1)
	vperm 3, 3, 2, 12
	addi 5, 1, 48
	stw 8, 16(1)
	addi 7, 1, 32
	vperm 12, 2, 4, 12
	addi 8, 1, 16
	lxvw4x 33, 0, 5
	li 5, 32
	lxvw4x 32, 0, 10
	lxvw4x 38, 0, 7
	lxvw4x 39, 0, 8
	lis 7, .LCPI0_0@ha
	lvx 8, 4, 6
	lvx 9, 0, 4
	lvx 10, 4, 5
	vmrghw 2, 1, 0
	li 5, .LCPI0_0@l
	vperm 9, 9, 8, 5
	vperm 8, 8, 10, 5
	vmrghw 4, 7, 6
	vadduwm 3, 12, 3
	vspltisw 6, 10
	xxlxor 33, 33, 33
	vmrglw 11, 9, 8
	vmrghw 9, 9, 8
	xxmrghd	36, 36, 34
	lxvw4x 34, 7, 5
	li 5, .LCPI0_1@l
	lis 7, .LCPI0_1@ha
	lxvw4x 39, 7, 5
	li 5, 48
	li 7, 63
	vmrghw 8, 9, 11
	vmrglw 9, 9, 11
	lvx 11, 4, 5
	lis 5, .LCPI0_2@ha
	vperm 10, 10, 11, 5
	vadduwm 0, 3, 8
	vcmpgtsb 3, 1, 2
	xxlxor 36, 32, 36
	vadduwm 0, 0, 9
	vperm 4, 4, 4, 2
	xxlandc 45, 36, 35
	vadduwm 4, 6, 6
	vadduwm 6, 13, 7
	xxlxor 39, 38, 44
	lvx 12, 4, 7
	li 4, .LCPI0_2@l
	vrlw 7, 7, 4
	vperm 11, 11, 12, 5
	lxvw4x 37, 5, 4
	li 4, .LCPI0_3@l
	lis 5, .LCPI0_3@ha
	vadduwm 12, 0, 7
	vcmpgtsb 0, 1, 5
	xxlxor 33, 45, 44
	vmrglw 13, 10, 11
	vperm 1, 1, 1, 5
	vmrghw 14, 10, 11
	vmrglw 10, 11, 10
	xxlandc 49, 33, 32
	vmrghw 13, 14, 13
	vadduwm 6, 6, 17
	xxswapd	0, 49
	vsubuwm 1, 16, 15
	xxlxor 39, 38, 39
	xxsldwi 38, 38, 38, 1
	vmrglw 14, 10, 14
	vrlw 7, 7, 1
	vadduwm 12, 12, 13
	xxsldwi 45, 45, 45, 3
	xxsldwi 44, 44, 44, 3
	vadduwm 12, 7, 12
	xxlxor 47, 44, 0
	vperm 15, 15, 15, 2
	xxlandc 43, 47, 35
	vadduwm 15, 6, 11
	xxlxor 38, 47, 39
	vrlw 7, 6, 4
	vadduwm 6, 12, 14
	vadduwm 10, 6, 7
	xxlxor 38, 43, 42
	vperm 11, 6, 6, 5
	lxvw4x 38, 5, 4
	li 4, .LCPI0_4@l
	lis 5, .LCPI0_4@ha
	vperm 12, 8, 9, 6
	xxlandc 43, 43, 32
	vadduwm 15, 15, 11
	xxswapd	0, 43
	xxlxor 39, 47, 39
	xxsldwi 47, 47, 47, 3
	vrlw 16, 7, 1
	vadduwm 7, 10, 12
	xxsldwi 44, 44, 44, 1
	xxsldwi 39, 39, 39, 1
	vadduwm 11, 16, 7
	xxlxor 39, 43, 0
	xxsldwi 0, 46, 45, 3
	vperm 10, 7, 7, 2
	lxvw4x 39, 5, 4
	li 4, .LCPI0_5@l
	lis 5, .LCPI0_5@ha
	xxsldwi 49, 45, 0, 1
	xxlandc 50, 42, 35
	vperm 10, 8, 17, 7
	vadduwm 15, 15, 18
	xxlxor 40, 47, 48
	vrlw 16, 8, 4
	vadduwm 8, 11, 10
	vadduwm 11, 8, 16
	xxlxor 40, 50, 43
	xxmrghd	50, 46, 41
	xxsldwi 43, 43, 43, 3
	vmrglw 9, 9, 14
	vperm 17, 8, 8, 5
	lxvw4x 40, 5, 4
	vperm 18, 18, 13, 8
	xxlandc 49, 49, 32
	vadduwm 15, 15, 17
	xxswapd	0, 49
	vadduwm 11, 11, 18
	xxlxor 48, 47, 48
	xxsldwi 47, 47, 47, 1
	vmrghw 17, 13, 9
	vrlw 16, 16, 1
	vadduwm 11, 11, 16
	xxlxor 46, 43, 0
	xxsldwi 0, 49, 41, 1
	vperm 14, 14, 14, 2
	xxsldwi 45, 0, 45, 1
	vadduwm 11, 11, 13
	xxlandc 46, 46, 35
	vadduwm 15, 15, 14
	xxlxor 41, 47, 48
	vperm 16, 12, 10, 6
	vrlw 9, 9, 4
	vadduwm 11, 11, 9
	xxlxor 46, 46, 43
	vperm 14, 14, 14, 5
	xxlandc 46, 46, 32
	vadduwm 15, 15, 14
	xxswapd	0, 46
	xxlxor 41, 47, 41
	xxsldwi 46, 47, 47, 3
	vrlw 17, 9, 1
	vadduwm 9, 11, 16
	xxsldwi 41, 41, 41, 1
	vadduwm 11, 17, 9
	xxlxor 41, 43, 0
	xxsldwi 0, 45, 50, 3
	vperm 9, 9, 9, 2
	xxsldwi 47, 50, 0, 1
	xxlandc 51, 41, 35
	vperm 9, 12, 15, 7
	vadduwm 14, 14, 19
	xxlxor 44, 46, 49
	xxmrghd	49, 45, 42
	vmrglw 10, 10, 13
	vrlw 12, 12, 4
	vadduwm 11, 11, 9
	vperm 17, 17, 18, 8
	vadduwm 11, 11, 12
	xxlxor 47, 51, 43
	xxsldwi 43, 43, 43, 3
	vperm 15, 15, 15, 5
	vadduwm 11, 11, 17
	xxlandc 47, 47, 32
	vadduwm 14, 14, 15
	xxswapd	0, 47
	vmrghw 15, 18, 10
	xxlxor 44, 46, 44
	xxsldwi 46, 46, 46, 1
	vrlw 12, 12, 1
	vadduwm 11, 11, 12
	xxlxor 45, 43, 0
	xxsldwi 0, 47, 42, 1
	xxsldwi 47, 48, 48, 1
	vperm 13, 13, 13, 2
	vperm 16, 15, 9, 6
	xxlandc 45, 45, 35
	vadduwm 14, 14, 13
	xxlxor 42, 46, 44
	xxsldwi 44, 0, 50, 1
	vrlw 10, 10, 4
	vadduwm 11, 11, 12
	vadduwm 11, 11, 10
	xxlxor 45, 45, 43
	vperm 13, 13, 13, 5
	xxlandc 45, 45, 32
	vadduwm 14, 14, 13
	xxswapd	0, 45
	xxlxor 42, 46, 42
	xxsldwi 45, 46, 46, 3
	vrlw 18, 10, 1
	vadduwm 10, 11, 16
	xxsldwi 42, 42, 42, 1
	vadduwm 11, 18, 10
	xxlxor 42, 43, 0
	xxsldwi 0, 44, 49, 3
	vperm 10, 10, 10, 2
	xxsldwi 46, 49, 0, 1
	xxlandc 51, 42, 35
	vperm 10, 15, 14, 7
	vadduwm 13, 13, 19
	xxlxor 46, 45, 50
	xxmrghd	50, 44, 41
	vmrglw 9, 9, 12
	vrlw 14, 14, 4
	vadduwm 11, 11, 10
	vperm 18, 18, 17, 8
	vadduwm 11, 11, 14
	xxlxor 47, 51, 43
	xxsldwi 43, 43, 43, 3
	vperm 15, 15, 15, 5
	vadduwm 11, 11, 18
	xxlandc 47, 47, 32
	vadduwm 13, 13, 15
	xxswapd	0, 47
	vmrghw 15, 17, 9
	xxlxor 46, 45, 46
	xxsldwi 45, 45, 45, 1
	vrlw 14, 14, 1
	vadduwm 11, 11, 14
	xxlxor 44, 43, 0
	xxsldwi 0, 47, 41, 1
	xxsldwi 47, 48, 48, 1
	vperm 12, 12, 12, 2
	vperm 16, 15, 10, 6
	xxlandc 44, 44, 35
	vadduwm 13, 13, 12
	xxlxor 41, 45, 46
	xxsldwi 46, 0, 49, 1
	vrlw 9, 9, 4
	vadduwm 11, 11, 14
	vadduwm 11, 11, 9
	xxlxor 44, 44, 43
	vperm 12, 12, 12, 5
	xxlandc 44, 44, 32
	vadduwm 13, 13, 12
	xxswapd	0, 44
	xxlxor 41, 45, 41
	xxsldwi 44, 45, 45, 3
	vrlw 17, 9, 1
	vadduwm 9, 11, 16
	xxsldwi 41, 41, 41, 1
	vadduwm 11, 17, 9
	xxlxor 41, 43, 0
	xxsldwi 0, 46, 50, 3
	vperm 9, 9, 9, 2
	xxsldwi 45, 50, 0, 1
	xxlandc 51, 41, 35
	vperm 9, 15, 13, 7
	vadduwm 12, 12, 19
	xxlxor 45, 44, 49
	xxmrghd	49, 46, 42
	vmrglw 10, 10, 14
	vrlw 13, 13, 4
	vadduwm 11, 11, 9
	vperm 17, 17, 18, 8
	vadduwm 11, 11, 13
	xxlxor 47, 51, 43
	xxsldwi 43, 43, 43, 3
	vperm 15, 15, 15, 5
	vadduwm 11, 11, 17
	xxlandc 47, 47, 32
	vadduwm 12, 12, 15
	xxswapd	0, 47
	vmrghw 15, 18, 10
	xxlxor 45, 44, 45
	xxsldwi 44, 44, 44, 1
	vrlw 13, 13, 1
	vadduwm 11, 11, 13
	xxlxor 46, 43, 0
	xxsldwi 0, 47, 42, 1
	xxsldwi 47, 48, 48, 1
	vperm 14, 14, 14, 2
	vperm 16, 15, 9, 6
	xxlandc 46, 46, 35
	vadduwm 12, 12, 14
	xxlxor 42, 44, 45
	xxsldwi 45, 0, 50, 1
	vrlw 10, 10, 4
	vadduwm 11, 11, 13
	vadduwm 11, 11, 10
	xxlxor 46, 46, 43
	vperm 14, 14, 14, 5
	xxlandc 46, 46, 32
	vadduwm 12, 12, 14
	xxswapd	0, 46
	xxlxor 42, 44, 42
	xxsldwi 44, 44, 44, 3
	vrlw 18, 10, 1
	vadduwm 10, 11, 16
	xxsldwi 42, 42, 42, 1
	vadduwm 11, 18, 10
	xxlxor 42, 43, 0
	xxsldwi 0, 45, 49, 3
	vperm 10, 10, 10, 2
	xxsldwi 46, 49, 0, 1
	xxlandc 51, 42, 35
	vperm 10, 15, 14, 7
	vadduwm 12, 12, 19
	xxlxor 46, 44, 50
	xxmrghd	50, 45, 41
	vmrglw 9, 9, 13
	vrlw 14, 14, 4
	vadduwm 11, 11, 10
	vperm 18, 18, 17, 8
	vadduwm 11, 11, 14
	xxlxor 47, 51, 43
	xxsldwi 43, 43, 43, 3
	vperm 15, 15, 15, 5
	vadduwm 11, 11, 18
	xxlandc 47, 47, 32
	vadduwm 12, 12, 15
	xxswapd	0, 47
	vmrghw 15, 17, 9
	xxlxor 46, 44, 46
	xxsldwi 44, 44, 44, 1
	vrlw 14, 14, 1
	vadduwm 11, 11, 14
	xxlxor 45, 43, 0
	xxsldwi 0, 47, 41, 1
	xxsldwi 47, 48, 48, 1
	vperm 13, 13, 13, 2
	vperm 6, 15, 10, 6
	xxlandc 45, 45, 35
	vadduwm 12, 12, 13
	xxlxor 41, 44, 46
	xxsldwi 46, 0, 49, 1
	vrlw 9, 9, 4
	vadduwm 11, 11, 14
	vadduwm 11, 11, 9
	xxlxor 45, 45, 43
	vadduwm 6, 11, 6
	vperm 13, 13, 13, 5
	xxsldwi 38, 38, 38, 1
	xxlandc 45, 45, 32
	vadduwm 12, 12, 13
	xxswapd	0, 45
	xxlxor 41, 44, 41
	xxsldwi 44, 44, 44, 3
	vrlw 9, 9, 1
	vadduwm 6, 9, 6
	xxlxor 43, 38, 0
	xxsldwi 0, 46, 50, 3
	vperm 11, 11, 11, 2
	xxsldwi 45, 50, 0, 1
	vperm 7, 15, 13, 7
	xxlandc 43, 43, 35
	vadduwm 12, 12, 11
	xxlxor 41, 44, 41
	vadduwm 6, 6, 7
	vrlw 9, 9, 4
	vadduwm 6, 6, 9
	xxlxor 39, 43, 38
	xxmrghd	43, 46, 42
	xxsldwi 38, 38, 38, 3
	vperm 7, 7, 7, 5
	vperm 8, 11, 18, 8
	xxlandc 39, 39, 32
	vadduwm 6, 6, 8
	vadduwm 12, 12, 7
	xxswapd	0, 39
	vmrglw 8, 10, 14
	xxlxor 41, 44, 41
	xxsldwi 42, 44, 44, 1
	vrlw 9, 9, 1
	vadduwm 6, 6, 9
	xxlxor 39, 38, 0
	vperm 2, 7, 7, 2
	vmrghw 7, 18, 8
	xxlandc 34, 34, 35
	xxsldwi 0, 39, 40, 1
	vadduwm 3, 10, 2
	xxlxor 41, 35, 41
	xxsldwi 39, 0, 50, 1
	vrlw 4, 9, 4
	vadduwm 6, 6, 7
	vadduwm 6, 6, 4
	xxlxor 34, 34, 38
	xxsldwi 0, 38, 38, 1
	vperm 2, 2, 2, 5
	xxlandc 34, 34, 32
	vadduwm 3, 3, 2
	xxswapd	2, 34
	xxlxor 36, 35, 36
	xxsldwi 1, 35, 35, 3
	vrlw 4, 4, 1
	xxlxor 0, 1, 0
	stxvw4x 0, 0, 3
	xxlxor 1, 36, 2
	stxvw4x 1, 3, 6
	addi 1, 1, 80
	blr
.Lfunc_end0:
	.size	_blake3_compress_in_place_sse41, .Lfunc_end0-.Lfunc_begin0

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
	.byte	1
	.byte	2
	.byte	3
	.byte	0
	.byte	5
	.byte	6
	.byte	7
	.byte	4
	.byte	9
	.byte	10
	.byte	11
	.byte	8
	.byte	13
	.byte	14
	.byte	15
	.byte	12
.LCPI1_3:
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
.LCPI1_4:
	.byte	12
	.byte	13
	.byte	14
	.byte	15
	.byte	20
	.byte	21
	.byte	22
	.byte	23
	.byte	0
	.byte	1
	.byte	2
	.byte	3
	.byte	28
	.byte	29
	.byte	30
	.byte	31
.LCPI1_5:
	.byte	0
	.byte	1
	.byte	2
	.byte	3
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	28
	.byte	29
	.byte	30
	.byte	31
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.text
	.globl	_blake3_compress_xof_sse41
	.p2align	2
	.type	_blake3_compress_xof_sse41,@function
_blake3_compress_xof_sse41:
.Lfunc_begin1:
	stwu 1, -96(1)
	li 6, 80
	li 11, 31
	lvsl 0, 0, 4
	vspltisw 16, -16
	stxvd2x 63, 1, 6
	li 6, 16
	lvx 3, 3, 6
	lvx 4, 0, 3
	vspltisw 17, 9
	lvx 5, 3, 11
	stw 9, 64(1)
	addi 9, 1, 64
	stw 5, 48(1)
	stw 7, 32(1)
	addi 5, 1, 48
	stw 8, 16(1)
	addi 7, 1, 32
	addi 8, 1, 16
	lxvw4x 38, 0, 5
	li 5, 32
	lxvw4x 33, 0, 9
	lxvw4x 39, 0, 7
	lxvw4x 40, 0, 8
	li 7, .LCPI1_0@l
	lis 8, .LCPI1_0@ha
	lvx 2, 4, 6
	lvx 9, 0, 4
	lvx 11, 4, 5
	vperm 9, 9, 2, 0
	vperm 10, 2, 11, 0
	lvsl 2, 0, 3
	vperm 4, 4, 3, 2
	vperm 13, 3, 5, 2
	vmrghw 3, 6, 1
	vmrghw 5, 8, 7
	vmrglw 12, 9, 10
	vmrghw 10, 9, 10
	xxlxor 38, 38, 38
	vspltisw 7, 10
	vadduwm 4, 13, 4
	xxmrghd	37, 37, 35
	lxvw4x 35, 8, 7
	li 7, .LCPI1_1@l
	lis 8, .LCPI1_1@ha
	lxvw4x 40, 8, 7
	li 7, 48
	li 8, 63
	vmrghw 9, 10, 12
	vmrglw 10, 10, 12
	lvx 12, 4, 7
	vperm 11, 11, 12, 0
	vadduwm 1, 4, 9
	vcmpgtsb 4, 6, 3
	xxlxor 37, 33, 37
	vadduwm 1, 1, 10
	vperm 5, 5, 5, 3
	xxlandc 46, 37, 36
	vadduwm 5, 7, 7
	vadduwm 7, 14, 8
	xxlxor 40, 39, 45
	lvx 13, 4, 8
	li 4, .LCPI1_2@l
	lis 8, .LCPI1_2@ha
	vrlw 8, 8, 5
	vperm 12, 12, 13, 0
	lxvw4x 32, 8, 4
	li 4, .LCPI1_3@l
	lis 8, .LCPI1_3@ha
	vadduwm 13, 1, 8
	vcmpgtsb 1, 6, 0
	xxlxor 38, 46, 45
	vmrglw 14, 11, 12
	vperm 6, 6, 6, 0
	vmrghw 15, 11, 12
	vmrglw 11, 12, 11
	xxlandc 50, 38, 33
	vmrghw 14, 15, 14
	vadduwm 7, 7, 18
	xxswapd	0, 50
	vsubuwm 6, 17, 16
	xxlxor 40, 39, 40
	xxsldwi 39, 39, 39, 1
	vmrglw 15, 11, 15
	vrlw 8, 8, 6
	vadduwm 13, 13, 14
	xxsldwi 46, 46, 46, 3
	xxsldwi 45, 45, 45, 3
	vadduwm 13, 8, 13
	xxlxor 48, 45, 0
	vperm 16, 16, 16, 3
	xxlandc 44, 48, 36
	vadduwm 16, 7, 12
	xxlxor 39, 48, 40
	vrlw 8, 7, 5
	vadduwm 7, 13, 15
	vadduwm 11, 7, 8
	xxlxor 39, 44, 43
	vperm 12, 7, 7, 0
	lxvw4x 39, 8, 4
	li 4, .LCPI1_4@l
	lis 8, .LCPI1_4@ha
	vperm 13, 9, 10, 7
	xxlandc 44, 44, 33
	vadduwm 16, 16, 12
	xxswapd	0, 44
	xxlxor 40, 48, 40
	xxsldwi 48, 48, 48, 3
	vrlw 17, 8, 6
	vadduwm 8, 11, 13
	xxsldwi 45, 45, 45, 1
	xxsldwi 40, 40, 40, 1
	vadduwm 12, 17, 8
	xxlxor 40, 44, 0
	xxsldwi 0, 47, 46, 3
	vperm 11, 8, 8, 3
	lxvw4x 40, 8, 4
	li 4, .LCPI1_5@l
	lis 8, .LCPI1_5@ha
	xxsldwi 50, 46, 0, 1
	xxlandc 51, 43, 36
	vperm 11, 9, 18, 8
	vadduwm 16, 16, 19
	xxlxor 41, 48, 49
	vrlw 17, 9, 5
	vadduwm 9, 12, 11
	vadduwm 12, 9, 17
	xxlxor 41, 51, 44
	xxmrghd	51, 47, 42
	xxsldwi 44, 44, 44, 3
	vmrglw 10, 10, 15
	vperm 18, 9, 9, 0
	lxvw4x 41, 8, 4
	vperm 19, 19, 14, 9
	xxlandc 50, 50, 33
	vadduwm 16, 16, 18
	xxswapd	0, 50
	vadduwm 12, 12, 19
	xxlxor 49, 48, 49
	xxsldwi 48, 48, 48, 1
	vmrghw 18, 14, 10
	vrlw 17, 17, 6
	vadduwm 12, 12, 17
	xxlxor 47, 44, 0
	xxsldwi 0, 50, 42, 1
	vperm 15, 15, 15, 3
	xxsldwi 46, 0, 46, 1
	vadduwm 12, 12, 14
	xxlandc 47, 47, 36
	vadduwm 16, 16, 15
	xxlxor 42, 48, 49
	vperm 17, 13, 11, 7
	vrlw 10, 10, 5
	vadduwm 12, 12, 10
	xxlxor 47, 47, 44
	vperm 15, 15, 15, 0
	xxlandc 47, 47, 33
	vadduwm 16, 16, 15
	xxswapd	0, 47
	xxlxor 42, 48, 42
	xxsldwi 47, 48, 48, 3
	vrlw 18, 10, 6
	vadduwm 10, 12, 17
	xxsldwi 42, 42, 42, 1
	vadduwm 12, 18, 10
	xxlxor 42, 44, 0
	xxsldwi 0, 46, 51, 3
	vperm 10, 10, 10, 3
	xxsldwi 48, 51, 0, 1
	xxlandc 63, 42, 36
	vperm 10, 13, 16, 8
	vadduwm 15, 15, 31
	xxlxor 45, 47, 50
	xxmrghd	50, 46, 43
	vmrglw 11, 11, 14
	vrlw 13, 13, 5
	vadduwm 12, 12, 10
	vperm 18, 18, 19, 9
	vadduwm 12, 12, 13
	xxlxor 48, 63, 44
	xxsldwi 44, 44, 44, 3
	vperm 16, 16, 16, 0
	vadduwm 12, 12, 18
	xxlandc 48, 48, 33
	vadduwm 15, 15, 16
	xxswapd	0, 48
	vmrghw 16, 19, 11
	xxlxor 45, 47, 45
	xxsldwi 47, 47, 47, 1
	vrlw 13, 13, 6
	vadduwm 12, 12, 13
	xxlxor 46, 44, 0
	xxsldwi 0, 48, 43, 1
	xxsldwi 48, 49, 49, 1
	vperm 14, 14, 14, 3
	vperm 17, 16, 10, 7
	xxlandc 46, 46, 36
	vadduwm 15, 15, 14
	xxlxor 43, 47, 45
	xxsldwi 45, 0, 51, 1
	vrlw 11, 11, 5
	vadduwm 12, 12, 13
	vadduwm 12, 12, 11
	xxlxor 46, 46, 44
	vperm 14, 14, 14, 0
	xxlandc 46, 46, 33
	vadduwm 15, 15, 14
	xxswapd	0, 46
	xxlxor 43, 47, 43
	xxsldwi 46, 47, 47, 3
	vrlw 19, 11, 6
	vadduwm 11, 12, 17
	xxsldwi 43, 43, 43, 1
	vadduwm 12, 19, 11
	xxlxor 43, 44, 0
	xxsldwi 0, 45, 50, 3
	vperm 11, 11, 11, 3
	xxsldwi 47, 50, 0, 1
	xxlandc 63, 43, 36
	vperm 11, 16, 15, 8
	vadduwm 14, 14, 31
	xxlxor 47, 46, 51
	xxmrghd	51, 45, 42
	vmrglw 10, 10, 13
	vrlw 15, 15, 5
	vadduwm 12, 12, 11
	vperm 19, 19, 18, 9
	vadduwm 12, 12, 15
	xxlxor 48, 63, 44
	xxsldwi 44, 44, 44, 3
	vperm 16, 16, 16, 0
	vadduwm 12, 12, 19
	xxlandc 48, 48, 33
	vadduwm 14, 14, 16
	xxswapd	0, 48
	vmrghw 16, 18, 10
	xxlxor 47, 46, 47
	xxsldwi 46, 46, 46, 1
	vrlw 15, 15, 6
	vadduwm 12, 12, 15
	xxlxor 45, 44, 0
	xxsldwi 0, 48, 42, 1
	xxsldwi 48, 49, 49, 1
	vperm 13, 13, 13, 3
	vperm 17, 16, 11, 7
	xxlandc 45, 45, 36
	vadduwm 14, 14, 13
	xxlxor 42, 46, 47
	xxsldwi 47, 0, 50, 1
	vrlw 10, 10, 5
	vadduwm 12, 12, 15
	vadduwm 12, 12, 10
	xxlxor 45, 45, 44
	vperm 13, 13, 13, 0
	xxlandc 45, 45, 33
	vadduwm 14, 14, 13
	xxswapd	0, 45
	xxlxor 42, 46, 42
	xxsldwi 45, 46, 46, 3
	vrlw 18, 10, 6
	vadduwm 10, 12, 17
	xxsldwi 42, 42, 42, 1
	vadduwm 12, 18, 10
	xxlxor 42, 44, 0
	xxsldwi 0, 47, 51, 3
	vperm 10, 10, 10, 3
	xxsldwi 46, 51, 0, 1
	xxlandc 63, 42, 36
	vperm 10, 16, 14, 8
	vadduwm 13, 13, 31
	xxlxor 46, 45, 50
	xxmrghd	50, 47, 43
	vmrglw 11, 11, 15
	vrlw 14, 14, 5
	vadduwm 12, 12, 10
	vperm 18, 18, 19, 9
	vadduwm 12, 12, 14
	xxlxor 48, 63, 44
	xxsldwi 44, 44, 44, 3
	vperm 16, 16, 16, 0
	vadduwm 12, 12, 18
	xxlandc 48, 48, 33
	vadduwm 13, 13, 16
	xxswapd	0, 48
	vmrghw 16, 19, 11
	xxlxor 46, 45, 46
	xxsldwi 45, 45, 45, 1
	vrlw 14, 14, 6
	vadduwm 12, 12, 14
	xxlxor 47, 44, 0
	xxsldwi 0, 48, 43, 1
	xxsldwi 48, 49, 49, 1
	vperm 15, 15, 15, 3
	vperm 17, 16, 10, 7
	xxlandc 47, 47, 36
	vadduwm 13, 13, 15
	xxlxor 43, 45, 46
	xxsldwi 46, 0, 51, 1
	vrlw 11, 11, 5
	vadduwm 12, 12, 14
	vadduwm 12, 12, 11
	xxlxor 47, 47, 44
	vperm 15, 15, 15, 0
	xxlandc 47, 47, 33
	vadduwm 13, 13, 15
	xxswapd	0, 47
	xxlxor 43, 45, 43
	xxsldwi 45, 45, 45, 3
	vrlw 19, 11, 6
	vadduwm 11, 12, 17
	xxsldwi 43, 43, 43, 1
	vadduwm 12, 19, 11
	xxlxor 43, 44, 0
	xxsldwi 0, 46, 50, 3
	vperm 11, 11, 11, 3
	xxsldwi 47, 50, 0, 1
	xxlandc 63, 43, 36
	vperm 11, 16, 15, 8
	vadduwm 13, 13, 31
	xxlxor 47, 45, 51
	xxmrghd	51, 46, 42
	vmrglw 10, 10, 14
	vrlw 15, 15, 5
	vadduwm 12, 12, 11
	vperm 19, 19, 18, 9
	vadduwm 12, 12, 15
	xxlxor 48, 63, 44
	xxsldwi 44, 44, 44, 3
	vperm 16, 16, 16, 0
	vadduwm 12, 12, 19
	xxlandc 48, 48, 33
	vadduwm 13, 13, 16
	xxswapd	0, 48
	vmrghw 16, 18, 10
	xxlxor 47, 45, 47
	xxsldwi 45, 45, 45, 1
	vrlw 15, 15, 6
	vadduwm 12, 12, 15
	xxlxor 46, 44, 0
	xxsldwi 0, 48, 42, 1
	xxsldwi 48, 49, 49, 1
	vperm 14, 14, 14, 3
	vperm 7, 16, 11, 7
	xxlandc 46, 46, 36
	vadduwm 13, 13, 14
	xxlxor 42, 45, 47
	xxsldwi 47, 0, 50, 1
	vrlw 10, 10, 5
	vadduwm 12, 12, 15
	vadduwm 12, 12, 10
	xxlxor 46, 46, 44
	vadduwm 7, 12, 7
	vperm 14, 14, 14, 0
	xxsldwi 39, 39, 39, 1
	xxlandc 46, 46, 33
	vadduwm 13, 13, 14
	xxswapd	0, 46
	xxlxor 42, 45, 42
	xxsldwi 45, 45, 45, 3
	vrlw 10, 10, 6
	vadduwm 7, 10, 7
	xxlxor 44, 39, 0
	xxsldwi 0, 47, 51, 3
	vperm 12, 12, 12, 3
	xxsldwi 46, 51, 0, 1
	vperm 8, 16, 14, 8
	xxlandc 44, 44, 36
	vadduwm 13, 13, 12
	xxlxor 42, 45, 42
	vadduwm 7, 7, 8
	vrlw 10, 10, 5
	vadduwm 7, 7, 10
	xxlxor 40, 44, 39
	xxmrghd	44, 47, 43
	xxsldwi 39, 39, 39, 3
	vperm 8, 8, 8, 0
	vperm 9, 12, 19, 9
	xxlandc 40, 40, 33
	vadduwm 7, 7, 9
	vadduwm 13, 13, 8
	xxswapd	0, 40
	vmrglw 9, 11, 15
	xxlxor 42, 45, 42
	xxsldwi 43, 45, 45, 1
	vrlw 10, 10, 6
	vadduwm 7, 7, 10
	xxlxor 40, 39, 0
	vperm 3, 8, 8, 3
	vmrghw 8, 19, 9
	xxlandc 35, 35, 36
	xxsldwi 0, 40, 41, 1
	vadduwm 4, 11, 3
	xxlxor 42, 36, 42
	xxsldwi 40, 0, 51, 1
	vrlw 5, 10, 5
	vadduwm 7, 7, 8
	vadduwm 7, 7, 5
	xxlxor 35, 35, 39
	xxsldwi 0, 39, 39, 1
	vperm 3, 3, 3, 0
	xxlandc 35, 35, 33
	vadduwm 4, 4, 3
	xxswapd	2, 35
	xxlxor 37, 36, 37
	xxsldwi 1, 36, 36, 3
	vrlw 5, 5, 6
	xxlxor 0, 1, 0
	stxvw4x 0, 0, 10
	xxlxor 3, 37, 2
	stxvw4x 3, 10, 6
	lvx 3, 3, 6
	lvx 4, 0, 3
	vperm 3, 4, 3, 2
	xxlxor 0, 1, 35
	stxvw4x 0, 10, 5
	lvx 3, 3, 11
	lvx 4, 3, 6
	li 3, 80
	lxvd2x 63, 1, 3
	vperm 2, 4, 3, 2
	xxlxor 0, 2, 34
	stxvw4x 0, 10, 7
	addi 1, 1, 96
	blr
.Lfunc_end1:
	.size	_blake3_compress_xof_sse41, .Lfunc_end1-.Lfunc_begin1

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
	.byte	1
	.byte	2
	.byte	3
	.byte	0
	.byte	5
	.byte	6
	.byte	7
	.byte	4
	.byte	9
	.byte	10
	.byte	11
	.byte	8
	.byte	13
	.byte	14
	.byte	15
	.byte	12
.LCPI2_3:
	.long	1779033703
	.long	1779033703
	.long	1779033703
	.long	1779033703
.LCPI2_4:
	.long	3144134277
	.long	3144134277
	.long	3144134277
	.long	3144134277
.LCPI2_5:
	.long	1013904242
	.long	1013904242
	.long	1013904242
	.long	1013904242
.LCPI2_6:
	.long	2773480762
	.long	2773480762
	.long	2773480762
	.long	2773480762
	.text
	.globl	_blake3_hash_many_sse41
	.p2align	2
	.type	_blake3_hash_many_sse41,@function
_blake3_hash_many_sse41:
.Lfunc_begin2:
	mflr 0
	stw 0, 4(1)
	stwu 1, -640(1)
	li 11, 304
	stw 21, 524(1)
	lwz 21, 652(1)
	stxvd2x 52, 1, 11
	li 11, 320
	stw 24, 536(1)
	stxvd2x 53, 1, 11
	li 11, 336
	stw 29, 556(1)
	stxvd2x 54, 1, 11
	li 11, 352
	mr	29, 8
	lwz 24, 656(1)
	stxvd2x 55, 1, 11
	li 11, 368
	lwz 8, 648(1)
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
	stw 26, 544(1)
	stxvd2x 60, 1, 11
	li 11, 448
	stw 28, 552(1)
	stxvd2x 61, 1, 11
	li 11, 464
	stw 30, 560(1)
	stxvd2x 62, 1, 11
	li 11, 480
	mr	30, 10
	mr	28, 7
	mr	14, 6
	mr	26, 5
	mr	25, 4
	mr	20, 3
	andi. 4, 9, 1
	stw 15, 500(1)
	stfd 23, 568(1)
	stw 16, 504(1)
	stw 17, 508(1)
	stw 18, 512(1)
	stw 19, 516(1)
	stw 22, 528(1)
	stw 23, 532(1)
	stw 27, 548(1)
	stw 31, 564(1)
	stfd 24, 576(1)
	stfd 25, 584(1)
	stfd 26, 592(1)
	stfd 27, 600(1)
	stfd 28, 608(1)
	stfd 29, 616(1)
	stfd 30, 624(1)
	stfd 31, 632(1)
	stxvd2x 63, 1, 11
	stw 8, 20(1)
	blt	1, .LBB2_8
	li 3, -1
	li 9, 0
	li 4, .LCPI2_1@l
	lis 5, .LCPI2_1@ha
	iselgt	3, 3, 9
	lxvw4x 34, 5, 4
	addi 4, 1, 256
	li 6, .LCPI2_2@l
	stw 3, 256(1)
	lis 7, .LCPI2_2@ha
	li 3, .LCPI2_0@l
	vspltisb 5, -1
	lxvw4x 0, 0, 4
	lis 4, .LCPI2_0@ha
	lxvw4x 35, 7, 6
	xxlxor 36, 36, 36
	lxvw4x 1, 4, 3
	addi 3, 1, 224
	xxlor 8, 34, 34
	cmpwi 1, 26, 0
	stw 3, 68(1)
	addi 3, 1, 96
	vcmpgtsb 0, 4, 2
	or 5, 8, 30
	stw 3, 64(1)
	addi 3, 1, 112
	vcmpgtsb 4, 4, 3
	li 18, 16
	vslw 2, 5, 5
	stw 3, 60(1)
	addi 3, 1, 128
	li 17, 32
	xxspltw 0, 0, 0
	stw 3, 56(1)
	addi 3, 1, 144
	xxlor 9, 35, 35
	stw 3, 52(1)
	addi 3, 1, 160
	li 16, 48
	stw 3, 48(1)
	addi 3, 1, 176
	li 15, 63
	stw 3, 44(1)
	addi 3, 1, 192
	xxland 0, 0, 1
	lis 6, .LCPI2_4@ha
	stw 3, 40(1)
	addi 3, 1, 208
	xxlnor 12, 32, 32
	li 7, .LCPI2_5@l
	stw 3, 36(1)
	addi 3, 1, 240
	xxlnor 13, 36, 36
	li 8, .LCPI2_6@l
	xxlor 10, 34, 34
	stw 3, 24(1)
	lis 3, .LCPI2_5@ha
	lis 9, .LCPI2_6@ha
	xxlor 11, 0, 0
	li 10, 0
	stw 5, 28(1)
	xxlor 31, 0, 34
	stw 20, 32(1)
	stw 14, 72(1)
.LBB2_2:
	lwz 5, 0(14)
	lwz 4, 68(1)
	stw 5, 224(1)
	lwz 5, 4(14)
	lxvw4x 0, 0, 4
	lwz 4, 64(1)
	stw 5, 96(1)
	lwz 5, 8(14)
	lxvw4x 1, 0, 4
	xxspltw 34, 0, 0
	lwz 4, 60(1)
	stw 5, 112(1)
	lwz 5, 12(14)
	lxvw4x 2, 0, 4
	xxspltw 43, 1, 0
	lwz 4, 56(1)
	stw 5, 128(1)
	lwz 5, 16(14)
	lxvw4x 3, 0, 4
	xxspltw 32, 2, 0
	lwz 4, 52(1)
	stw 5, 144(1)
	lwz 5, 20(14)
	lxvw4x 4, 0, 4
	xxspltw 33, 3, 0
	lwz 4, 48(1)
	stw 5, 160(1)
	lwz 5, 24(14)
	lxvw4x 0, 0, 4
	xxspltw 55, 4, 0
	lwz 4, 44(1)
	stw 5, 176(1)
	lwz 5, 28(14)
	lxvw4x 1, 0, 4
	xxspltw 47, 0, 0
	lwz 4, 40(1)
	stw 5, 192(1)
	lxvw4x 2, 0, 4
	lwz 4, 36(1)
	xxspltw 45, 1, 0
	stw 29, 208(1)
	lxvw4x 0, 0, 4
	stw 28, 240(1)
	xxspltw 48, 2, 0
	stw 10, 76(1)
	bc 12, 6, .LBB2_7
	xxspltw 36, 0, 0
	xxlor 35, 11, 11
	lwz 4, 24(1)
	slwi 5, 10, 4
	xxlor 0, 10, 10
	lwz 11, 0(20)
	lwz 12, 4(20)
	li 10, 0
	lxvw4x 0, 0, 4
	lwz 4, 32(1)
	vadduwm 3, 4, 3
	lwz 23, 8(20)
	lwz 22, 12(20)
	add 5, 5, 4
	lwz 27, 28(1)
	xxlor 2, 35, 35
	xxspltw 37, 0, 0
	addi 0, 5, -4
	xxlxor 36, 35, 10
	xxlor 35, 31, 31
	vcmpgtsw 4, 3, 4
	vsubuwm 3, 5, 4
	xxlor 3, 35, 35
.LBB2_4:
	slwi 5, 10, 6
	addi 10, 10, 1
	add 14, 11, 5
	add 31, 12, 5
	add 4, 23, 5
	add 19, 22, 5
	lvx 4, 11, 5
	lvsl 14, 12, 5
	cmplw 5, 10, 26
	lvsl 19, 23, 5
	lvx 6, 14, 18
	lvx 5, 12, 5
	lvx 18, 31, 18
	lvx 29, 23, 5
	lvx 27, 4, 18
	lvx 28, 22, 5
	lvx 26, 19, 18
	vperm 12, 5, 18, 14
	lvx 25, 14, 17
	lvx 24, 31, 17
	vperm 5, 29, 27, 19
	lvx 22, 4, 17
	lvsl 8, 11, 5
	lvsl 30, 22, 5
	lvx 20, 19, 17
	vperm 29, 18, 24, 14
	lvx 7, 14, 16
	lvx 18, 31, 16
	vperm 3, 27, 22, 19
	lvx 9, 4, 16
	lvx 27, 19, 16
	vperm 4, 4, 6, 8
	lvx 10, 14, 15
	vperm 28, 28, 26, 30
	mr	14, 0
	vperm 6, 6, 25, 8
	vperm 21, 26, 20, 30
	vperm 26, 25, 7, 8
	vperm 8, 7, 10, 8
	lvx 7, 31, 15
	lvx 10, 4, 15
	li 4, 0
	vperm 25, 24, 18, 14
	vperm 18, 18, 7, 14
	lvx 7, 19, 15
	vperm 24, 22, 9, 19
	vperm 20, 20, 27, 30
	vperm 19, 9, 10, 19
	vperm 22, 27, 7, 30
	isel 4, 21, 4, 22
	or 4, 4, 27
	clrlwi	27, 4, 24
	li 4, 4
	mtctr 4
.LBB2_5:
	lwzu 4, 4(14)
	add 4, 4, 5
	addi 4, 4, 256
	dcbt 0, 4
	bdnz .LBB2_5
	vmrghw 30, 5, 28
	stw 27, 80(1)
	addi 4, 1, 80
	lis 5, .LCPI2_3@ha
	vmrglw 5, 5, 28
	lxvw4x 0, 0, 4
	li 4, .LCPI2_3@l
	mr	27, 30
	vmrghw 31, 6, 29
	vmrglw 27, 6, 29
	vmrghw 28, 3, 21
	vmrglw 29, 3, 21
	vmrghw 3, 26, 25
	vmrghw 14, 4, 12
	vmrglw 4, 4, 12
	vspltisw 7, 4
	vadduwm 11, 15, 11
	xxlor 7, 47, 47
	vspltisw 9, 10
	vadduwm 15, 1, 16
	xxspltw 0, 0, 0
	xxlor 29, 35, 35
	vmrghw 3, 8, 18
	xxmrghd	33, 46, 62
	vadduwm 12, 0, 13
	vslw 17, 7, 7
	xxmrghd	32, 59, 61
	xxlor 30, 48, 48
	vspltisw 16, 9
	vmrghw 21, 24, 20
	vmrglw 20, 24, 20
	xxlor 24, 35, 35
	xxmrgld	62, 46, 62
	vmrglw 3, 8, 18
	vadduwm 8, 23, 2
	vspltisw 18, -16
	xxmrghd	34, 63, 60
	vadduwm 15, 15, 0
	vadduwm 8, 8, 1
	vmrghw 24, 19, 22
	vmrglw 19, 19, 22
	xxlor 23, 35, 35
	xxmrghd	35, 36, 37
	vadduwm 10, 9, 9
	vsubuwm 22, 16, 18
	xxmrgld	50, 59, 61
	vadduwm 11, 11, 3
	vadduwm 12, 12, 2
	xxlxor 48, 40, 2
	xxlor 41, 8, 8
	xxlxor 46, 47, 0
	xxlor 5, 35, 35
	xxmrgld	35, 36, 37
	xxlor 4, 34, 34
	xxlxor 34, 43, 3
	xxlxor 37, 44, 49
	vperm 16, 16, 16, 9
	vperm 14, 14, 14, 9
	vperm 2, 2, 2, 9
	vperm 5, 5, 5, 9
	xxlor 1, 2, 2
	xxlor 1, 3, 3
	vadduwm 11, 11, 3
	xxlor 6, 35, 35
	lxvw4x 35, 9, 8
	xxland 49, 48, 12
	lxvw4x 48, 5, 4
	li 4, .LCPI2_4@l
	vmr	7, 31
	lxvw4x 63, 3, 7
	xxlor 1, 45, 45
	lxvw4x 45, 6, 4
	xxland 46, 46, 12
	xxland 34, 34, 12
	xxland 37, 37, 12
	vadduwm 16, 17, 16
	vadduwm 6, 14, 3
	xxmrgld	36, 39, 60
	vadduwm 13, 2, 13
	xxmrghd	39, 29, 53
	vadduwm 31, 5, 31
	xxlor 28, 32, 32
	xxlxor 32, 48, 55
	xxlxor 59, 38, 30
	xxlor 25, 33, 33
	xxlxor 33, 45, 7
	xxlxor 55, 63, 1
	vrlw 0, 0, 10
	vrlw 27, 27, 10
	vrlw 1, 1, 10
	vrlw 23, 23, 10
	vadduwm 8, 8, 30
	vadduwm 15, 15, 18
	vadduwm 12, 12, 4
	vadduwm 8, 8, 0
	vadduwm 15, 15, 27
	vadduwm 11, 11, 1
	vadduwm 12, 12, 23
	vmrglw 25, 26, 25
	xxlor 26, 36, 36
	xxlxor 49, 40, 49
	xxlxor 36, 47, 46
	xxlor 58, 9, 9
	xxlxor 34, 43, 34
	xxlxor 35, 44, 37
	xxmrghd	37, 57, 52
	vperm 17, 17, 17, 26
	vperm 4, 4, 4, 26
	vperm 2, 2, 2, 26
	vperm 3, 3, 3, 26
	vadduwm 11, 11, 5
	xxlor 7, 37, 37
	xxland 49, 49, 13
	xxland 61, 36, 13
	xxland 34, 34, 13
	xxland 35, 35, 13
	vadduwm 16, 16, 17
	vadduwm 6, 6, 29
	vadduwm 13, 13, 2
	vadduwm 31, 31, 3
	xxlxor 32, 48, 32
	xxlxor 59, 38, 59
	xxlxor 36, 45, 33
	xxlxor 33, 63, 55
	vrlw 5, 27, 22
	vrlw 0, 0, 22
	vadduwm 8, 8, 7
	xxlor 27, 39, 39
	xxmrghd	39, 23, 51
	vrlw 23, 4, 22
	vrlw 4, 1, 22
	xxmrghd	33, 24, 56
	vadduwm 15, 15, 7
	vmr	14, 19
	vadduwm 15, 15, 0
	vadduwm 12, 12, 1
	xxlxor 35, 47, 35
	vadduwm 12, 12, 5
	vadduwm 8, 8, 23
	xxlxor 34, 44, 34
	vadduwm 11, 11, 4
	vperm 2, 2, 2, 9
	vperm 3, 3, 3, 9
	xxlxor 61, 40, 61
	xxlxor 49, 43, 49
	vperm 29, 29, 29, 9
	vperm 17, 17, 17, 9
	xxland 34, 34, 12
	xxland 35, 35, 12
	vadduwm 16, 16, 2
	vadduwm 13, 13, 3
	vmr	19, 1
	xxlor 30, 39, 39
	xxmrgld	33, 29, 53
	xxmrgld	39, 57, 52
	xxland 61, 61, 12
	xxland 52, 49, 12
	xxlxor 37, 48, 37
	xxlxor 32, 45, 32
	vadduwm 31, 31, 29
	vadduwm 6, 6, 20
	vrlw 5, 5, 10
	vrlw 0, 0, 10
	vadduwm 8, 8, 1
	xxlor 29, 33, 33
	xxmrgld	33, 24, 56
	vadduwm 11, 11, 7
	vmr	28, 7
	xxmrgld	39, 23, 46
	xxlxor 55, 63, 55
	xxlxor 36, 38, 36
	vrlw 24, 23, 10
	vrlw 4, 4, 10
	vadduwm 12, 12, 1
	vadduwm 15, 15, 7
	vadduwm 12, 12, 5
	vadduwm 15, 15, 0
	xxlxor 34, 44, 34
	xxlxor 35, 47, 35
	vadduwm 8, 8, 24
	vadduwm 11, 11, 4
	vperm 2, 2, 2, 26
	vperm 3, 3, 3, 26
	xxlxor 61, 40, 61
	xxlxor 55, 43, 52
	vperm 29, 29, 29, 26
	vperm 23, 23, 23, 26
	xxland 34, 34, 13
	xxland 35, 35, 13
	vadduwm 16, 16, 2
	vadduwm 13, 13, 3
	xxland 61, 61, 13
	xxland 55, 55, 13
	xxlxor 32, 45, 32
	xxlxor 37, 48, 37
	vadduwm 31, 31, 29
	vadduwm 6, 6, 23
	vrlw 0, 0, 22
	vrlw 5, 5, 22
	xxlor 57, 5, 5
	xxlxor 56, 63, 56
	xxlxor 36, 38, 36
	xxlor 52, 4, 4
	vadduwm 8, 8, 25
	vrlw 24, 24, 22
	vrlw 4, 4, 22
	vadduwm 15, 15, 20
	xxlor 46, 6, 6
	vadduwm 8, 8, 0
	vadduwm 15, 15, 5
	vadduwm 11, 11, 14
	vadduwm 12, 12, 18
	xxlxor 55, 40, 55
	xxlxor 61, 47, 61
	vadduwm 11, 11, 24
	vadduwm 12, 12, 4
	vperm 23, 23, 23, 9
	vperm 29, 29, 29, 9
	xxlxor 34, 43, 34
	xxlxor 35, 44, 35
	vperm 2, 2, 2, 9
	vperm 3, 3, 3, 9
	xxland 55, 55, 12
	xxland 61, 61, 12
	vadduwm 16, 16, 23
	vadduwm 6, 6, 29
	xxland 34, 34, 12
	xxland 35, 35, 12
	xxlxor 32, 48, 32
	xxlxor 37, 38, 37
	vadduwm 13, 13, 2
	vadduwm 31, 31, 3
	vrlw 0, 0, 10
	vrlw 5, 5, 10
	xxlor 53, 28, 28
	xxlxor 56, 45, 56
	xxlxor 36, 63, 36
	vadduwm 8, 8, 21
	vrlw 24, 24, 10
	vrlw 4, 4, 10
	vadduwm 15, 15, 1
	vmr	27, 7
	xxlor 39, 7, 7
	xxlor 49, 25, 25
	vadduwm 8, 8, 0
	vadduwm 15, 15, 5
	vadduwm 11, 11, 7
	vadduwm 12, 12, 17
	xxlxor 55, 40, 55
	xxlxor 61, 47, 61
	vadduwm 11, 11, 24
	vadduwm 12, 12, 4
	vperm 23, 23, 23, 26
	vperm 29, 29, 29, 26
	xxlxor 34, 43, 34
	xxlxor 35, 44, 35
	vperm 2, 2, 2, 26
	vperm 3, 3, 3, 26
	xxland 55, 55, 13
	xxland 61, 61, 13
	vadduwm 16, 16, 23
	vadduwm 6, 6, 29
	xxland 34, 34, 13
	xxland 35, 35, 13
	xxlxor 32, 48, 32
	xxlxor 37, 38, 37
	vadduwm 13, 13, 2
	vadduwm 31, 31, 3
	vrlw 5, 5, 22
	vrlw 0, 0, 22
	xxlxor 56, 45, 56
	xxlxor 36, 63, 36
	xxlor 49, 29, 29
	vrlw 24, 24, 22
	vrlw 4, 4, 22
	vadduwm 12, 12, 17
	vadduwm 15, 15, 27
	vadduwm 12, 12, 5
	vadduwm 15, 15, 0
	vadduwm 8, 8, 30
	vadduwm 11, 11, 19
	xxlxor 34, 44, 34
	xxlxor 35, 47, 35
	vadduwm 8, 8, 24
	vadduwm 11, 11, 4
	vperm 2, 2, 2, 9
	vperm 3, 3, 3, 9
	xxlxor 61, 40, 61
	xxlxor 55, 43, 55
	vperm 29, 29, 29, 9
	vperm 23, 23, 23, 9
	xxland 34, 34, 12
	xxland 35, 35, 12
	vadduwm 16, 16, 2
	vadduwm 13, 13, 3
	xxland 61, 61, 12
	xxland 55, 55, 12
	xxlxor 37, 48, 37
	xxlxor 32, 45, 32
	vadduwm 31, 31, 29
	vadduwm 6, 6, 23
	vrlw 5, 5, 10
	vrlw 0, 0, 10
	xxlor 5, 50, 50
	vmr	18, 1
	xxlor 7, 59, 59
	xxlxor 56, 63, 56
	xxlxor 36, 38, 36
	xxlor 59, 30, 30
	xxlor 33, 27, 27
	vrlw 24, 24, 10
	vrlw 4, 4, 10
	vadduwm 12, 12, 27
	vadduwm 15, 15, 1
	xxlor 24, 62, 62
	vadduwm 8, 8, 28
	vmr	30, 28
	xxlor 60, 26, 26
	vadduwm 12, 12, 5
	vadduwm 15, 15, 0
	vadduwm 11, 11, 28
	xxlxor 34, 44, 34
	xxlxor 35, 47, 35
	vadduwm 8, 8, 24
	vadduwm 11, 11, 4
	vperm 2, 2, 2, 26
	vperm 3, 3, 3, 26
	xxlxor 61, 40, 61
	xxlxor 55, 43, 55
	vperm 29, 29, 29, 26
	vperm 23, 23, 23, 26
	xxland 34, 34, 13
	xxland 35, 35, 13
	vadduwm 16, 16, 2
	vadduwm 13, 13, 3
	xxland 61, 61, 13
	xxland 55, 55, 13
	xxlxor 32, 45, 32
	xxlxor 37, 48, 37
	vadduwm 31, 31, 29
	vadduwm 6, 6, 23
	vrlw 0, 0, 22
	vrlw 5, 5, 22
	xxlxor 56, 63, 56
	xxlxor 36, 38, 36
	vadduwm 12, 12, 18
	xxlor 27, 50, 50
	xxlor 50, 5, 5
	vadduwm 8, 8, 14
	vrlw 24, 24, 22
	vrlw 4, 4, 22
	vadduwm 15, 15, 18
	vadduwm 8, 8, 0
	vadduwm 15, 15, 5
	vadduwm 11, 11, 7
	xxlxor 55, 40, 55
	xxlxor 61, 47, 61
	vadduwm 11, 11, 24
	vadduwm 12, 12, 4
	vperm 23, 23, 23, 9
	vperm 29, 29, 29, 9
	xxlxor 34, 43, 34
	xxlxor 35, 44, 35
	vperm 2, 2, 2, 9
	vperm 3, 3, 3, 9
	xxland 55, 55, 12
	xxland 61, 61, 12
	vadduwm 16, 16, 23
	vadduwm 6, 6, 29
	xxland 34, 34, 12
	xxland 35, 35, 12
	xxlxor 32, 48, 32
	xxlxor 37, 38, 37
	vadduwm 13, 13, 2
	vadduwm 31, 31, 3
	vrlw 0, 0, 10
	vrlw 5, 5, 10
	xxlxor 56, 45, 56
	xxlxor 36, 63, 36
	vadduwm 8, 8, 20
	vrlw 24, 24, 10
	vrlw 4, 4, 10
	vadduwm 15, 15, 27
	vadduwm 8, 8, 0
	vadduwm 15, 15, 5
	vadduwm 11, 11, 19
	vadduwm 12, 12, 25
	xxlxor 55, 40, 55
	xxlxor 61, 47, 61
	vadduwm 11, 11, 24
	vadduwm 12, 12, 4
	vperm 23, 23, 23, 26
	vperm 29, 29, 29, 26
	xxlxor 34, 43, 34
	xxlxor 35, 44, 35
	vperm 2, 2, 2, 26
	vperm 3, 3, 3, 26
	xxland 55, 55, 13
	xxland 61, 61, 13
	vadduwm 16, 16, 23
	vadduwm 6, 6, 29
	xxland 34, 34, 13
	xxland 35, 35, 13
	xxlxor 32, 48, 32
	xxlxor 37, 38, 37
	vadduwm 13, 13, 2
	vadduwm 31, 31, 3
	vrlw 5, 5, 22
	vrlw 0, 0, 22
	xxlxor 56, 45, 56
	xxlxor 36, 63, 36
	vrlw 24, 24, 22
	vrlw 4, 4, 22
	vadduwm 12, 12, 30
	vadduwm 15, 15, 1
	vadduwm 12, 12, 5
	vadduwm 15, 15, 0
	vadduwm 8, 8, 21
	vadduwm 11, 11, 17
	xxlxor 34, 44, 34
	xxlxor 35, 47, 35
	vadduwm 8, 8, 24
	vadduwm 11, 11, 4
	vperm 2, 2, 2, 9
	vperm 3, 3, 3, 9
	xxlxor 61, 40, 61
	xxlxor 55, 43, 55
	vperm 29, 29, 29, 9
	vperm 23, 23, 23, 9
	xxland 34, 34, 12
	xxland 35, 35, 12
	vadduwm 16, 16, 2
	vadduwm 13, 13, 3
	xxland 61, 61, 12
	xxland 55, 55, 12
	xxlxor 37, 48, 37
	xxlxor 32, 45, 32
	vadduwm 31, 31, 29
	vadduwm 6, 6, 23
	vrlw 5, 5, 10
	vrlw 0, 0, 10
	xxlor 4, 6, 6
	xxlor 5, 57, 57
	xxlor 6, 30, 30
	xxlor 30, 53, 53
	vmr	25, 30
	xxlxor 56, 63, 56
	xxlxor 36, 38, 36
	xxlor 53, 7, 7
	xxlor 62, 24, 24
	vrlw 24, 24, 10
	vrlw 4, 4, 10
	vadduwm 12, 12, 21
	vadduwm 15, 15, 30
	vmr	14, 19
	xxlor 51, 25, 25
	vadduwm 12, 12, 5
	vadduwm 15, 15, 0
	vadduwm 8, 8, 28
	vadduwm 11, 11, 19
	xxlxor 34, 44, 34
	xxlxor 35, 47, 35
	vadduwm 8, 8, 24
	vadduwm 11, 11, 4
	vperm 2, 2, 2, 26
	vperm 3, 3, 3, 26
	xxlxor 61, 40, 61
	xxlxor 55, 43, 55
	vperm 29, 29, 29, 26
	vperm 23, 23, 23, 26
	xxland 34, 34, 13
	xxland 35, 35, 13
	vadduwm 16, 16, 2
	vadduwm 13, 13, 3
	xxland 61, 61, 13
	xxland 55, 55, 13
	xxlxor 32, 45, 32
	xxlxor 37, 48, 37
	vadduwm 31, 31, 29
	vadduwm 6, 6, 23
	vrlw 0, 0, 22
	vrlw 5, 5, 22
	xxlor 28, 52, 52
	xxlor 52, 29, 29
	xxlor 29, 33, 33
	vadduwm 8, 8, 7
	vmr	1, 7
	xxlxor 56, 63, 56
	xxlxor 36, 38, 36
	xxlor 39, 27, 27
	vrlw 24, 24, 22
	vrlw 4, 4, 22
	vadduwm 15, 15, 7
	xxlor 49, 6, 6
	vadduwm 8, 8, 0
	vadduwm 15, 15, 5
	vadduwm 11, 11, 14
	vadduwm 12, 12, 17
	xxlxor 55, 40, 55
	xxlxor 61, 47, 61
	vadduwm 11, 11, 24
	vadduwm 12, 12, 4
	vperm 23, 23, 23, 9
	vperm 29, 29, 29, 9
	xxlxor 34, 43, 34
	xxlxor 35, 44, 35
	vperm 2, 2, 2, 9
	vperm 3, 3, 3, 9
	xxland 55, 55, 12
	xxland 61, 61, 12
	vadduwm 16, 16, 23
	vadduwm 6, 6, 29
	xxland 34, 34, 12
	xxland 35, 35, 12
	xxlxor 32, 48, 32
	xxlxor 37, 38, 37
	vadduwm 13, 13, 2
	vadduwm 31, 31, 3
	vrlw 0, 0, 10
	vrlw 5, 5, 10
	xxlxor 56, 45, 56
	xxlxor 36, 63, 36
	vadduwm 8, 8, 18
	vrlw 24, 24, 10
	vrlw 4, 4, 10
	vadduwm 15, 15, 21
	xxlor 39, 4, 4
	vadduwm 8, 8, 0
	vadduwm 15, 15, 5
	vadduwm 11, 11, 20
	vadduwm 12, 12, 7
	xxlxor 55, 40, 55
	xxlxor 61, 47, 61
	vadduwm 11, 11, 24
	vadduwm 12, 12, 4
	vperm 23, 23, 23, 26
	vperm 29, 29, 29, 26
	xxlxor 34, 43, 34
	xxlxor 35, 44, 35
	vperm 2, 2, 2, 26
	vperm 3, 3, 3, 26
	xxland 55, 55, 13
	xxland 61, 61, 13
	vadduwm 16, 16, 23
	vadduwm 6, 6, 29
	xxland 34, 34, 13
	xxland 35, 35, 13
	xxlxor 32, 48, 32
	xxlxor 37, 38, 37
	vadduwm 13, 13, 2
	vadduwm 31, 31, 3
	vrlw 5, 5, 22
	vrlw 0, 0, 22
	xxlxor 56, 45, 56
	xxlxor 36, 63, 36
	vrlw 24, 24, 22
	vrlw 4, 4, 22
	vadduwm 12, 12, 28
	vadduwm 15, 15, 30
	vmr	27, 14
	xxlor 46, 28, 28
	vadduwm 12, 12, 5
	vadduwm 15, 15, 0
	vadduwm 8, 8, 14
	vadduwm 11, 11, 25
	xxlxor 34, 44, 34
	xxlxor 35, 47, 35
	vadduwm 8, 8, 24
	vadduwm 11, 11, 4
	vperm 2, 2, 2, 9
	vperm 3, 3, 3, 9
	xxlxor 61, 40, 61
	xxlxor 55, 43, 55
	vperm 29, 29, 29, 9
	vperm 23, 23, 23, 9
	xxland 34, 34, 12
	xxland 35, 35, 12
	vadduwm 16, 16, 2
	vadduwm 13, 13, 3
	xxland 61, 61, 12
	xxland 55, 55, 12
	xxlxor 37, 48, 37
	xxlxor 32, 45, 32
	vadduwm 31, 31, 29
	vadduwm 6, 6, 23
	vrlw 5, 5, 10
	vrlw 0, 0, 10
	xxlor 6, 27, 27
	xxlor 27, 50, 50
	xxlxor 56, 63, 56
	xxlxor 36, 38, 36
	xxlor 62, 29, 29
	xxlor 50, 30, 30
	vrlw 24, 24, 10
	vrlw 4, 4, 10
	vadduwm 12, 12, 30
	vadduwm 15, 15, 18
	xxlor 46, 5, 5
	vadduwm 12, 12, 5
	vadduwm 15, 15, 0
	vadduwm 8, 8, 19
	vadduwm 11, 11, 14
	xxlxor 34, 44, 34
	xxlxor 35, 47, 35
	vadduwm 8, 8, 24
	vadduwm 11, 11, 4
	vperm 2, 2, 2, 26
	vperm 3, 3, 3, 26
	xxlxor 61, 40, 61
	xxlxor 55, 43, 55
	vperm 29, 29, 29, 26
	vperm 23, 23, 23, 26
	xxland 34, 34, 13
	xxland 35, 35, 13
	vadduwm 16, 16, 2
	vadduwm 13, 13, 3
	xxland 61, 61, 13
	xxland 55, 55, 13
	xxlxor 32, 45, 32
	xxlxor 37, 48, 37
	vadduwm 31, 31, 29
	vadduwm 6, 6, 23
	vrlw 0, 0, 22
	vrlw 5, 5, 22
	xxlxor 56, 63, 56
	xxlxor 36, 38, 36
	vadduwm 8, 8, 27
	vrlw 24, 24, 22
	vrlw 4, 4, 22
	vadduwm 15, 15, 17
	vadduwm 8, 8, 0
	vadduwm 15, 15, 5
	vadduwm 11, 11, 20
	vadduwm 12, 12, 21
	xxlxor 55, 40, 55
	xxlxor 61, 47, 61
	vadduwm 11, 11, 24
	vadduwm 12, 12, 4
	vperm 23, 23, 23, 9
	vperm 29, 29, 29, 9
	xxlxor 34, 43, 34
	xxlxor 35, 44, 35
	vperm 2, 2, 2, 9
	vperm 3, 3, 3, 9
	xxland 55, 55, 12
	xxland 61, 61, 12
	vadduwm 16, 16, 23
	vadduwm 6, 6, 29
	xxland 34, 34, 12
	xxland 35, 35, 12
	xxlxor 32, 48, 32
	xxlxor 37, 38, 37
	vadduwm 13, 13, 2
	vadduwm 31, 31, 3
	vrlw 0, 0, 10
	vrlw 5, 5, 10
	vmr	19, 20
	xxlor 52, 6, 6
	xxlxor 56, 45, 56
	xxlxor 36, 63, 36
	vadduwm 8, 8, 20
	vrlw 24, 24, 10
	vrlw 4, 4, 10
	vadduwm 15, 15, 30
	vadduwm 8, 8, 0
	vadduwm 15, 15, 5
	vadduwm 11, 11, 25
	vadduwm 12, 12, 1
	xxlxor 55, 40, 55
	xxlxor 61, 47, 61
	vadduwm 11, 11, 24
	vadduwm 12, 12, 4
	vperm 23, 23, 23, 26
	vperm 29, 29, 29, 26
	xxlxor 34, 43, 34
	xxlxor 35, 44, 35
	vperm 2, 2, 2, 26
	vperm 3, 3, 3, 26
	xxland 55, 55, 13
	xxland 61, 61, 13
	vadduwm 16, 16, 23
	vadduwm 6, 6, 29
	xxland 34, 34, 13
	xxland 35, 35, 13
	xxlxor 32, 48, 32
	xxlxor 37, 38, 37
	xxlor 4, 33, 33
	xxlor 33, 27, 27
	vadduwm 13, 13, 2
	vadduwm 31, 31, 3
	vrlw 5, 5, 22
	vrlw 0, 0, 22
	vadduwm 8, 8, 1
	xxlxor 56, 45, 56
	xxlxor 36, 63, 36
	xxlor 33, 25, 25
	vrlw 24, 24, 22
	vrlw 4, 4, 22
	vadduwm 12, 12, 1
	vadduwm 15, 15, 18
	vadduwm 12, 12, 5
	vadduwm 15, 15, 0
	vadduwm 11, 11, 28
	xxlxor 34, 44, 34
	xxlxor 35, 47, 35
	vadduwm 8, 8, 24
	vadduwm 11, 11, 4
	vperm 2, 2, 2, 9
	vperm 3, 3, 3, 9
	xxlxor 61, 40, 61
	xxlxor 55, 43, 55
	vperm 29, 29, 29, 9
	vperm 23, 23, 23, 9
	xxland 34, 34, 12
	xxland 35, 35, 12
	vadduwm 16, 16, 2
	vadduwm 13, 13, 3
	xxland 61, 61, 12
	xxland 55, 55, 12
	xxlxor 37, 48, 37
	xxlxor 32, 45, 32
	vadduwm 31, 31, 29
	vadduwm 6, 6, 23
	vrlw 5, 5, 10
	vrlw 0, 0, 10
	xxlor 5, 59, 59
	vadduwm 11, 11, 7
	xxlor 6, 39, 39
	xxlxor 56, 63, 56
	xxlxor 36, 38, 36
	xxlor 39, 24, 24
	xxlor 59, 28, 28
	vrlw 24, 24, 10
	vrlw 4, 4, 10
	vadduwm 12, 12, 7
	vadduwm 15, 15, 27
	vadduwm 12, 12, 5
	vadduwm 15, 15, 0
	vadduwm 8, 8, 14
	xxlxor 34, 44, 34
	xxlxor 35, 47, 35
	vadduwm 8, 8, 24
	vadduwm 11, 11, 4
	vperm 2, 2, 2, 26
	vperm 3, 3, 3, 26
	xxlxor 61, 40, 61
	xxlxor 55, 43, 55
	vperm 29, 29, 29, 26
	vperm 23, 23, 23, 26
	xxland 34, 34, 13
	xxland 35, 35, 13
	vadduwm 16, 16, 2
	vadduwm 13, 13, 3
	xxland 61, 61, 13
	xxland 55, 55, 13
	xxlxor 32, 45, 32
	xxlxor 37, 48, 37
	vadduwm 31, 31, 29
	vadduwm 6, 6, 23
	vrlw 0, 0, 22
	vrlw 5, 5, 22
	xxlxor 56, 63, 56
	xxlxor 36, 38, 36
	vadduwm 8, 8, 19
	vrlw 24, 24, 22
	vrlw 4, 4, 22
	vadduwm 15, 15, 21
	vadduwm 8, 8, 0
	vadduwm 15, 15, 5
	vadduwm 11, 11, 25
	vadduwm 12, 12, 30
	xxlxor 55, 40, 55
	xxlxor 61, 47, 61
	vadduwm 11, 11, 24
	vadduwm 12, 12, 4
	vperm 23, 23, 23, 9
	vperm 29, 29, 29, 9
	xxlxor 34, 43, 34
	xxlxor 35, 44, 35
	vperm 2, 2, 2, 9
	vperm 3, 3, 3, 9
	xxland 55, 55, 12
	xxland 61, 61, 12
	vadduwm 16, 16, 23
	vadduwm 6, 6, 29
	xxland 34, 34, 12
	xxland 35, 35, 12
	xxlxor 32, 48, 32
	xxlxor 37, 38, 37
	xxlor 30, 49, 49
	vadduwm 13, 13, 2
	vadduwm 31, 31, 3
	vrlw 0, 0, 10
	vrlw 5, 5, 10
	vmr	17, 14
	xxlor 46, 30, 30
	xxlxor 56, 45, 56
	xxlxor 36, 63, 36
	vadduwm 8, 8, 14
	vrlw 24, 24, 10
	vrlw 4, 4, 10
	vadduwm 15, 15, 7
	xxlor 46, 5, 5
	vadduwm 8, 8, 0
	vadduwm 15, 15, 5
	vadduwm 11, 11, 28
	vadduwm 12, 12, 14
	xxlxor 55, 40, 55
	xxlxor 61, 47, 61
	vadduwm 11, 11, 24
	vadduwm 12, 12, 4
	vperm 23, 23, 23, 26
	vperm 29, 29, 29, 26
	xxlxor 34, 43, 34
	xxlxor 35, 44, 35
	vperm 2, 2, 2, 26
	vperm 3, 3, 3, 26
	xxland 55, 55, 13
	xxland 61, 61, 13
	vadduwm 16, 16, 23
	vadduwm 6, 6, 29
	xxland 34, 34, 13
	xxland 35, 35, 13
	xxlxor 32, 48, 32
	xxlxor 37, 38, 37
	vadduwm 13, 13, 2
	vadduwm 31, 31, 3
	vrlw 5, 5, 22
	vrlw 0, 0, 22
	xxlxor 56, 45, 56
	xxlxor 36, 63, 36
	vrlw 24, 24, 22
	vrlw 4, 4, 22
	vadduwm 12, 12, 17
	vadduwm 15, 15, 27
	vadduwm 12, 12, 5
	vadduwm 15, 15, 0
	vadduwm 8, 8, 20
	vadduwm 11, 11, 1
	xxlxor 34, 44, 34
	xxlxor 35, 47, 35
	vadduwm 8, 8, 24
	vadduwm 11, 11, 4
	vperm 2, 2, 2, 9
	vperm 3, 3, 3, 9
	xxlxor 61, 40, 61
	xxlxor 55, 43, 55
	vperm 29, 29, 29, 9
	vperm 23, 23, 23, 9
	xxland 34, 34, 12
	xxland 35, 35, 12
	vadduwm 16, 16, 2
	vadduwm 13, 13, 3
	xxland 61, 61, 12
	xxland 55, 55, 12
	xxlxor 37, 48, 37
	xxlxor 32, 45, 32
	vadduwm 31, 31, 29
	vadduwm 6, 6, 23
	vrlw 5, 5, 10
	vrlw 0, 0, 10
	xxlxor 56, 63, 56
	xxlxor 36, 38, 36
	xxlor 33, 27, 27
	vrlw 24, 24, 10
	vrlw 4, 4, 10
	vadduwm 12, 12, 18
	vadduwm 15, 15, 1
	xxlor 29, 53, 53
	vmr	21, 17
	xxlor 46, 6, 6
	xxlor 49, 4, 4
	vadduwm 12, 12, 5
	vadduwm 15, 15, 0
	vadduwm 8, 8, 14
	vadduwm 11, 11, 17
	xxlxor 34, 44, 34
	xxlxor 35, 47, 35
	vadduwm 8, 8, 24
	vadduwm 11, 11, 4
	vperm 2, 2, 2, 26
	vperm 3, 3, 3, 26
	xxlxor 61, 40, 61
	xxlxor 55, 43, 55
	vperm 29, 29, 29, 26
	vperm 23, 23, 23, 26
	xxland 34, 34, 13
	xxland 35, 35, 13
	vadduwm 16, 16, 2
	vadduwm 13, 13, 3
	vadduwm 11, 11, 28
	xxland 61, 61, 13
	xxland 60, 55, 13
	xxlxor 32, 45, 32
	xxlxor 37, 48, 37
	vadduwm 31, 31, 29
	vadduwm 6, 6, 28
	vrlw 0, 0, 22
	vrlw 5, 5, 22
	vadduwm 8, 8, 25
	xxlxor 57, 63, 56
	xxlxor 36, 38, 36
	vrlw 25, 25, 22
	vrlw 4, 4, 22
	vadduwm 12, 12, 7
	vadduwm 7, 15, 30
	vadduwm 8, 8, 0
	vadduwm 7, 7, 5
	xxlxor 47, 40, 60
	xxlxor 62, 39, 61
	vadduwm 11, 11, 25
	vadduwm 12, 12, 4
	vperm 15, 15, 15, 9
	vperm 30, 30, 30, 9
	xxlxor 34, 43, 34
	xxlxor 35, 44, 35
	xxlor 7, 24, 24
	xxlor 7, 51, 51
	xxlor 51, 25, 25
	vperm 2, 2, 2, 9
	vperm 3, 3, 3, 9
	vadduwm 11, 11, 19
	xxland 47, 47, 12
	xxland 51, 62, 12
	vadduwm 16, 16, 15
	vadduwm 6, 6, 19
	xxland 34, 34, 12
	xxland 35, 35, 12
	xxlxor 32, 48, 32
	xxlxor 37, 38, 37
	vadduwm 13, 13, 2
	vadduwm 31, 31, 3
	vrlw 0, 0, 10
	vrlw 5, 5, 10
	xxlor 61, 29, 29
	xxlxor 62, 45, 57
	xxlxor 36, 63, 36
	vadduwm 8, 8, 29
	vrlw 30, 30, 10
	vrlw 4, 4, 10
	vadduwm 7, 7, 18
	xxlor 61, 7, 7
	vadduwm 8, 8, 0
	vadduwm 7, 7, 5
	vadduwm 12, 12, 29
	xxlxor 47, 40, 47
	xxlxor 50, 39, 51
	vadduwm 11, 11, 30
	vadduwm 12, 12, 4
	vperm 15, 15, 15, 26
	vperm 18, 18, 18, 26
	xxlxor 34, 43, 34
	xxlxor 35, 44, 35
	vperm 2, 2, 2, 26
	vperm 3, 3, 3, 26
	xxland 47, 47, 13
	xxland 50, 50, 13
	vadduwm 16, 16, 15
	vadduwm 6, 6, 18
	xxlor 51, 30, 30
	xxland 34, 34, 13
	xxland 35, 35, 13
	xxlxor 32, 48, 32
	xxlxor 37, 38, 37
	vadduwm 8, 8, 19
	vadduwm 13, 13, 2
	vadduwm 19, 31, 3
	vrlw 5, 5, 22
	vrlw 0, 0, 22
	xxlxor 63, 45, 62
	xxlxor 36, 51, 36
	vrlw 31, 31, 22
	vrlw 4, 4, 22
	vadduwm 12, 12, 14
	vadduwm 7, 7, 1
	vadduwm 12, 12, 5
	vadduwm 7, 7, 0
	vadduwm 11, 11, 21
	xxlxor 34, 44, 34
	xxlxor 35, 39, 35
	vadduwm 8, 8, 31
	vadduwm 11, 11, 4
	vperm 2, 2, 2, 9
	vperm 3, 3, 3, 9
	xxlxor 50, 40, 50
	xxlxor 47, 43, 47
	vperm 18, 18, 18, 9
	vperm 15, 15, 15, 9
	xxland 34, 34, 12
	xxland 35, 35, 12
	xxlor 33, 5, 5
	vadduwm 16, 16, 2
	vadduwm 13, 13, 3
	vadduwm 1, 11, 1
	xxland 43, 50, 12
	xxland 46, 47, 12
	xxlxor 37, 48, 37
	xxlxor 32, 45, 32
	vadduwm 15, 19, 11
	vadduwm 6, 6, 14
	vrlw 5, 5, 10
	vrlw 0, 0, 10
	xxlxor 50, 47, 63
	xxlxor 36, 38, 36
	vrlw 18, 18, 10
	vrlw 4, 4, 10
	vadduwm 10, 12, 27
	vadduwm 7, 7, 20
	vadduwm 10, 10, 5
	vadduwm 7, 7, 0
	vadduwm 8, 8, 17
	xxlxor 34, 42, 34
	xxlxor 35, 39, 35
	vadduwm 8, 8, 18
	vadduwm 1, 1, 4
	vperm 2, 2, 2, 26
	vperm 3, 3, 3, 26
	xxlxor 43, 40, 43
	xxlxor 44, 33, 46
	vperm 14, 11, 11, 26
	vperm 12, 12, 12, 26
	xxland 49, 34, 13
	xxland 35, 35, 13
	vadduwm 2, 16, 17
	vadduwm 11, 13, 3
	xxlxor 37, 34, 37
	xxlxor 34, 34, 40
	xxlxor 32, 43, 32
	xxlxor 43, 43, 33
	xxland 33, 46, 13
	xxland 40, 44, 13
	vadduwm 12, 15, 1
	vadduwm 6, 6, 8
	xxlxor 45, 44, 50
	xxlxor 36, 38, 36
	vrlw 0, 0, 22
	vrlw 13, 13, 22
	vrlw 4, 4, 22
	vrlw 5, 5, 22
	xxlor 0, 12, 12
	xxlor 1, 13, 13
	xxlxor 0, 44, 42
	xxlxor 1, 38, 39
	xxlxor 55, 32, 40
	xxlor 32, 0, 0
	xxlxor 47, 45, 49
	xxlxor 45, 36, 35
	xxlxor 48, 37, 33
	xxlor 33, 1, 1
	xxlor 26, 25, 25
	bne	5, .LBB2_4
.LBB2_7:
	vmrghw 3, 2, 11
	addic 4, 29, 4
	lwz 10, 76(1)
	addi 25, 25, -4
	vmrglw 2, 2, 11
	addze 5, 28
	lwz 14, 72(1)
	cmplwi 5, 25, 3
	vmrglw 5, 0, 1
	addi 20, 20, 16
	addi 10, 10, 1
	vmrglw 6, 23, 15
	vmrglw 7, 13, 16
	vmrghw 4, 0, 1
	vmrghw 0, 23, 15
	vmrghw 1, 13, 16
	xxmrghd	2, 34, 37
	iselgt	29, 4, 29
	li 4, 64
	xxmrgld	3, 34, 37
	iselgt	28, 5, 28
	xxmrghd	6, 38, 39
	xxmrghd	0, 35, 36
	stxvd2x 2, 24, 4
	li 4, 80
	xxmrgld	1, 35, 36
	xxmrghd	4, 32, 33
	stxvd2x 6, 24, 4
	li 4, 96
	xxmrgld	5, 32, 33
	stxvd2x 3, 24, 4
	li 4, 112
	xxmrgld	7, 38, 39
	stxvd2x 0, 0, 24
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
	bl _blake3_compress_in_place_sse41
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
	lfd 31, 632(1)
	lfd 30, 624(1)
	lxvd2x 63, 1, 3
	li 3, 464
	lfd 29, 616(1)
	lxvd2x 62, 1, 3
	li 3, 448
	lfd 28, 608(1)
	lxvd2x 61, 1, 3
	li 3, 432
	lfd 27, 600(1)
	lxvd2x 60, 1, 3
	li 3, 416
	lfd 26, 592(1)
	lxvd2x 59, 1, 3
	li 3, 400
	lfd 25, 584(1)
	lxvd2x 58, 1, 3
	li 3, 384
	lfd 24, 576(1)
	lxvd2x 57, 1, 3
	li 3, 368
	lfd 23, 568(1)
	lxvd2x 56, 1, 3
	li 3, 352
	lwz 31, 564(1)
	lxvd2x 55, 1, 3
	li 3, 336
	lwz 30, 560(1)
	lxvd2x 54, 1, 3
	li 3, 320
	lwz 29, 556(1)
	lxvd2x 53, 1, 3
	li 3, 304
	lwz 28, 552(1)
	lxvd2x 52, 1, 3
	lwz 27, 548(1)
	lwz 26, 544(1)
	lwz 25, 540(1)
	lwz 24, 536(1)
	lwz 23, 532(1)
	lwz 22, 528(1)
	lwz 21, 524(1)
	lwz 20, 520(1)
	lwz 19, 516(1)
	lwz 18, 512(1)
	lwz 17, 508(1)
	lwz 16, 504(1)
	lwz 15, 500(1)
	lwz 14, 496(1)
	lwz 0, 644(1)
	addi 1, 1, 640
	mtlr 0
	blr
.Lfunc_end2:
	.size	_blake3_hash_many_sse41, .Lfunc_end2-.Lfunc_begin2

#endif
