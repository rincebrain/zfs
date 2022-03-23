/* x86_features.c - x86 feature check
 *
 * Copyright (C) 2013 Intel Corporation. All rights reserved.
 * Author:
 *  Jim Kukunas
 *
 * For conditions of distribution and use, see copyright notice in zlib.h
 */

#include "../../zbuild.h"

#ifdef _MSC_VER
#  include <intrin.h>
#else
// Newer versions of GCC and clang come with cpuid.h
#  include <cpuid.h>
#endif

#ifndef _KERNEL
#include <string.h>
#else
#include <sys/strings.h>
#endif

#include <sys/simd.h>

Z_INTERNAL int x86_cpu_has_avx2;
Z_INTERNAL int x86_cpu_has_avx512;
Z_INTERNAL int x86_cpu_has_avx512vnni;
Z_INTERNAL int x86_cpu_has_sse2;
Z_INTERNAL int x86_cpu_has_ssse3;
Z_INTERNAL int x86_cpu_has_sse41;
Z_INTERNAL int x86_cpu_has_sse42;
Z_INTERNAL int x86_cpu_has_pclmulqdq;
Z_INTERNAL int x86_cpu_has_vpclmulqdq;
Z_INTERNAL int x86_cpu_has_tzcnt;

#if 0
static void cpuid(int info, unsigned* eax, unsigned* ebx, unsigned* ecx, unsigned* edx) {
#ifdef _MSC_VER
    unsigned int registers[4];
    __cpuid((int *)registers, info);

    *eax = registers[0];
    *ebx = registers[1];
    *ecx = registers[2];
    *edx = registers[3];
#else
    __cpuid(info, *eax, *ebx, *ecx, *edx);
#endif
}

static void cpuidex(int info, int subinfo, unsigned* eax, unsigned* ebx, unsigned* ecx, unsigned* edx) {
#ifdef _MSC_VER
    unsigned int registers[4];
    __cpuidex((int *)registers, info, subinfo);

    *eax = registers[0];
    *ebx = registers[1];
    *ecx = registers[2];
    *edx = registers[3];
#else
    __cpuid_count(info, subinfo, *eax, *ebx, *ecx, *edx);
#endif
}
#endif
void Z_INTERNAL x86_check_features(void) {
//    unsigned eax, ebx, ecx, edx;
//    unsigned maxbasic;
    x86_cpu_has_sse2 = zfs_sse2_available();
    x86_cpu_has_ssse3 = zfs_ssse3_available();
    x86_cpu_has_sse41 = zfs_sse4_1_available();
    x86_cpu_has_sse42 = zfs_sse4_2_available();
    x86_cpu_has_pclmulqdq = zfs_pclmulqdq_available();
    // technically wrong, but I won't tell if you don't.
    x86_cpu_has_tzcnt = zfs_sse4_2_available();
    x86_cpu_has_avx2 = zfs_avx2_available();
    x86_cpu_has_avx512 = zfs_avx512f_available();
    x86_cpu_has_avx512vnni = 0;
    // again, shhh.
    x86_cpu_has_vpclmulqdq = zfs_pclmulqdq_available();

#if 0
    cpuid(0, &maxbasic, &ebx, &ecx, &edx);
    cpuid(1 /*CPU_PROCINFO_AND_FEATUREBITS*/, &eax, &ebx, &ecx, &edx);
    x86_cpu_has_sse2 = edx & 0x4000000;
    x86_cpu_has_ssse3 = ecx & 0x200;
    x86_cpu_has_sse41 = ecx & 0x80000;
    x86_cpu_has_sse42 = ecx & 0x100000;
    x86_cpu_has_pclmulqdq = ecx & 0x2;

    if (maxbasic >= 7) {
        cpuidex(7, 0, &eax, &ebx, &ecx, &edx);

        // check BMI1 bit
        // Reference: https://software.intel.com/sites/default/files/article/405250/how-to-detect-new-instruction-support-in-the-4th-generation-intel-core-processor-family.pdf
        x86_cpu_has_tzcnt = ebx & 0x8;
        // check AVX2 bit
        x86_cpu_has_avx2 = ebx & 0x20;
        x86_cpu_has_avx512 = ebx & 0x00010000;
        x86_cpu_has_avx512vnni = ecx & 0x800;
        x86_cpu_has_vpclmulqdq = ecx & 0x400;
    } else {
        x86_cpu_has_tzcnt = 0;
        x86_cpu_has_avx2 = 0;
        x86_cpu_has_vpclmulqdq = 0;
    }
#endif
}
