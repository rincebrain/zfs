include $(top_srcdir)/config/Rules.am

VPATH = \
	$(top_srcdir)/module/icp \
	$(top_srcdir)/lib/libicp

# Includes kernel code, generate warnings for large stack frames
AM_CFLAGS += $(FRAME_LARGER_THAN)

algs/blake3/blake3.$(OBJEXT): CFLAGS += -mno-sse2 -mno-sse4.1 -mno-avx2 -mno-avx512f
algs/blake3/blake3.l$(OBJEXT): CFLAGS += -mno-sse2 -mno-sse4.1 -mno-avx2 -mno-avx512f
algs/blake3/blake3_sse2.$(OBJEXT): CFLAGS += -msse2 -march=native
algs/blake3/blake3_sse2.l$(OBJEXT): CFLAGS += -msse2 -march=native
algs/blake3/blake3_sse41.$(OBJEXT): CFLAGS += -msse4.1 -march=native
algs/blake3/blake3_sse41.l$(OBJEXT): CFLAGS += -msse4.1 -march=native
algs/blake3/blake3_avx2.$(OBJEXT): CFLAGS += -mavx2 -march=native
algs/blake3/blake3_avx2.l$(OBJEXT): CFLAGS += -mavx2 -march=native
algs/blake3/blake3_avx512.$(OBJEXT): CFLAGS += -mavx512f -march=native
algs/blake3/blake3_avx512.l$(OBJEXT): CFLAGS += -mavx512f -march=native

noinst_LTLIBRARIES = libicp.la

if TARGET_CPU_AARCH64
ASM_SOURCES_C =
ASM_SOURCES_AS = \
	asm-aarch64/blake3/b3_aarch64_sse2.S \
	asm-aarch64/blake3/b3_aarch64_sse41.S
else
if TARGET_CPU_POWERPC
ASM_SOURCES_C =
ASM_SOURCES_AS = \
	asm-ppc64/blake3/b3_ppc64_sse2.S \
	asm-ppc64/blake3/b3_ppc64_sse41.S \
	asm-ppc64/blake3/b3_ppc64le_sse2.S \
	asm-ppc64/blake3/b3_ppc64le_sse41.S
else
if TARGET_CPU_X86_64
ASM_SOURCES_C = asm-x86_64/aes/aeskey.c
ASM_SOURCES_AS = \
	asm-x86_64/aes/aes_amd64.S \
	asm-x86_64/aes/aes_aesni.S \
	asm-x86_64/modes/gcm_pclmulqdq.S \
	asm-x86_64/modes/aesni-gcm-x86_64.S \
	asm-x86_64/modes/ghash-x86_64.S \
	asm-x86_64/sha2/sha256_impl.S \
	asm-x86_64/sha2/sha512_impl.S
else
ASM_SOURCES_C =
ASM_SOURCES_AS =
endif
endif
endif

KERNEL_C = \
	spi/kcf_spi.c \
	api/kcf_ctxops.c \
	api/kcf_cipher.c \
	api/kcf_mac.c \
	algs/aes/aes_impl_aesni.c \
	algs/aes/aes_impl_generic.c \
	algs/aes/aes_impl_x86-64.c \
	algs/aes/aes_impl.c \
	algs/aes/aes_modes.c \
	algs/blake3/blake3.c \
	algs/blake3/blake3_generic.c \
	algs/blake3/blake3_portable.c \
	algs/blake3/blake3_impl.c \
	algs/blake3/blake3_x86-64.c \
	algs/blake3/blake3_avx2.c \
	algs/blake3/blake3_sse2.c \
	algs/blake3/blake3_sse41.c \
	algs/blake3/blake3_avx512.c \
	algs/edonr/edonr.c \
	algs/modes/modes.c \
	algs/modes/cbc.c \
	algs/modes/gcm_generic.c \
	algs/modes/gcm_pclmulqdq.c \
	algs/modes/gcm.c \
	algs/modes/ctr.c \
	algs/modes/ccm.c \
	algs/modes/ecb.c \
	algs/sha2/sha2.c \
	algs/skein/skein.c \
	algs/skein/skein_block.c \
	algs/skein/skein_iv.c \
	illumos-crypto.c \
	io/aes.c \
	io/sha2_mod.c \
	io/skein_mod.c \
	core/kcf_sched.c \
	core/kcf_prov_lib.c \
	core/kcf_callprov.c \
	core/kcf_mech_tabs.c \
	core/kcf_prov_tabs.c \
	$(ASM_SOURCES_C)

KERNEL_ASM = $(ASM_SOURCES_AS)

nodist_libicp_la_SOURCES = \
	$(KERNEL_C) \
	$(KERNEL_ASM)

include $(top_srcdir)/config/CppCheck.am
