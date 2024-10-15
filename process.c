/* See LICENSE file for copyright and license details. */
#include "common.h"
#include <stdatomic.h>

#if defined(__SSE4_1__) && defined(__SSSE3__) && defined(__SSE2__) && defined(__SHA__)
# define HAVE_X86_SHA256_INTRINSICS
#endif

#if defined(__arm__) || defined(__aarch32__) || defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM)
# if defined(__ARM_NEON) && (defined(__ARM_ACLE) || defined(__ARM_FEATURE_CRYPTO))
#  define HAVE_ARM_SHA256_INTRINSICS
# endif
#endif


#ifdef HAVE_X86_SHA256_INTRINSICS
# include <immintrin.h>
#endif

#ifdef HAVE_ARM_SHA256_INTRINSICS
# include <arm_neon.h>
# include <arm_acle.h>
#endif


/**
 * Unified implementation (what can unified without performance impact)
 * of the chunk processing for all SHA-2 functions
 * 
 * @param  chunk      The data to process
 * @param  A          Wordsize-dependent constant, take a look at the code
 * @param  B          Wordsize-dependent constant, take a look at the code
 * @param  C          Wordsize-dependent constant, take a look at the code
 * @param  D          Wordsize-dependent constant, take a look at the code
 * @param  E          Wordsize-dependent constant, take a look at the code
 * @param  F          Wordsize-dependent constant, take a look at the code
 * @param  G          Wordsize-dependent constant, take a look at the code
 * @param  H          Wordsize-dependent constant, take a look at the code
 * @param  I          Wordsize-dependent constant, take a look at the code
 * @param  J          Wordsize-dependent constant, take a look at the code
 * @param  K          Wordsize-dependent constant, take a look at the code
 * @param  L          Wordsize-dependent constant, take a look at the code
 * @param  WORD_T     `__typeof()` on any wordsize-dependent variable
 * @param  WORD_SIZE  4 for 32-bit algorithms and 8 for 64-bit algorithms
 * @param  TRUNC      `TRUNC32` for 32-bit algorithms and `TRUNC64` for 64-bit algorithms
 * @param  k          Round constants
 * @param  w          Words
 * @param  h          Hash values
 * @param  work_h     Space for temporary hash values
 */
#define SHA2_IMPLEMENTATION(chunk, A, B, C, D, E, F, G, H, I, J, K, L, WORD_T, WORD_SIZE, TRUNC, k, w, h, work_h) \
	memcpy(work_h, h, sizeof(work_h));\
	\
	memset(w, 0, 16 * sizeof(*(w)));\
	for (i = 0; i < 16; i++)\
		for (j = 0; j < WORD_SIZE; j++)\
			w[i] |= ((WORD_T)(chunk[(i + 1) * WORD_SIZE - j - 1])) << (j << 3);\
	\
	for (i = 16; i < sizeof(k) / sizeof(*(k)); i++)	{\
		w[i] = w[i - 16] + w[i - 7];\
		w[i] += ROTR(w[i - 15], A) ^ ROTR(w[i - 15], B) ^ (w[i - 15] >> (C));\
		w[i] += ROTR(w[i - 2], D) ^ ROTR(w[i - 2], E) ^ (w[i - 2] >> (F));\
		w[i] = TRUNC(w[i]);\
	}\
	\
	for (i = 0; i < sizeof(k) / sizeof(*(k)); i++) {\
		s1 = work_h[6] ^ (work_h[4] & (work_h[5] ^ work_h[6]));\
		s1 += work_h[7] + k[i] + w[i];\
		s0 = (work_h[0] & work_h[1]) | (work_h[2] & (work_h[0] | work_h[1]));\
		s1 += ROTR(work_h[4], G) ^ ROTR(work_h[4], H) ^ ROTR(work_h[4], I);\
		s0 += ROTR(work_h[0], J) ^ ROTR(work_h[0], K) ^ ROTR(work_h[0], L);\
		\
		memmove(&work_h[1], work_h, 7 * sizeof(*(work_h)));\
		work_h[4] = TRUNC(work_h[4] + s1);\
		work_h[0] = TRUNC(s1 + s0);\
	}\
	\
	for (i = 0; i < 8; i++)\
		h[i] = TRUNC(h[i] + work_h[i]);


#ifdef HAVE_X86_SHA256_INTRINSICS

static size_t
process_x86_sha256(struct libsha2_state *restrict state, const unsigned char *restrict data, size_t len)
{
	const __m128i SHUFFLE_MASK = _mm_set_epi64x(0x0C0D0E0F08090A0BULL, 0x0405060700010203ULL);
	register __m128i temp, s0, s1, msg, msg0, msg1, msg2, msg3;
	__m128i abef_orig, cdgh_orig;
	const unsigned char *restrict chunk;
	size_t off = 0;

	temp = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)&state->h.b32[0]), 0xB1);
	s1   = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)&state->h.b32[4]), 0x1B);
	s0   = _mm_alignr_epi8(temp, s1, 8);
	s1   = _mm_blend_epi16(s1, temp, 0xF0);

	for (; len - off >= state->chunk_size; off += state->chunk_size) {
		chunk = &data[off];

		abef_orig = s0;
		cdgh_orig = s1;

#if defined(__GNUC__)
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wsign-conversion"
#endif

		msg = _mm_loadu_si128((const __m128i *)&chunk[0]);
		msg0 = _mm_shuffle_epi8(msg, SHUFFLE_MASK);
		msg = _mm_add_epi32(msg0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
		s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		s0 = _mm_sha256rnds2_epu32(s0, s1, msg);

	        msg1 = _mm_loadu_si128((const __m128i *)&chunk[16]);
		msg1 = _mm_shuffle_epi8(msg1, SHUFFLE_MASK);
		msg = _mm_add_epi32(msg1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
		s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		msg0 = _mm_sha256msg1_epu32(msg0, msg1);
		s0 = _mm_sha256rnds2_epu32(s0, s1, msg);

	        msg2 = _mm_loadu_si128((const __m128i *)&chunk[32]);
		msg2 = _mm_shuffle_epi8(msg2, SHUFFLE_MASK);
		msg = _mm_add_epi32(msg2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
		s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
		msg1 = _mm_sha256msg1_epu32(msg1, msg2);

		msg3 = _mm_loadu_si128((const __m128i *)&chunk[48]);
		msg3 = _mm_shuffle_epi8(msg3, SHUFFLE_MASK);
		msg = _mm_add_epi32(msg3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
		temp = _mm_alignr_epi8(msg3, msg2, 4);
		msg0 = _mm_add_epi32(msg0, temp);
		s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		msg0 = _mm_sha256msg2_epu32(msg0, msg3);
		s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
		msg2 = _mm_sha256msg1_epu32(msg2, msg3);

	        msg = _mm_add_epi32(msg0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
		s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
		temp = _mm_alignr_epi8(msg0, msg3, 4);
		msg1 = _mm_add_epi32(msg1, temp);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		msg1 = _mm_sha256msg2_epu32(msg1, msg0);
		s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
		msg3 = _mm_sha256msg1_epu32(msg3, msg0);

	        msg = _mm_add_epi32(msg1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
		s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
		temp = _mm_alignr_epi8(msg1, msg0, 4);
		msg2 = _mm_add_epi32(msg2, temp);
		msg2 = _mm_sha256msg2_epu32(msg2, msg1);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
		msg0 = _mm_sha256msg1_epu32(msg0, msg1);

	        msg = _mm_add_epi32(msg2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
		s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
		temp = _mm_alignr_epi8(msg2, msg1, 4);
		msg3 = _mm_add_epi32(msg3, temp);
		msg3 = _mm_sha256msg2_epu32(msg3, msg2);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
		msg1 = _mm_sha256msg1_epu32(msg1, msg2);

	        msg = _mm_add_epi32(msg3, _mm_set_epi64x(0x1429296706CA6351ULL,  0xD5A79147C6E00BF3ULL));
		s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
		temp = _mm_alignr_epi8(msg3, msg2, 4);
		msg0 = _mm_add_epi32(msg0, temp);
		msg0 = _mm_sha256msg2_epu32(msg0, msg3);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
		msg2 = _mm_sha256msg1_epu32(msg2, msg3);

	        msg = _mm_add_epi32(msg0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
		s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
		temp = _mm_alignr_epi8(msg0, msg3, 4);
		msg1 = _mm_add_epi32(msg1, temp);
		msg1 = _mm_sha256msg2_epu32(msg1, msg0);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
		msg3 = _mm_sha256msg1_epu32(msg3, msg0);

	        msg = _mm_add_epi32(msg1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
		s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
		temp = _mm_alignr_epi8(msg1, msg0, 4);
		msg2 = _mm_add_epi32(msg2, temp);
		msg2 = _mm_sha256msg2_epu32(msg2, msg1);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
		msg0 = _mm_sha256msg1_epu32(msg0, msg1);

	        msg = _mm_add_epi32(msg2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
		s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
		temp = _mm_alignr_epi8(msg2, msg1, 4);
		msg3 = _mm_add_epi32(msg3, temp);
		msg3 = _mm_sha256msg2_epu32(msg3, msg2);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
		msg1 = _mm_sha256msg1_epu32(msg1, msg2);

	        msg = _mm_add_epi32(msg3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
		s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
		temp = _mm_alignr_epi8(msg3, msg2, 4);
		msg0 = _mm_add_epi32(msg0, temp);
		msg0 = _mm_sha256msg2_epu32(msg0, msg3);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
		msg2 = _mm_sha256msg1_epu32(msg2, msg3);

	        msg = _mm_add_epi32(msg0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
		s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
		temp = _mm_alignr_epi8(msg0, msg3, 4);
		msg1 = _mm_add_epi32(msg1, temp);
		msg1 = _mm_sha256msg2_epu32(msg1, msg0);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		s0 = _mm_sha256rnds2_epu32(s0, s1, msg);
		msg3 = _mm_sha256msg1_epu32(msg3, msg0);

	        msg = _mm_add_epi32(msg1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
		s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
		temp = _mm_alignr_epi8(msg1, msg0, 4);
		msg2 = _mm_add_epi32(msg2, temp);
		msg2 = _mm_sha256msg2_epu32(msg2, msg1);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		s0 = _mm_sha256rnds2_epu32(s0, s1, msg);

	        msg = _mm_add_epi32(msg2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
		s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
		temp = _mm_alignr_epi8(msg2, msg1, 4);
		msg3 = _mm_add_epi32(msg3, temp);
		msg3 = _mm_sha256msg2_epu32(msg3, msg2);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		s0 = _mm_sha256rnds2_epu32(s0, s1, msg);

	        msg = _mm_add_epi32(msg3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
		s1 = _mm_sha256rnds2_epu32(s1, s0, msg);
		msg = _mm_shuffle_epi32(msg, 0x0E);
		s0 = _mm_sha256rnds2_epu32(s0, s1, msg);

#if defined(__GNUC__)
# pragma GCC diagnostic pop
#endif

	        s0 = _mm_add_epi32(s0, abef_orig);
		s1 = _mm_add_epi32(s1, cdgh_orig);
	}

	temp = _mm_shuffle_epi32(s0, 0x1B);
	s1   = _mm_shuffle_epi32(s1, 0xB1);
	s0   = _mm_blend_epi16(temp, s1, 0xF0);
	s1   = _mm_alignr_epi8(s1, temp, 8);

	_mm_storeu_si128((__m128i *)&state->h.b32[0], s0);
	_mm_storeu_si128((__m128i *)&state->h.b32[4], s1);

	return off;
}

# if defined(__GNUC__)
__attribute__((__constructor__))
# endif
static int
have_sha_intrinsics(void)
{
	static volatile int ret = -1;
	static volatile atomic_flag spinlock = ATOMIC_FLAG_INIT;
	int a, b, c, d;

	if (ret != -1)
		return ret;

	while (atomic_flag_test_and_set(&spinlock));

	if (ret != -1)
		goto out;

	a = 7;
	c = 0;
	__asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(a), "c"(c));
	if (!(b & (1 << 29))) {
		ret = 0;
		goto out;
	}
	a = 1;
	__asm__ volatile("cpuid" : "=a"(a), "=b"(b), "=c"(c), "=d"(d) : "a"(a), "c"(c));
	if (!(c & (1 << 19)) || !(c & (1 << 0)) || !(d & (1 << 26))) {
		ret = 0;
		goto out;
	}
	ret = 1;

out:
	atomic_flag_clear(&spinlock);
	return ret;
}

#endif

#ifdef HAVE_ARM_SHA256_INTRINSICS

static size_t
process_arm_sha256(struct libsha2_state *restrict state, const unsigned char *restrict data, size_t len)
{
	static const uint32_t rc[] = {
		UINT32_C(0x428A2F98), UINT32_C(0x71374491), UINT32_C(0xB5C0FBCF), UINT32_C(0xE9B5DBA5),
		UINT32_C(0x3956C25B), UINT32_C(0x59F111F1), UINT32_C(0x923F82A4), UINT32_C(0xAB1C5ED5),
		UINT32_C(0xD807AA98), UINT32_C(0x12835B01), UINT32_C(0x243185BE), UINT32_C(0x550C7DC3),
		UINT32_C(0x72BE5D74), UINT32_C(0x80DEB1FE), UINT32_C(0x9BDC06A7), UINT32_C(0xC19BF174),
		UINT32_C(0xE49B69C1), UINT32_C(0xEFBE4786), UINT32_C(0x0FC19DC6), UINT32_C(0x240CA1CC),
		UINT32_C(0x2DE92C6F), UINT32_C(0x4A7484AA), UINT32_C(0x5CB0A9DC), UINT32_C(0x76F988DA),
		UINT32_C(0x983E5152), UINT32_C(0xA831C66D), UINT32_C(0xB00327C8), UINT32_C(0xBF597FC7),
		UINT32_C(0xC6E00BF3), UINT32_C(0xD5A79147), UINT32_C(0x06CA6351), UINT32_C(0x14292967),
		UINT32_C(0x27B70A85), UINT32_C(0x2E1B2138), UINT32_C(0x4D2C6DFC), UINT32_C(0x53380D13),
		UINT32_C(0x650A7354), UINT32_C(0x766A0ABB), UINT32_C(0x81C2C92E), UINT32_C(0x92722C85),
		UINT32_C(0xA2BFE8A1), UINT32_C(0xA81A664B), UINT32_C(0xC24B8B70), UINT32_C(0xC76C51A3),
		UINT32_C(0xD192E819), UINT32_C(0xD6990624), UINT32_C(0xF40E3585), UINT32_C(0x106AA070),
		UINT32_C(0x19A4C116), UINT32_C(0x1E376C08), UINT32_C(0x2748774C), UINT32_C(0x34B0BCB5),
		UINT32_C(0x391C0CB3), UINT32_C(0x4ED8AA4A), UINT32_C(0x5B9CCA4F), UINT32_C(0x682E6FF3),
		UINT32_C(0x748F82EE), UINT32_C(0x78A5636F), UINT32_C(0x84C87814), UINT32_C(0x8CC70208),
		UINT32_C(0x90BEFFFA), UINT32_C(0xA4506CEB), UINT32_C(0xBEF9A3F7), UINT32_C(0xC67178F2)
	};

	uint32x4_t abcd, efgh, abcd_orig, efgh_orig;
	uint32x4_t msg0, msg1, msg2, msg3, tmp0, tmp1, tmp2;
	const unsigned char *restrict chunk;
	size_t off = 0;

	abcd_orig = vld1q_u32(&state->h.b32[0]);
	efgh_orig = vld1q_u32(&state->h.b32[4]);

	for (; len - off >= state->chunk_size; off += state->chunk_size) {
		abcd = abcd_orig;
		efgh = efgh_orig;

		chunk = &data[off];
		msg0 = vld1q_u32((const uint32_t *)&chunk[0]);
		msg1 = vld1q_u32((const uint32_t *)&chunk[16]);
		msg2 = vld1q_u32((const uint32_t *)&chunk[32]);
		msg3 = vld1q_u32((const uint32_t *)&chunk[48]);
		msg0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg0)));
		msg1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg1)));
		msg2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg2)));
		msg3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msg3)));

		tmp0 = vaddq_u32(msg0, vld1q_u32(&rc[0 * 4]));

		msg0 = vsha256su0q_u32(msg0, msg1);
		tmp2 = abcd;
		tmp1 = vaddq_u32(msg1, vld1q_u32(&rc[1 * 4]));
		abcd = vsha256hq_u32(abcd, efgh, tmp0);
		efgh = vsha256h2q_u32(efgh, tmp2, tmp0);
		msg0 = vsha256su1q_u32(msg0, msg2, msg3);

		msg1 = vsha256su0q_u32(msg1, msg2);
		tmp2 = abcd;
		tmp0 = vaddq_u32(msg2, vld1q_u32(&rc[2 * 4]));
		abcd = vsha256hq_u32(abcd, efgh, tmp1);
		efgh = vsha256h2q_u32(efgh, tmp2, tmp1);
		msg1 = vsha256su1q_u32(msg1, msg3, msg0);

		msg2 = vsha256su0q_u32(msg2, msg3);
		tmp2 = abcd;
		tmp1 = vaddq_u32(msg3, vld1q_u32(&rc[3 * 4]));
		abcd = vsha256hq_u32(abcd, efgh, tmp0);
		efgh = vsha256h2q_u32(efgh, tmp2, tmp0);
		msg2 = vsha256su1q_u32(msg2, msg0, msg1);

		msg3 = vsha256su0q_u32(msg3, msg0);
		tmp2 = abcd;
		tmp0 = vaddq_u32(msg0, vld1q_u32(&rc[4 * 4]));
		abcd = vsha256hq_u32(abcd, efgh, tmp1);
		efgh = vsha256h2q_u32(efgh, tmp2, tmp1);
		msg3 = vsha256su1q_u32(msg3, msg1, msg2);

		msg0 = vsha256su0q_u32(msg0, msg1);
		tmp2 = abcd;
		tmp1 = vaddq_u32(msg1, vld1q_u32(&rc[5 * 4]));
		abcd = vsha256hq_u32(abcd, efgh, tmp0);
		efgh = vsha256h2q_u32(efgh, tmp2, tmp0);
		msg0 = vsha256su1q_u32(msg0, msg2, msg3);

		msg1 = vsha256su0q_u32(msg1, msg2);
		tmp2 = abcd;
		tmp0 = vaddq_u32(msg2, vld1q_u32(&rc[6 * 4]));
		abcd = vsha256hq_u32(abcd, efgh, tmp1);
		efgh = vsha256h2q_u32(efgh, tmp2, tmp1);
		msg1 = vsha256su1q_u32(msg1, msg3, msg0);

		msg2 = vsha256su0q_u32(msg2, msg3);
		tmp2 = abcd;
		tmp1 = vaddq_u32(msg3, vld1q_u32(&rc[7 * 4]));
		abcd = vsha256hq_u32(abcd, efgh, tmp0);
		efgh = vsha256h2q_u32(efgh, tmp2, tmp0);
		msg2 = vsha256su1q_u32(msg2, msg0, msg1);

		msg3 = vsha256su0q_u32(msg3, msg0);
		tmp2 = abcd;
		tmp0 = vaddq_u32(msg0, vld1q_u32(&rc[8 * 4]));
		abcd = vsha256hq_u32(abcd, efgh, tmp1);
		efgh = vsha256h2q_u32(efgh, tmp2, tmp1);
		msg3 = vsha256su1q_u32(msg3, msg1, msg2);

		msg0 = vsha256su0q_u32(msg0, msg1);
		tmp2 = abcd;
		tmp1 = vaddq_u32(msg1, vld1q_u32(&rc[9 * 4]));
		abcd = vsha256hq_u32(abcd, efgh, tmp0);
		efgh = vsha256h2q_u32(efgh, tmp2, tmp0);
		msg0 = vsha256su1q_u32(msg0, msg2, msg3);

		msg1 = vsha256su0q_u32(msg1, msg2);
		tmp2 = abcd;
		tmp0 = vaddq_u32(msg2, vld1q_u32(&rc[10 * 4]));
		abcd = vsha256hq_u32(abcd, efgh, tmp1);
		efgh = vsha256h2q_u32(efgh, tmp2, tmp1);
		msg1 = vsha256su1q_u32(msg1, msg3, msg0);

		msg2 = vsha256su0q_u32(msg2, msg3);
		tmp2 = abcd;
		tmp1 = vaddq_u32(msg3, vld1q_u32(&rc[11 * 4]));
		abcd = vsha256hq_u32(abcd, efgh, tmp0);
		efgh = vsha256h2q_u32(efgh, tmp2, tmp0);
		msg2 = vsha256su1q_u32(msg2, msg0, msg1);

		msg3 = vsha256su0q_u32(msg3, msg0);
		tmp2 = abcd;
		tmp0 = vaddq_u32(msg0, vld1q_u32(&rc[12 * 4]));
		abcd = vsha256hq_u32(abcd, efgh, tmp1);
		efgh = vsha256h2q_u32(efgh, tmp2, tmp1);
		msg3 = vsha256su1q_u32(msg3, msg1, msg2);

		tmp2 = abcd;
		tmp1 = vaddq_u32(msg1, vld1q_u32(&rc[13 * 4]));
		abcd = vsha256hq_u32(abcd, efgh, tmp0);
		efgh = vsha256h2q_u32(efgh, tmp2, tmp0);

		tmp2 = abcd;
		tmp0 = vaddq_u32(msg2, vld1q_u32(&rc[14 * 4]));
		abcd = vsha256hq_u32(abcd, efgh, tmp1);
		efgh = vsha256h2q_u32(efgh, tmp2, tmp1);

		tmp2 = abcd;
		tmp1 = vaddq_u32(msg3, vld1q_u32(&rc[15 * 4]));
		abcd = vsha256hq_u32(abcd, efgh, tmp0);
		efgh = vsha256h2q_u32(efgh, tmp2, tmp0);

		tmp2 = abcd;
		abcd = vsha256hq_u32(abcd, efgh, tmp1);
		efgh = vsha256h2q_u32(efgh, tmp2, tmp1);

		abcd_orig = vaddq_u32(abcd_orig, abcd);
		efgh_orig = vaddq_u32(efgh_orig, efgh);
	}

	vst1q_u32(&state->h.b32[0], abcd_orig);
	vst1q_u32(&state->h.b32[4], efgh_orig);

	return off;
}

#endif

size_t
libsha2_process(struct libsha2_state *restrict state, const unsigned char *restrict data, size_t len)
{
	const unsigned char *restrict chunk;
	size_t off = 0;

	if (state->algorithm <= LIBSHA2_256) {
#if defined(HAVE_ARM_SHA256_INTRINSICS)
		return process_arm_sha256(state, data, len);
#else
# define ROTR(X, N) TRUNC32(((X) >> (N)) | ((X) << (32 - (N))))
		uint_least32_t s0, s1;
		size_t i, j;

#if defined(__GNUC__)
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wmemset-elt-size"
#endif
# ifdef HAVE_X86_SHA256_INTRINSICS
		if (have_sha_intrinsics())
			return process_x86_sha256(state, data, len);
# endif
		for (; len - off >= state->chunk_size; off += state->chunk_size) {
			chunk = &data[off];
			SHA2_IMPLEMENTATION(chunk, 7, 18, 3, 17, 19, 10, 6, 11, 25, 2, 13, 22, uint_least32_t, 4,
			                    TRUNC32, state->k.b32, state->w.b32, state->h.b32, state->work_h.b32);
		}
# if defined(__GNUC__)
#  pragma GCC diagnostic pop
# endif
# undef ROTR
#endif

	} else {
#define ROTR(X, N) TRUNC64(((X) >> (N)) | ((X) << (64 - (N))))
		uint_least64_t s0, s1;
		size_t i, j;

		/* TODO Add optimisation using ARMv8.2 SHA-512 intrinsics (when I've access to a machine supporting it)  */

		for (; len - off >= state->chunk_size; off += state->chunk_size) {
			chunk = &data[off];
			SHA2_IMPLEMENTATION(chunk, 1, 8, 7, 19, 61, 6, 14, 18, 41, 28, 34, 39, uint_least64_t, 8,
			                    TRUNC64, state->k.b64, state->w.b64, state->h.b64, state->work_h.b64);
		}
#undef ROTR
	}

	return off;
}
