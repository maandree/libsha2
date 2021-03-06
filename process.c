/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Unified implementation (what can unified without performance impact)
 * of the chunk processing for all SHA-2 functions
 * 
 * @param  chunk   The data to process
 * @param  A       Wordsize-dependent constant, take a look at the code
 * @param  B       Wordsize-dependent constant, take a look at the code
 * @param  C       Wordsize-dependent constant, take a look at the code
 * @param  D       Wordsize-dependent constant, take a look at the code
 * @param  E       Wordsize-dependent constant, take a look at the code
 * @param  F       Wordsize-dependent constant, take a look at the code
 * @param  G       Wordsize-dependent constant, take a look at the code
 * @param  H       Wordsize-dependent constant, take a look at the code
 * @param  I       Wordsize-dependent constant, take a look at the code
 * @param  J       Wordsize-dependent constant, take a look at the code
 * @param  K       Wordsize-dependent constant, take a look at the code
 * @param  L       Wordsize-dependent constant, take a look at the code
 * @param  WORD_T  `__typeof()` on any wordsize-dependent variable, with exact size
 * @param  k       Round constants
 * @param  w       Words
 * @param  h       Hash values
 * @param  work_h  Space for temporary hash values
 */
#define SHA2_IMPLEMENTATION(chunk, A, B, C, D, E, F, G, H, I, J, K, L, WORD_T, k, w, h, work_h)\
	memcpy(work_h, h, sizeof(work_h));\
	\
	memset(w, 0, 16 * sizeof(*(w)));\
	for (i = 0; i < 16; i++)\
		for (j = 0; j < sizeof(WORD_T); j++)\
			w[i] |= ((WORD_T)(chunk[(i + 1) * sizeof(WORD_T) - j - 1])) << (j << 3);\
	\
	for (i = 16; i < sizeof(k) / sizeof(*(k)); i++)	{\
		w[i] = w[i - 16] + w[i - 7];\
		w[i] += ROTR(w[i - 15], A) ^ ROTR(w[i - 15], B) ^ (w[i - 15] >> (C));\
		w[i] += ROTR(w[i - 2], D) ^ ROTR(w[i - 2], E) ^ (w[i - 2] >> (F));\
	}\
	\
	for (i = 0; i < sizeof(k) / sizeof(*(k)); i++) {\
		s1 = work_h[6] ^ (work_h[4] & (work_h[5] ^ work_h[6]));\
		s1 += work_h[7] + k[i] + w[i];\
		s0 = (work_h[0] & work_h[1]) | (work_h[2] & (work_h[0] | work_h[1]));\
		s1 += ROTR(work_h[4], G) ^ ROTR(work_h[4], H) ^ ROTR(work_h[4], I);\
		s0 += ROTR(work_h[0], J) ^ ROTR(work_h[0], K) ^ ROTR(work_h[0], L);\
		\
		memmove(work_h + 1, work_h, 7 * sizeof(*(work_h)));\
		work_h[4] += s1;\
		work_h[0] = s1 + s0;\
	}\
	\
	for (i = 0; i < 8; i++)\
		h[i] += work_h[i]


/**
 * Process a chunk using SHA-2
 * 
 * @param  state  The hashing state
 * @param  chunk  The data to process
 */
void
libsha2_process(struct libsha2_state *restrict state, const unsigned char *restrict chunk)
{
	if (state->algorithm <= LIBSHA2_256) {
		uint32_t s0, s1;
		size_t i, j;

#if defined(__GNUC__)
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wmemset-elt-size"
#endif
#define ROTR(X, N) (((X) >> (N)) | ((X) << ((sizeof(uint32_t) * 8) - (N))))

		SHA2_IMPLEMENTATION(chunk, 7, 18, 3, 17, 19, 10, 6, 11, 25, 2, 13, 22, uint32_t,
		                    state->k.b32, state->w.b32, state->h.b32, state->work_h.b32);

#undef ROTR
#if defined(__GNUC__)
# pragma GCC diagnostic pop
#endif

	} else {
		uint64_t s0, s1;
		size_t i, j;

#define ROTR(X, N) (((X) >> (N)) | ((X) << ((sizeof(uint64_t) * 8) - (N))))

		SHA2_IMPLEMENTATION(chunk, 1, 8, 7, 19, 61, 6, 14, 18, 41, 28, 34, 39, uint64_t,
		                    state->k.b64, state->w.b64, state->h.b64, state->work_h.b64);

#undef ROTR
	}
}
