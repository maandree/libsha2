/**
 * libsha2 – SHA-2-family hashing library
 * 
 * Copyright © 2015  Mattias Andrée (maandree@member.fsf.org)
 * 
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "digest.h"
#include <alloca.h>
#include <string.h>



/**
 * Unified implementation (what can unified without performance impact)
 * of the chunk processing for all SHA-2 functions
 * 
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
#define SHA2_IMPLEMENTATION(A, B, C, D, E, F, G, H, I, J, K, L, WORD_T, k, w, h, work_h)	\
  memcpy(work_h, h, sizeof(work_h));								\
												\
  memset(w, 0, 16 * sizeof(*(w)));								\
  for (i = 0; i < 16; i++)									\
    for (j = 0; j < sizeof(WORD_T); j++)							\
      w[i] |= ((WORD_T)(state->chunk[(i + 1) * sizeof(WORD_T) - j - 1])) << (j << 3);		\
												\
  for (i = 16; i < sizeof(k) / sizeof(*(k)); i++)						\
    {												\
      w[i] = w[i - 16] + w[i - 7];								\
      w[i] += ROTR(w[i - 15], A) ^ ROTR(w[i - 15], B) ^ (w[i - 15] >> (C));			\
      w[i] += ROTR(w[i - 2], D) ^ ROTR(w[i - 2], E) ^ (w[i - 2] >> (F));			\
    }												\
												\
  for (i = 0; i < sizeof(k) / sizeof(*(k)); i++)						\
    {												\
      s1 = (work_h[4] & work_h[5]) ^ (work_h[6] & ~(work_h[4]));				\
      s1 += work_h[7] + k[i] + w[i];								\
      s0 = (work_h[0] & work_h[1]) ^ (work_h[0] & work_h[2]) ^ (work_h[1] & work_h[2]);		\
      s1 += ROTR(work_h[4], G) ^ ROTR(work_h[4], H) ^ ROTR(work_h[4], I);			\
      s0 += ROTR(work_h[0], J) ^ ROTR(work_h[0], K) ^ ROTR(work_h[0], L);			\
      												\
      memmove(work_h + 1, work_h, 7 * sizeof(*(work_h)));					\
      work_h[4] += s1;										\
      work_h[0] = s1 + s0;									\
    }												\
												\
  for (i = 0; i < 8; i++)									\
    h[i] += work_h[i]



/**
 * Process a chunk using SHA-256
 * 
 * @param  state  The hashing state
 */
__attribute__((nonnull, nothrow))
static void process256(libsha2_state_t* restrict state)
{
  uint32_t s0, s1;
  size_t i, j;
#define ROTR(X, N)  (((X) >> (N)) | ((X) << ((sizeof(uint32_t) * 8) - (N))))
  SHA2_IMPLEMENTATION(7, 18, 3, 17, 19, 10, 6, 11, 25, 2, 13, 22, uint32_t,
		      state->k.b32, state->w.b32, state->h.b32, state->work_h.b32);
#undef ROTR
}


/**
 * Process a chunk using SHA-512
 * 
 * @param  state  The hashing state
 */
__attribute__((nonnull, nothrow))
static void process512(libsha2_state_t* restrict state)
{
  uint64_t s0, s1;
  size_t i, j;
#define ROTR(X, N)  (((X) >> (N)) | ((X) << ((sizeof(uint64_t) * 8) - (N))))
  SHA2_IMPLEMENTATION(1, 8, 7, 19, 61, 6, 14, 18, 41, 28, 34, 39, uint64_t,
		      state->k.b64, state->w.b64, state->h.b64, state->work_h.b64);
#undef ROTR
}


/**
 * Absorb more of the message
 * 
 * @param  state    The hashing state
 * @param  message  The message, in bits, must be equivalent to 0 modulus 8
 * @param  msglen   The length of the message
 */
void libsha2_update(libsha2_state_t* restrict state, const char* restrict message, size_t msglen)
{
  size_t n, off, mlen;
  
  msglen /= 8;
  mlen = state->message_size / 8;
  
  while (msglen)
    {
      off = mlen % state->chunk_size;
      n = state->chunk_size - off;
      n = n < msglen ? n : msglen;
      memcpy(state->chunk + off, message, n);
      if (off + n == state->chunk_size)
	switch (state->algorithm)
	  {
	  case LIBSHA2_224:
	  case LIBSHA2_256:
	    process256(state);
	    break;
	    
	  default:
	    process512(state);
	    break;
	  }
      message += n, mlen += n, msglen -= n;
    }
  
  state->message_size = mlen * 8;
}


/**
 * Absorb the last part of the message and output a hash
 * 
 * @param  state    The hashing state
 * @param  message  The message, in bits
 * @param  msglen   The length of the message, zero if there is nothing more to absorb
 * @param  output   The output buffer for the hash
 */
void libsha2_digest(libsha2_state_t* restrict state, const char* restrict message, size_t msglen, char* output)
{
  char* appendix;
  size_t i, j, k, n;
  
  if (msglen & ~7)
    {
      libsha2_update(state, message, msglen & ~7);
      message += msglen & ~7;
      msglen &= 7;
    }
  
  k = 8 * state->chunk_size;
  n = state->chunk_size + 8;
  n = (k + (n % k)) % k;
  n = n / 8 - 1;
  
  appendix = state->appendix;
  if (msglen)
    {
      j = 7 - msglen;
      *appendix = *message;
      *appendix |= 1 << j;
      *appendix &= ~((1 << j) - 1);
    }
  else
    *appendix = (unsigned char)128;
  
  k = state->message_size + msglen;
  i = state->chunk_size / 8;
  appendix += n + i - 1;
  for (i = i < sizeof(size_t) ? i : sizeof(size_t); i--;)
    *(appendix - i) = (unsigned char)((k >> (i * 8)) & 255);
  
  n += state->chunk_size;
  libsha2_update(state, state->appendix, n);
  
  n = libsha2_algorithm_output_size(state->algorithm);
  switch (state->algorithm)
    {
    case LIBSHA2_224:
    case LIBSHA2_256:
      for (i = 0; i < 8; i++)
	for (j = 0; j < (state->chunk_size / 16); j++)
	  if (k = (i + 1) * (state->chunk_size / 16) - j - 1, k < n)
	    output[k] = (char)((state->h.b32[i] >> (8 * j)) & 255);
      break;
      
    default:
      for (i = 0; i < 8; i++)
	for (j = 0; j < (state->chunk_size / 16); j++)
	  if (k = (i + 1) * (state->chunk_size / 16) - j - 1, k < n)
	    output[k] = (char)((state->h.b64[i] >> (8 * j)) & 255);
      break;
    }
}

