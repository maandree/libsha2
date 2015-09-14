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
#include "state.h"
#include <string.h>
#include <errno.h>



/**
 * Round constants, SHA-256, should keep the 32 most significant bits of 64 first constants
 */
static const uint64_t ROUND_CONSTANTS[] = {
  0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL, 0xE9B5DBA58189DBBCULL,
  0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL, 0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL,
  0xD807AA98A3030242ULL, 0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
  0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL, 0xC19BF174CF692694ULL,
  0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL, 0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL,
  0x2DE92C6F592B0275ULL, 0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
  0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL, 0xBF597FC7BEEF0EE4ULL,
  0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL, 0x06CA6351E003826FULL, 0x142929670A0E6E70ULL,
  0x27B70A8546D22FFCULL, 0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
  0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL, 0x92722C851482353BULL,
  0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL, 0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL,
  0xD192E819D6EF5218ULL, 0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
  0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL, 0x34B0BCB5E19B48A8ULL,
  0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL, 0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL,
  0x748F82EE5DEFB2FCULL, 0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
  0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL, 0xC67178F2E372532BULL,
  0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL, 0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL,
  0x06F067AA72176FBAULL, 0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
  0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL, 0x431D67C49C100D4CULL,
  0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL, 0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL};



/**
 * Initialise a state
 * 
 * @parma   state      The state that should be initialised
 * @parma   algorithm  The hashing algorithm
 * @return             Zero on success, -1 on error
 */
int libsha2_state_initialise(libsha2_state_t* restrict state, libsha2_algorithm_t algorithm)
{
  static const uint32_t H_224[] = {
    0xC1059ED8UL, 0x367CD507UL, 0x3070DD17UL, 0xF70E5939UL,
    0xFFC00B31UL, 0x68581511UL, 0x64F98FA7UL, 0xBEFA4FA4UL};
  static const uint32_t H_256[] = {
    0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
    0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL};
  static const uint64_t H_384[] = {
    0xCBBB9D5DC1059ED8ULL, 0x629A292A367CD507ULL, 0x9159015A3070DD17ULL, 0x152FECD8F70E5939ULL,
    0x67332667FFC00B31ULL, 0x8EB44A8768581511ULL, 0xDB0C2E0D64F98FA7ULL, 0x47B5481DBEFA4FA4ULL};
  static const uint64_t H_512[] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL, 0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL, 0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL};
  static const uint64_t H_512_224[] = {
    0x8C3D37C819544DA2ULL, 0x73E1996689DCD4D6ULL, 0x1DFAB7AE32FF9C82ULL, 0x679DD514582F9FCFULL,
    0x0F6D2B697BD44DA8ULL, 0x77E36F7304C48942ULL, 0x3F9D85A86A1D36C8ULL, 0x1112E6AD91D692A1ULL};
  static const uint64_t H_512_256[] = {
    0x22312194FC2BF72CULL, 0x9F555FA3C84C64C2ULL, 0x2393B86B6F53B151ULL, 0x963877195940EABDULL,
    0x96283EE2A88EFFE3ULL, 0xBE5E1E2553863992ULL, 0x2B0199FC2C85B8AAULL, 0x0EB72DDC81C52CA2ULL};
  
  size_t i;
  
  memset(state, 0, sizeof(*state));
  state->message_size = 0;
  state->algorithm = algorithm;
  
  /* Set initial hash values. */
  switch (algorithm)
    {
    case LIBSHA2_224:      memcpy(state->h.b32, H_224,     sizeof(H_224));      break;
    case LIBSHA2_256:      memcpy(state->h.b32, H_256,     sizeof(H_256));      break;
    case LIBSHA2_384:      memcpy(state->h.b64, H_384,     sizeof(H_384));      break;
    case LIBSHA2_512:      memcpy(state->h.b64, H_512,     sizeof(H_512));      break;
    case LIBSHA2_512_224:  memcpy(state->h.b64, H_512_224, sizeof(H_512_224));  break;
    case LIBSHA2_512_256:  memcpy(state->h.b64, H_512_256, sizeof(H_512_256));  break;
    default:
      return errno = EINVAL, -1;
    }
  
  /* Set round constants, and chunk size. */
  switch (algorithm)
    {
    case LIBSHA2_224:
    case LIBSHA2_256:
      for (i = 0; i < 64; i++)
	state->k.b32[i] = (uint32_t)(ROUND_CONSTANTS[i] >> 32);
      state->chunk_size = 64;
      break;
      
    default:
      memcpy(state->k.b64, ROUND_CONSTANTS, sizeof(ROUND_CONSTANTS));
      state->chunk_size = 128;
      break;
    }
  
  return 0;
}


/**
 * Get the output size of the algorithm specified for a state
 * 
 * @parma   state  The state
 * @return         The number of bytes in the output, zero on error
 */
size_t libsha2_state_output_size(const libsha2_state_t* restrict state)
{
  return libsha2_algorithm_output_size(state->algorithm);
}


/**
 * Get the output size of an algorithm
 * 
 * @parma   algorithm  The hashing algorithm
 * @return             The number of bytes in the output, zero on error
 */
size_t libsha2_algorithm_output_size(libsha2_algorithm_t algorithm)
{
  switch (algorithm)
    {
    case LIBSHA2_224:     return 28;
    case LIBSHA2_256:     return 32;
    case LIBSHA2_384:     return 48;
    case LIBSHA2_512:     return 64;
    case LIBSHA2_512_224: return 28;
    case LIBSHA2_512_256: return 32;
    default:
      return errno = EINVAL, 0;
    }
}

