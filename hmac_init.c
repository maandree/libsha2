/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Initialise an HMAC state
 * 
 * @param   state        The state that should be initialised
 * @param   algorithm    The hashing algorithm
 * @param   key          The key
 * @param   key_length   The length of key, in bits
 * @return               Zero on success, -1 on error
 */
int
libsha2_hmac_init(struct libsha2_hmac_state *restrict state, enum libsha2_algorithm algorithm,
                  const void *restrict key_, size_t keylen)
{
	const unsigned char *restrict key = key_;
	size_t i;

	state->sha2_state.algorithm = algorithm;
	state->outsize = libsha2_algorithm_output_size(algorithm) * 8;
	if (!state->outsize) {
		errno = EINVAL;
		return -1;
	}
	state->inited = 0;

	if (keylen <= (algorithm <= LIBSHA2_256 ? 64 * 8 : 128 * 8)) {
		memset(state->ipad, 0x36, sizeof(state->ipad));
		memset(state->opad, 0x5C, sizeof(state->opad));
		for (i = 0; i < keylen / 8; i++) {
			state->ipad[i] ^= key[i];
			state->opad[i] ^= key[i];
		}
		if (keylen & 7) {
			state->ipad[i] ^= (unsigned char)(key[i] << (8 - (keylen & 7)));
			state->opad[i] ^= (unsigned char)(key[i] << (8 - (keylen & 7)));
		}
	} else {
		memset(state->ipad, 0, sizeof(state->ipad));
		if (libsha2_init(&state->sha2_state, algorithm))
			return -1;
		libsha2_digest(&state->sha2_state, key, keylen, state->ipad);
		memcpy(state->opad, state->ipad, sizeof(state->ipad));
		for (i = 0; i < sizeof(state->ipad); i++) {
			state->ipad[i] ^= 0x36;
			state->opad[i] ^= 0x5C;
		}
	}

	return 0;
}
