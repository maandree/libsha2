/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Feed data into the HMAC algorithm and
 * get the result
 * 
 * The state of the algorithm will be reset and
 * `libsha2_hmac_update` and `libsha2_hmac_update`
 * can be called again
 * 
 * @param   state   The state of the algorithm
 * @param   data    Data to feed into the algorithm
 * @param   n       The number of bytes to feed into the algorithm
 * @param   output  The output buffer for the hash, it will be as
 *                  large as for the underlaying hash algorithm
 * @return          Zero on success, -1 on error
 */
int
libsha2_hmac_digest(struct libsha2_hmac_state *restrict state, const void *data, size_t n, void *output)
{
	if (!state->inited) {
		if (libsha2_init(&state->sha2_state, state->sha2_state.algorithm))
			return -1;
		libsha2_update(&state->sha2_state, state->ipad, state->sha2_state.chunk_size * 8);
	}

	libsha2_digest(&state->sha2_state, data, n, output);
	if (libsha2_init(&state->sha2_state, state->sha2_state.algorithm))
		return -1;

	libsha2_update(&state->sha2_state, state->opad, state->sha2_state.chunk_size * 8);
	libsha2_digest(&state->sha2_state, output, state->outsize, output);
	state->inited = 0;
	return 0;
}
