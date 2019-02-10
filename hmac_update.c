/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Feed data into the HMAC algorithm
 * 
 * @param  state  The state of the algorithm
 * @param  data   Data to feed into the algorithm
 * @param  n      The number of bytes to feed into the
 *                algorithm, this must be a multiple of 8
 */
void
libsha2_hmac_update(struct libsha2_hmac_state *restrict state, const void *restrict data, size_t n)
{
	if (!state->inited) {
		libsha2_init(&state->sha2_state, state->sha2_state.algorithm);
		libsha2_update(&state->sha2_state, state->ipad, state->sha2_state.chunk_size * 8);
		state->inited = 1;
	}

	libsha2_update(&state->sha2_state, data, n);
}
