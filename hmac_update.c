/* See LICENSE file for copyright and license details. */
#include "common.h"


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
