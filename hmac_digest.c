/* See LICENSE file for copyright and license details. */
#include "common.h"


void
libsha2_hmac_digest(struct libsha2_hmac_state *restrict state, const void *data, size_t n, void *output)
{
	if (!state->inited) {
		libsha2_init(&state->sha2_state, state->sha2_state.algorithm);
		libsha2_update(&state->sha2_state, state->ipad, state->sha2_state.chunk_size * 8);
	}

	libsha2_digest(&state->sha2_state, data, n, output);
	libsha2_init(&state->sha2_state, state->sha2_state.algorithm);

	libsha2_update(&state->sha2_state, state->opad, state->sha2_state.chunk_size * 8);
	libsha2_digest(&state->sha2_state, output, state->outsize, output);
	state->inited = 0;
}
