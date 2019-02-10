/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Absorb more of the message
 * 
 * @param  state    The hashing state
 * @param  message  The message, in bits, must be equivalent to 0 modulus 8
 * @param  msglen   The length of the message
 */
void
libsha2_update(struct libsha2_state *restrict state, const char *restrict message, size_t msglen) /* TODO avoid coping */
{
	size_t n, off, mlen;

	msglen /= 8;
	mlen = state->message_size / 8;

	while (msglen) {
		off = mlen % state->chunk_size;
		n = state->chunk_size - off;
		n = n < msglen ? n : msglen;
		memcpy(state->chunk + off, message, n);
		if (off + n == state->chunk_size)
			libsha2_process(state, state->chunk);
		message += n, mlen += n, msglen -= n;
	}

	state->message_size = mlen * 8;
}
