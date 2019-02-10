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
libsha2_update(struct libsha2_state *restrict state, const void *restrict message_, size_t msglen)
{
	const char *restrict message = message_;
	size_t n, off;

	off = (state->message_size / 8) % state->chunk_size;
	state->message_size += msglen;
	msglen /= 8;

	if (off) {
		n = msglen < state->chunk_size - off ? msglen : state->chunk_size - off;
		memcpy(state->chunk + off, message, n);
		if (off + n == state->chunk_size)
			libsha2_process(state, state->chunk);
		message += n;
		msglen -= n;
	}

	while (msglen >= state->chunk_size) {
		libsha2_process(state, (const unsigned char *)message);
		message += state->chunk_size;
		msglen -= state->chunk_size;
	}

	if (msglen)
		memcpy(state->chunk, message, msglen);
}
