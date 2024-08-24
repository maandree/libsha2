/* See LICENSE file for copyright and license details. */
#include "common.h"


void
libsha2_digest(struct libsha2_state *restrict state, const void *message_, size_t msglen, void *output_)
{
	const char *message = message_;
	unsigned char *output = output_;
	size_t off, i, n;

	if (msglen & ~(size_t)7) {
		libsha2_update(state, message, msglen & ~(size_t)7);
		message += msglen >> 3;
		msglen &= (size_t)7;
	}

	off = (state->message_size / 8) % state->chunk_size;
	if (msglen) {
		state->chunk[off] = (unsigned char)(*message << (8 - (int)msglen));
		state->chunk[off] |= (unsigned char)(1 << (7 - msglen));
		state->chunk[off] &= (unsigned char)~((1 << (7 - msglen)) - 1);
		state->message_size += msglen;
	} else {
		state->chunk[off] = 0x80;
	}
	off += 1;

	if (off > state->chunk_size - (size_t)8 * (size_t)(1 + (state->algorithm > LIBSHA2_256))) {
		memset(state->chunk + off, 0, state->chunk_size - off);
		off = 0;
		libsha2_process(state, state->chunk, state->chunk_size);
	}

	memset(state->chunk + off, 0, state->chunk_size - 8 - off);
	state->chunk[state->chunk_size - 8] = (unsigned char)(state->message_size >> 56);
	state->chunk[state->chunk_size - 7] = (unsigned char)(state->message_size >> 48);
	state->chunk[state->chunk_size - 6] = (unsigned char)(state->message_size >> 40);
	state->chunk[state->chunk_size - 5] = (unsigned char)(state->message_size >> 32);
	state->chunk[state->chunk_size - 4] = (unsigned char)(state->message_size >> 24);
	state->chunk[state->chunk_size - 3] = (unsigned char)(state->message_size >> 16);
	state->chunk[state->chunk_size - 2] = (unsigned char)(state->message_size >>  8);
	state->chunk[state->chunk_size - 1] = (unsigned char)(state->message_size >>  0);
	libsha2_process(state, state->chunk, state->chunk_size);

	n = libsha2_algorithm_output_size(state->algorithm);
	if (state->algorithm <= LIBSHA2_256) {
		for (i = 0, n /= 4; i < n; i++) {
			output[4 * i + 0] = (unsigned char)(state->h.b32[i] >> 24);
			output[4 * i + 1] = (unsigned char)(state->h.b32[i] >> 16);
			output[4 * i + 2] = (unsigned char)(state->h.b32[i] >>  8);
			output[4 * i + 3] = (unsigned char)(state->h.b32[i] >>  0);
		}
	} else {
		for (i = 0, n = (n + 7) / 8; i < n; i++) {
			output[8 * i + 0] = (unsigned char)(state->h.b64[i] >> 56);
			output[8 * i + 1] = (unsigned char)(state->h.b64[i] >> 48);
			output[8 * i + 2] = (unsigned char)(state->h.b64[i] >> 40);
			output[8 * i + 3] = (unsigned char)(state->h.b64[i] >> 32);
			output[8 * i + 4] = (unsigned char)(state->h.b64[i] >> 24);
			output[8 * i + 5] = (unsigned char)(state->h.b64[i] >> 16);
			output[8 * i + 6] = (unsigned char)(state->h.b64[i] >>  8);
			output[8 * i + 7] = (unsigned char)(state->h.b64[i] >>  0);
		}
	}
}
