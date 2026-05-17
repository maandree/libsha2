/* See LICENSE file for copyright and license details. */
#include "common.h"


size_t
libsha2_marshal(const struct libsha2_state *restrict state, void *restrict buf_)
{
	unsigned char *restrict buf = buf_;
	size_t off = 0;

	if (buf)
		memcpy(buf, &(int){1}, sizeof(int));
	off += sizeof(int);
	if (buf)
		memcpy(&buf[off], &state->algorithm, sizeof(enum libsha2_algorithm));
	off += sizeof(enum libsha2_algorithm);
	if (buf)
		memcpy(&buf[off], &state->message_size, sizeof(size_t));
	off += sizeof(size_t);

	if (state->algorithm <= LIBSHA2_256) {
		if (buf)
			memcpy(&buf[off], state->k.b32, sizeof(state->k.b32));
		off += sizeof(state->k.b32);
		if (buf)
			memcpy(&buf[off], state->h.b32, sizeof(state->h.b32));
		off += sizeof(state->h.b32);
	} else {
		if (buf)
			memcpy(&buf[off], state->k.b64, sizeof(state->k.b64));
		off += sizeof(state->k.b64);
		if (buf)
			memcpy(&buf[off], state->h.b64, sizeof(state->h.b64));
		off += sizeof(state->h.b64);
	}

	if (buf)
		memcpy(&buf[off], &state->chunk_size, sizeof(size_t));
	off += sizeof(size_t);
	if (buf)
		memcpy(&buf[off], state->chunk, (state->message_size / 8) % state->chunk_size);
	off += (state->message_size / 8) % state->chunk_size;

	return off;
}
