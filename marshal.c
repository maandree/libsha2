/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Marshal a state into a buffer
 * 
 * @param   state  The state to marshal
 * @param   buf    Output buffer, `NULL` to only return the required size
 * @return         The number of bytes marshalled to `buf`
 */
size_t
libsha2_marshal(const struct libsha2_state *restrict state, char *restrict buf)
{
	size_t off = 0;

	if (buf)
		*(int *)buf = 0; /* version */
	off += sizeof(int);
	if (buf)
		*(enum libsha2_algorithm *)&buf[off] = state->algorithm;
	off += sizeof(enum libsha2_algorithm);
	if (buf)
		*(size_t *)&buf[off] = state->message_size;
	off += sizeof(size_t);

	if (state->algorithm <= LIBSHA2_256) {
		if (buf)
			memcpy(&buf[off], state->k.b32, sizeof(state->k.b32));
		off += sizeof(state->k.b32);
		if (buf)
			memcpy(&buf[off], state->w.b32, sizeof(state->w.b32));
		off += sizeof(state->w.b32);
		if (buf)
			memcpy(&buf[off], state->h.b32, sizeof(state->h.b32));
		off += sizeof(state->h.b32);
	} else {
		if (buf)
			memcpy(&buf[off], state->k.b64, sizeof(state->k.b64));
		off += sizeof(state->k.b64);
		if (buf)
			memcpy(&buf[off], state->w.b64, sizeof(state->w.b64));
		off += sizeof(state->w.b64);
		if (buf)
			memcpy(&buf[off], state->h.b64, sizeof(state->h.b64));
		off += sizeof(state->h.b64);
	}

	if (buf)
		memcpy(&buf[off], state->chunk, sizeof(state->chunk));
	off += sizeof(state->chunk);
	if (buf)
		*(size_t *)&buf[off] = state->chunk_size;
	off += sizeof(size_t);

	return off;
}
