/* See LICENSE file for copyright and license details. */
#include "common.h"


size_t
libsha2_hmac_marshal(const struct libsha2_hmac_state *restrict state, void *restrict buf_)
{
	unsigned char *restrict buf = buf_;
	size_t off = 0;

	if (buf)
		memcpy(buf, &(int){0}, sizeof(int)); /* version */
	off += sizeof(int);

	off += libsha2_marshal(&state->sha2_state, buf ? &buf[off] : NULL);

	if (buf)
		memcpy(&buf[off], &state->outsize, sizeof(size_t));
	off += sizeof(size_t);

	if (buf)
		buf[off] = state->inited;
	off += sizeof(unsigned char);

	if (buf)
		memcpy(&buf[off], state->ipad, state->sha2_state.chunk_size);
	off += state->sha2_state.chunk_size;

	if (buf)
		memcpy(&buf[off], state->opad, state->sha2_state.chunk_size);
	off += state->sha2_state.chunk_size;

	return off;
}
