/* See LICENSE file for copyright and license details. */
#include "common.h"


size_t
libsha2_hmac_marshal(const struct libsha2_hmac_state *restrict state, void *restrict buf_)
{
	char *restrict buf = buf_;
	size_t off = 0;

	if (buf)
		*(int *)buf = 0; /* version */
	off += sizeof(int);

	off += libsha2_marshal(&state->sha2_state, buf ? &buf[off] : NULL);

	if (buf)
		*(size_t *)&buf[off] = state->outsize;
	off += sizeof(size_t);

	if (buf)
		*(unsigned char *)&buf[off] = state->inited;
	off += sizeof(unsigned char);

	if (buf)
		memcpy(&buf[off], state->ipad, state->sha2_state.chunk_size);
	off += state->sha2_state.chunk_size;

	if (buf)
		memcpy(&buf[off], state->opad, state->sha2_state.chunk_size);
	off += state->sha2_state.chunk_size;

	return off;
}
