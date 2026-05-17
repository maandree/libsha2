/* See LICENSE file for copyright and license details. */
#include "common.h"


size_t
libsha2_hmac_unmarshal(struct libsha2_hmac_state *restrict state, const void *restrict buf_, size_t bufsize)
{
	const unsigned char *restrict buf = buf_;
	size_t off = 0;
	size_t r;
	int version;

	if (bufsize < sizeof(int)) {
		errno = EINVAL;
		return 0;
	}

	memcpy(&version, buf, sizeof(int));
	if (version != 0) {
		errno = EINVAL;
		return 0;
	}
	off += sizeof(int);

	r = libsha2_unmarshal(&state->sha2_state, &buf[off], bufsize - off);
	if (!r)
		return 0;
	off += r;

	if (bufsize - off < sizeof(size_t) + sizeof(unsigned char) + 2 * state->sha2_state.chunk_size) {
		errno = EINVAL;
		return 0;
	}

	memcpy(&state->outsize, &buf[off], sizeof(size_t));
	off += sizeof(size_t);

	state->inited = buf[off];
	off += sizeof(unsigned char);

	memcpy(state->ipad, &buf[off], state->sha2_state.chunk_size);
	off += state->sha2_state.chunk_size;

	memcpy(state->opad, &buf[off], state->sha2_state.chunk_size);
	off += state->sha2_state.chunk_size;

	return off;
}
