/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Unmarshal a state from a buffer
 * 
 * @param   state    Output parameter for the unmarshalled state
 * @param   buf      The buffer from which the state shall be unmarshalled
 * @param   bufsize  The maximum number of bytes that can be unmarshalled
 * @return           The number of read bytes, 0 on failure
 */
size_t
libsha2_unmarshal(struct libsha2_state *restrict state, const char *restrict buf, size_t bufsize)
{
	size_t off = 0;

	if (bufsize < sizeof(int) + sizeof(enum libsha2_algorithm) + sizeof(size_t)) {
		errno = EINVAL;
		return 0;
	}

	if (*(const int *)buf) { /* version */
		errno = EINVAL;
		return 0;
	}
	off += sizeof(int);

	state->algorithm = *(const enum libsha2_algorithm *)&buf[off];
	off += sizeof(enum libsha2_algorithm);
	state->message_size = *(const size_t *)&buf[off];
	off += sizeof(size_t);

	switch (state->algorithm) {
	case LIBSHA2_224:
	case LIBSHA2_256:
		if (bufsize - off < sizeof(state->k.b32) + sizeof(state->w.b32) + sizeof(state->h.b32)) {
			errno = EINVAL;
			return 0;
		}
		memcpy(state->k.b32, &buf[off], sizeof(state->k.b32));
		off += sizeof(state->k.b32);
		memcpy(state->w.b32, &buf[off], sizeof(state->w.b32));
		off += sizeof(state->w.b32);
		memcpy(state->h.b32, &buf[off], sizeof(state->h.b32));
		off += sizeof(state->h.b32);
		break;

	case LIBSHA2_384:
	case LIBSHA2_512:
	case LIBSHA2_512_224:
	case LIBSHA2_512_256:
		if (bufsize - off < sizeof(state->k.b64) + sizeof(state->w.b64) + sizeof(state->h.b64)) {
			errno = EINVAL;
			return 0;
		}
		memcpy(state->k.b64, &buf[off], sizeof(state->k.b64));
		off += sizeof(state->k.b64);
		memcpy(state->w.b64, &buf[off], sizeof(state->w.b64));
		off += sizeof(state->w.b64);
		memcpy(state->h.b64, &buf[off], sizeof(state->h.b64));
		off += sizeof(state->h.b64);
		break;

	default:
		errno = EINVAL;
		return 0;
	}

	if (bufsize - off < sizeof(size_t)) {
		errno = EINVAL;
		return 0;
	}
	state->chunk_size = *(const size_t *)&buf[off];
	off += sizeof(size_t);

	if (bufsize - off < state->chunk_size) {
		errno = EINVAL;
		return 0;
	}
	memcpy(state->chunk, &buf[off], state->chunk_size);
	off += state->chunk_size;

	return off;
}
