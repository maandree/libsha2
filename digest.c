/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Absorb the last part of the message and output a hash
 * 
 * @param  state    The hashing state
 * @param  message  The message, in bits
 * @param  msglen   The length of the message, zero if there is nothing more to absorb
 * @param  output   The output buffer for the hash
 */
void
libsha2_digest(struct libsha2_state *restrict state, const char *restrict message, size_t msglen, char *output)
{
	char *appendix;
	size_t i, j, k, n;

	if (msglen & ~7) {
		libsha2_update(state, message, msglen & ~7);
		message += msglen & ~7;
		msglen &= 7;
	}

	k = 8 * state->chunk_size;
	n = state->chunk_size + 8;
	n = (k + (n % k)) % k;
	n = n / 8 - 1;

	appendix = state->appendix;
	if (msglen) {
		j = 7 - msglen;
		*appendix = *message;
		*appendix |= 1 << j;
		*appendix &= ~((1 << j) - 1);
	} else {
		*appendix = (unsigned char)128;
	}

	k = state->message_size + msglen;
	i = state->chunk_size / 8;
	appendix += n + i - 1;
	for (i = i < sizeof(size_t) ? i : sizeof(size_t); i--;)
		*(appendix - i) = (unsigned char)((k >> (i * 8)) & 255);

	n += state->chunk_size;
	libsha2_update(state, state->appendix, n);

	n = libsha2_algorithm_output_size(state->algorithm);
	switch (state->algorithm) {
	case LIBSHA2_224:
	case LIBSHA2_256:
		for (i = 0; i < 8; i++)
			for (j = 0; j < (state->chunk_size / 16); j++)
				if (k = (i + 1) * (state->chunk_size / 16) - j - 1, k < n)
					output[k] = (char)((state->h.b32[i] >> (8 * j)) & 255);
		break;

	default:
		for (i = 0; i < 8; i++)
			for (j = 0; j < (state->chunk_size / 16); j++)
				if (k = (i + 1) * (state->chunk_size / 16) - j - 1, k < n)
					output[k] = (char)((state->h.b64[i] >> (8 * j)) & 255);
		break;
	}
}
