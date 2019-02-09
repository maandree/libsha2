/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Get the output size of an algorithm
 * 
 * @parma   algorithm  The hashing algorithm
 * @return             The number of bytes in the output, zero on error
 */
size_t
libsha2_algorithm_output_size(enum libsha2_algorithm algorithm)
{
	switch (algorithm) {
	case LIBSHA2_224:     return 28;
	case LIBSHA2_256:     return 32;
	case LIBSHA2_384:     return 48;
	case LIBSHA2_512:     return 64;
	case LIBSHA2_512_224: return 28;
	case LIBSHA2_512_256: return 32;
	default:
		errno = EINVAL;
		return 0;
	}
}
