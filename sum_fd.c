/* See LICENSE file for copyright and license details. */
#include "common.h"


int
libsha2_sum_fd(int fd, enum libsha2_algorithm algorithm, void *restrict hashsum)
{
	struct libsha2_state state;
	ssize_t r;
#ifndef _WIN32
	struct stat attr;
#endif
	size_t blksize = 4096;
	char *restrict chunk;

	if (libsha2_init(&state, algorithm) < 0)
		return -1;

#ifndef _WIN32
	if (fstat(fd, &attr) == 0 && attr.st_blksize > 0)
		blksize = (size_t)(attr.st_blksize);
#endif

#if ALLOCA_LIMIT > 0
	if (blksize > (size_t)ALLOCA_LIMIT) {
		blksize = (size_t)ALLOCA_LIMIT;
		blksize -= blksize % sizeof(((struct libsha2_state)NULL)->chunk);
		if (!blksize)
			blksize = sizeof(((struct libsha2_state)NULL)->chunk);
	}
# if defined(__clang__)
	/* We are using a limit so it's just like declaring an array
	 * in a function, except we might use less of the stack. */
#  pragma clang diagnostic push
#  pragma clang diagnostic ignored "-Walloca"
# endif
	chunk = alloca(blksize);
# if defined(__clang__)
#  pragma clang diagnostic pop
# endif
#else
	chunk = malloc(blksize);
	if (!chunk)
		return -1;
#endif

	for (;;) {
		r = read(fd, chunk, blksize);
		if (r <= 0) {
			if (!r)
				break;
			if (errno == EINTR)
				continue;
#if ALLOCA_LIMIT <= 0
			free(chunk);
#endif
			return -1;
		}
		libsha2_update(&state, chunk, (size_t)r * 8);
	}

	libsha2_digest(&state, NULL, 0, hashsum);
#if ALLOCA_LIMIT <= 0
       free(chunk);
#endif
	return 0;
}
