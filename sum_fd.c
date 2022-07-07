/* See LICENSE file for copyright and license details. */
#include "common.h"


int
libsha2_sum_fd(int fd, enum libsha2_algorithm algorithm, void *restrict hashsum)
{
	struct libsha2_state state;
	ssize_t r;
	struct stat attr;
	size_t blksize = 4096;
	char *restrict chunk;

	if (libsha2_init(&state, algorithm) < 0)
		return -1;

	if (fstat(fd, &attr) == 0 && attr.st_blksize > 0)
		blksize = (size_t)(attr.st_blksize);

	chunk = alloca(blksize);

	for (;;) {
		r = read(fd, chunk, blksize);
		if (r <= 0) {
			if (!r)
				break;
			if (errno == EINTR)
				continue;
			return -1;
		}
		libsha2_update(&state, chunk, (size_t)r * 8);
	}

	libsha2_digest(&state, NULL, 0, hashsum);
	return 0;
}
