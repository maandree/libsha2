/* See LICENSE file for copyright and license details. */
#include "common.h"


void
libsha2_behex_upper(char *restrict output, const void *restrict hashsum_, size_t n)
{
	const unsigned char *restrict hashsum = hashsum_;
	output[2 * n] = '\0';
	while (n--) {
		output[2 * n + 0] = "0123456789ABCDEF"[(hashsum[n] >> 4) & 15];
		output[2 * n + 1] = "0123456789ABCDEF"[(hashsum[n] >> 0) & 15];
	}
}
