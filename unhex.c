/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Convert a hexadecimal hashsum (both lower case, upper
 * case and mixed is supported) to binary representation
 * 
 * @param  output   Output array, should have an allocation
 *                  size of at least `strlen(hashsum) / 2`
 * @param  hashsum  The hashsum to convert
 */
void
libsha2_unhex(char *restrict output, const char *restrict hashsum)
{
	size_t n = strlen(hashsum) / 2;
	while (n--) {
		char a = hashsum[2 * n + 0];
		char b = hashsum[2 * n + 1];

		a = (char)((a & 15) + (a > '9' ? 9 : 0));
		b = (char)((b & 15) + (b > '9' ? 9 : 0));

		output[n] = (char)((a << 4) | b);
	}
}
