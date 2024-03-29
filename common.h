/* See LICENSE file for copyright and license details. */
#include "libsha2.h"

#include <sys/stat.h>
#include <alloca.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#ifndef ALLOCA_LIMIT
# define ALLOCA_LIMIT 0
#endif


/**
 * Truncate an unsigned integer to an unsigned 32-bit integer
 * 
 * @param   X:uint_least32_t  The value to truncate
 * @return  :uint_least32_t   The 32 lowest bits in `X`
 */
#define TRUNC32(X) ((X) & (uint_least32_t)0xFFFFFFFFUL)

/**
 * Truncate an unsigned integer to an unsigned 64-bit integer
 * 
 * @param   X:uint_least64_t  The value to truncate
 * @return  :uint_least64_t   The 64 lowest bits in `X`
 */
#define TRUNC64(X) ((X) & (uint_least64_t)0xFFFFFFFFFFFFFFFFULL)


/**
 * Process a chunk using SHA-2
 * 
 * @param   state  The hashing state
 * @param   data   The data to process
 * @param   len    The amount of available data
 * @return         The amount of data processed
 */
#if defined(__GNUC__)
__attribute__((__nonnull__, __nothrow__))
#endif
size_t libsha2_process(struct libsha2_state *restrict, const unsigned char *restrict, size_t);
