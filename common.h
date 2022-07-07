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
 * Process a chunk using SHA-2
 * 
 * @param  state  The hashing state
 * @param  chunk  The data to process
 */
#if defined(__GNUC__)
__attribute__((__nonnull__, __nothrow__))
#endif
void libsha2_process(struct libsha2_state *restrict, const unsigned char *restrict);
