/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Get the output size of an algorithm
 * 
 * @param   algorithm  The hashing algorithm
 * @return             The number of bytes in the output, zero on error
 */
extern inline size_t libsha2_algorithm_output_size(enum libsha2_algorithm);
