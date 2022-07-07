/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Get the output size of the algorithm specified for a HMAC state
 * 
 * @param   state  The state
 * @return         The number of bytes in the output, zero on error
 */
extern inline size_t libsha2_hmac_state_output_size(const struct libsha2_hmac_state *restrict);
