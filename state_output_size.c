/* See LICENSE file for copyright and license details. */
#include "common.h"


/**
 * Get the output size of the algorithm specified for a state
 * 
 * @parma   state  The state
 * @return         The number of bytes in the output, zero on error
 */
size_t
libsha2_state_output_size(const struct libsha2_state *restrict state)
{
	return libsha2_algorithm_output_size(state->algorithm);
}
