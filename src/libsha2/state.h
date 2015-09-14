/**
 * libsha2 – SHA-2-family hashing library
 * 
 * Copyright © 2015  Mattias Andrée (maandree@member.fsf.org)
 * 
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef LIBSHA2_STATE_H
#define LIBSHA2_STATE_H  1


#include <stdint.h>
#include <stddef.h>



/**
 * Algorithms supported by libsha2
 */
typedef enum libsha2_algorithm
  {
    /**
     * SHA-224, outputs 28 bytes
     */
    LIBSHA2_224 = 1,
    
    /**
     * SHA-256, outputs 32 bytes
     */
    LIBSHA2_256 = 2,
    
    /**
     * SHA-384, outputs 48 bytes
     */
    LIBSHA2_384 = 3,
    
    /**
     * SHA-512, outputs 64 bytes
     */
    LIBSHA2_512 = 4,
    
    /**
     * SHA-512/224, outputs 28 bytes
     */
    LIBSHA2_512_224 = 5,
    
    /**
     * SHA-512/256, outputs 32 bytes
     */
    LIBSHA2_512_256 = 6,
    
  } libsha2_algorithm_t;


/**
 * Datastructure that describes the state of a hashing process
 * 
 * Data that could just as well be allocated (with `auto`) are
 * allocated here so that is is easier to wipe the data without
 * exposing two versions of each function: one to wipe data,
 * and one not to wipe data to gain speed, now you can use use
 * `explicit_bzero` (or `memset`) when you are done.
 */
typedef struct libsha2_state
{
  /**
   * The size of the message, as far as processed, in bits;
   */
  size_t message_size;
  
  /**
   * Round constants
   */
  union
  {
    /**
     * For 32-bit algorithms
     */
    uint32_t b32[64];
    
    /**
     * For 64-bit algorithms
     */
    uint64_t b64[80];
    
  } k;
  
  /**
   * Words
   */
  union
  {
    /**
     * For 32-bit algorithms
     */
    uint32_t b32[64];
    
    /**
     * For 64-bit algorithms
     */
    uint64_t b64[80];
    
  } w;
  
  /**
   * Hashing values
   */
  union
  {
    /**
     * For 32-bit algorithms
     */
    uint32_t b32[8];
    
    /**
     * For 64-bit algorithms
     */
    uint64_t b64[8];
    
  } h;
  
  /**
   * Temporary hashing values
   */
  union
  {
    /**
     * For 32-bit algorithms
     */
    uint32_t b32[8];
    
    /**
     * For 64-bit algorithms
     */
    uint64_t b64[8];
    
  } work_h;
  
  /**
   * Space for chunks to process
   */
  union
  {
    /**
     * For 32-bit algorithms
     */
    unsigned char b32[64];
    
    /**
     * For 64-bit algorithms
     */
    unsigned char b64[128];
    
  } chunk;
  
  /**
   * Output buffer, required because
   * some algorithms truncate the output
   */
  char output[64];
  
  /**
   * The algorithm that is used
   */
  libsha2_algorithm_t algorithm;
  
} libsha2_state_t;



/**
 * Initialise a state
 * 
 * @parma   state      The state that should be initialised
 * @parma   algorithm  The hashing algorithm
 * @return             Zero on success, -1 on error
 */
__attribute__((leaf, nothrow, nonnull))
int libsha2_state_initialise(libsha2_state_t* restrict state, libsha2_algorithm_t algorithm);

/**
 * Get the output size of the algorithm specified for a state
 * 
 * @parma   state  The state
 * @return         The number of bytes in the output, zero on error
 */
__attribute__((nothrow, nonnull, pure))
size_t libsha2_state_output_size(const libsha2_state_t* restrict state);

/**
 * Get the output size of an algorithm
 * 
 * @parma   algorithm  The hashing algorithm
 * @return             The number of bytes in the output, zero on error
 */
__attribute__((leaf, nothrow, const))
size_t libsha2_algorithm_output_size(libsha2_algorithm_t algorithm);



#endif

