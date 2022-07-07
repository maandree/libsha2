/* See LICENSE file for copyright and license details. */
#ifndef LIBSHA2_H
#define LIBSHA2_H  1

#include <errno.h>
#include <stdint.h>
#include <stddef.h>


/**
 * Algorithms supported by libsha2
 */
enum libsha2_algorithm {

	/**
	 * SHA-224, outputs 28 bytes
	 */
	LIBSHA2_224,

	/**
	 * SHA-256, outputs 32 bytes
	 */
	LIBSHA2_256,

	/**
	 * SHA-384, outputs 48 bytes
	 */
	LIBSHA2_384,

	/**
	 * SHA-512, outputs 64 bytes
	 */
	LIBSHA2_512,

	/**
	 * SHA-512/224, outputs 28 bytes
	 */
	LIBSHA2_512_224,

	/**
	 * SHA-512/256, outputs 32 bytes
	 */
	LIBSHA2_512_256
};

/**
 * Data structure that describes the state of a hashing process
 * 
 * Data that could just as well be allocated (with `auto`) are
 * allocated here so that is is easier to wipe the data without
 * exposing two versions of each function: one to wipe data,
 * and one not to wipe data to gain speed, now you can use use
 * `explicit_bzero` (or `memset`) when you are done.
 */
struct libsha2_state {

	/**
	 * The size of the message, as far as processed, in bits;
	 */
	size_t message_size;

	/**
	 * Round constants
	 */
	union {
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
	 * 
	 * Does not need to be marshalled
	 */
	union {
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
	union {
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
	 * 
	 * Does not need to be marshalled
	 */
	union {
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
	 * Space for chunks to process, limited
	 * to 64 bytes on 32-bit algorithms
	 */
	unsigned char chunk[128];

	/**
	 * The size of the chunks, in bytes
	 */
	size_t chunk_size;

	/**
	 * The algorithm that is used
	 */
	enum libsha2_algorithm algorithm;

	int __padding1;
};


/**
 * Data structure that describes the state of a HMAC hashing process
 * 
 * Data that could just as well be allocated (with `auto`) are
 * allocated here so that is is easier to wipe the data without
 * exposing two versions of each function: one to wipe data,
 * and one not to wipe data to gain speed, now you can use use
 * `explicit_bzero` (or `memset`) when you are done.
 */
struct libsha2_hmac_state {
	/**
	 * State of the underlaying hash function
	 */
	struct libsha2_state sha2_state;

	/**
	 * The output size of the underlaying
	 * hash algorithm, in bits
	 */
	size_t outsize;

	/**
	 * Whether `.sha2_state` has been initialised
	 * and whether the `ipad` has been feed into
	 * the algorithm
	 */
	unsigned char inited;

	/**
	 * Inner pad XOR processed key
	 */
	unsigned char ipad[128];

	/**
	 * Outer pad XOR processed key
	 */
	unsigned char opad[128];
};


/**
 * Initialise a state
 * 
 * @param   state      The state that should be initialised
 * @param   algorithm  The hashing algorithm
 * @return             Zero on success, -1 on error
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nothrow__, __nonnull__))
#endif
int libsha2_init(struct libsha2_state *restrict, enum libsha2_algorithm);

/**
 * Get the output size of an algorithm
 * 
 * @param   algorithm  The hashing algorithm
 * @return             The number of bytes in the output, zero on error
 */
#if defined(__GNUC__)
__attribute__((__warn_unused_result__, __nothrow__))
#endif
inline size_t
libsha2_algorithm_output_size(enum libsha2_algorithm algorithm__)
{
	switch (algorithm__) {
	case LIBSHA2_224:     return 28;
	case LIBSHA2_256:     return 32;
	case LIBSHA2_384:     return 48;
	case LIBSHA2_512:     return 64;
	case LIBSHA2_512_224: return 28;
	case LIBSHA2_512_256: return 32;
	default:
		errno = EINVAL;
		return 0;
	}
}

/**
 * Get the output size of the algorithm specified for a state
 * 
 * @param   state  The state
 * @return         The number of bytes in the output, zero on error
 */
#if defined(__GNUC__)
__attribute__((__warn_unused_result__, __nothrow__, __nonnull__))
#endif
inline size_t
libsha2_state_output_size(const struct libsha2_state *restrict state__)
{
	return libsha2_algorithm_output_size(state__->algorithm);
}

/**
 * Absorb more of the message
 * 
 * @param  state    The hashing state
 * @param  message  The message, in bits, must be equivalent to 0 modulus 8
 * @param  msglen   The length of the message
 */
#if defined(__GNUC__)
__attribute__((__nonnull__, __nothrow__))
#endif
void libsha2_update(struct libsha2_state *restrict, const void *restrict, size_t);

/**
 * Absorb the last part of the message and output a hash
 * 
 * @param  state    The hashing state
 * @param  message  The message, in bits
 * @param  msglen   The length of the message, zero if there is nothing more to absorb
 * @param  output   The output buffer for the hash
 */
#if defined(__GNUC__)
__attribute__((__nonnull__(1, 4), __nothrow__))
#endif
void libsha2_digest(struct libsha2_state *restrict, const void *, size_t, void *);

/**
 * Calculate the checksum for a file,
 * the content of the file is assumed non-sensitive
 * 
 * @param   fd         The file descriptor of the file
 * @param   algorithm  The hashing algorithm
 * @param   hashsum    Output buffer for the hash
 * @return             Zero on success, -1 on error
 */
#if defined(__GNUC__)
__attribute__((__nonnull__, __leaf__))
#endif
int libsha2_sum_fd(int, enum libsha2_algorithm, void *restrict);

/**
 * Convert a binary hashsum to lower case hexadecimal representation
 * 
 * @param  output   Output array, should have an allocation size of at least `2 * n + 1`
 * @param  hashsum  The hashsum to convert
 * @param  n        The size of `hashsum`
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__, __nothrow__))
#endif
void libsha2_behex_lower(char *restrict, const void *restrict, size_t);

/**
 * Convert a binary hashsum to upper case hexadecimal representation
 * 
 * @param  output   Output array, should have an allocation size of at least `2 * n + 1`
 * @param  hashsum  The hashsum to convert
 * @param  n        The size of `hashsum`
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__, __nothrow__))
#endif
void libsha2_behex_upper(char *restrict, const void *restrict, size_t);

/**
 * Convert a hexadecimal hashsum (both lower case, upper
 * case and mixed is supported) to binary representation
 * 
 * @param  output   Output array, should have an allocation
 *                  size of at least `strlen(hashsum) / 2`
 * @param  hashsum  The hashsum to convert
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__, __nothrow__))
#endif
void libsha2_unhex(void *restrict, const char *restrict);

/**
 * Marshal a state into a buffer
 * 
 * @param   state  The state to marshal
 * @param   buf    Output buffer, `NULL` to only return the required size
 * @return         The number of bytes marshalled to `buf`
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__(1), __nothrow__))
#endif
size_t libsha2_marshal(const struct libsha2_state *restrict, void *restrict);

/**
 * Unmarshal a state from a buffer
 * 
 * @param   state    Output parameter for the unmarshalled state
 * @param   buf      The buffer from which the state shall be unmarshalled
 * @param   bufsize  The maximum number of bytes that can be unmarshalled
 * @return           The number of read bytes, 0 on failure
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__, __nothrow__))
#endif
size_t libsha2_unmarshal(struct libsha2_state *restrict, const void *restrict, size_t);

/**
 * Initialise an HMAC state
 * 
 * @param   state        The state that should be initialised
 * @param   algorithm    The hashing algorithm
 * @param   key          The key
 * @param   key_length   The length of key, in bits
 * @return               Zero on success, -1 on error
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__, __nothrow__))
#endif
int libsha2_hmac_init(struct libsha2_hmac_state *restrict, enum libsha2_algorithm, const void *restrict, size_t);

/**
 * Get the output size of the algorithm specified for an HMAC state
 * 
 * @param   state  The state
 * @return         The number of bytes in the output, zero on error
 */
#if defined(__GNUC__)
__attribute__((__warn_unused_result__, __nothrow__, __nonnull__))
#endif
inline size_t
libsha2_hmac_state_output_size(const struct libsha2_hmac_state *restrict state__)
{
	return libsha2_algorithm_output_size(state__->sha2_state.algorithm);
}

/**
 * Feed data into the HMAC algorithm
 * 
 * @param  state  The state of the algorithm
 * @param  data   Data to feed into the algorithm
 * @param  n      The number of bytes to feed into the
 *                algorithm, this must be a multiple of 8
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__, __nothrow__))
#endif
void libsha2_hmac_update(struct libsha2_hmac_state *restrict, const void *restrict, size_t);

/**
 * Feed data into the HMAC algorithm and
 * get the result
 * 
 * The state of the algorithm will be reset and
 * `libsha2_hmac_update` and `libsha2_hmac_update`
 * can be called again
 * 
 * @param  state   The state of the algorithm
 * @param  data    Data to feed into the algorithm
 * @param  n       The number of bytes to feed into the algorithm
 * @param  output  The output buffer for the hash, it will be as
 *                 large as for the underlaying hash algorithm
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__, __nothrow__))
#endif
void libsha2_hmac_digest(struct libsha2_hmac_state *restrict, const void *, size_t, void *);

/**
 * Marshal an HMAC state into a buffer
 * 
 * @param   state  The state to marshal
 * @param   buf    Output buffer, `NULL` to only return the required size
 * @return         The number of bytes marshalled to `buf`
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__(1), __nothrow__))
#endif
size_t libsha2_hmac_marshal(const struct libsha2_hmac_state *restrict, void *restrict);

/**
 * Unmarshal an HMAC state from a buffer
 * 
 * @param   state    Output parameter for the unmarshalled state
 * @param   buf      The buffer from which the state shall be unmarshalled
 * @param   bufsize  The maximum number of bytes that can be unmarshalled
 * @return           The number of read bytes, 0 on failure
 */
#if defined(__GNUC__)
__attribute__((__leaf__, __nonnull__, __nothrow__))
#endif
size_t libsha2_hmac_unmarshal(struct libsha2_hmac_state *restrict, const void *restrict, size_t);


#endif
