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
#ifndef LIBSHA2_FILES_H
#define LIBSHA2_FILES_H  1


#include "state.h"


/**
 * Calculate the checksum for a file,
 * the content of the file is assumed non-sensitive
 * 
 * @param   fd         The file descriptor of the file
 * @param   algorithm  The hashing algorithm
 * @param   hashsum    Output buffer for the hash
 * @return             Zero on success, -1 on error
 */
__attribute__((nonnull, leaf))
int libsha2_sum_fd(int fd, libsha2_algorithm_t algorithm, char* restrict hashsum);


#endif

