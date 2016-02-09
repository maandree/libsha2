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
#include "libsha2-config.h"
#include "files.h"
#include "digest.h"
#include <stddef.h>
#include <unistd.h>
#include <sys/stat.h>
#include <alloca.h>
#include <errno.h>



/**
 * Calculate the checksum for a file,
 * the content of the file is assumed non-sensitive
 * 
 * @param   fd         The file descriptor of the file
 * @param   algorithm  The hashing algorithm
 * @param   hashsum    Output buffer for the hash
 * @return             Zero on success, -1 on error
 */
int libsha2_sum_fd(int fd, libsha2_algorithm_t algorithm, char* restrict hashsum)
{
  libsha2_state_t state;
  ssize_t got;
  struct stat attr;
  size_t blksize = 4096;
  char* restrict chunk;
  
  if (libsha2_state_initialise(&state, algorithm) < 0)
    return -1;
  
  if (fstat(fd, &attr) == 0)
    if (attr.st_blksize > 0)
      blksize = (size_t)(attr.st_blksize);
  
  chunk = alloca(blksize);
  
  for (;;)
    {
      got = read(fd, chunk, blksize);
      if (got < 0)
	{
	  if (errno == EINTR)
	    continue;
	  return -1;
	}
      if (got == 0)
	break;
      libsha2_update(&state, chunk, (size_t)got);
    }
  
  libsha2_digest(&state, NULL, 0, hashsum);
  return 0;
}

