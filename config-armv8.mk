PREFIX    = /usr
MANPREFIX = $(PREFIX)/share/man

CC = cc -std=c11

CPPFLAGS = -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700
CFLAGS   = -Wall -O3 -march=native
# If you cannot use -march=native, you should do e.g -march=armv8-a+crypto
# however, you have to be careful selecting the exact version,
# so you may have to replace armv8-a with something else.
LDFLAGS  = -s

# You can add -DALLOCA_LIMIT=# to CPPFLAGS, where # is a size_t
# value, to put a limit on how large allocation the library is
# allowed to make with alloca(3). For buffers that can have any
# size this limit will be used if it wants to allocate a larger
# buffer. Choose 0 to use malloc(3) instead of alloca(3).
