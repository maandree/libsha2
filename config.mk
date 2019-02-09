PREFIX    = /usr
MANPREFIX = $(PREFIX)/share/man

CPPFLAGS = -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700
CFLAGS   = -std=c99 -Wall -Wextra -O3 $(CPPFLAGS)
LDFLAGS  = -s

LIBEXT   = so
LIBFLAGS = -shared -Wl,-soname,libsha2.$(LIBEXT).$(LIB_MAJOR)
