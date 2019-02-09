.NONPOSIX:

CONFIGFILE = config.mk

LIB_MAJOR = 1
LIB_MINOR = 0
LIB_VERSION = $(LIB_MAJOR).$(LIB_MINOR)

LIBEXT = so
LIBFLAGS = -shared -Wl,-soname,libsha2.$(LIBEXT).$(LIB_MAJOR)

include $(CONFIGFILE)


HDR =\
	libsha2.h\
	common.h

OBJ =\
	algorithm_output_size.o\
	behex_lower.o\
	behex_upper.o\
	digest.o\
	init.o\
	marshal.o\
	state_output_size.o\
	sum_fd.o\
	unhex.o\
	unmarshal.o\
	update.o\

MAN0 =\
	libsha2.h.0

MAN3 =\
	libsha2_algorithm_output_size.3\
	libsha2_behex_lower.3\
	libsha2_behex_upper.3\
	libsha2_digest.3\
	libsha2_marshal.3\
	libsha2_init.3\
	libsha2_state_output_size.3\
	libsha2_sum_fd.3\
	libsha2_unhex.3\
	libsha2_unmarshal.3\
	libsha2_update.3


all: libsha2.a libsha2.$(LIBEXT)
$(OBJ): $(@:.o=.c) $(HDR)
$(OBJ:.o=.lo): $(@:.lo=.c) $(HDR)

.c.o:
	$(CC) -c -o $@ $< $(CFLAGS)

.c.lo:
	$(CC) -fPIC -c -o $@ $< $(CFLAGS)

libsha2.$(LIBEXT): $(OBJ:.o=.lo)
	$(CC) $(LIBFLAGS) -o $@ $(OBJ) $(LDFLAGS)

libsha2.a: $(OBJ)
	-rm -f -- $@
	$(AR) rc $@ $?
	$(AR) -s $@

install:
	mkdir -p -- "$(DESTDIR)$(PREFIX)/lib"
	mkdir -p -- "$(DESTDIR)$(PREFIX)/include"
	mkdir -p -- "$(DESTDIR)$(PREFIX)/share/licenses/libsha2"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man0"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man3"
	cp -- libsha2.a "$(DESTDIR)$(PREFIX)/lib"
	cp -- libsha2.$(LIBEXT) "$(DESTDIR)$(PREFIX)/lib/libsha2.$(LIBEXT).$(LIB_MAJOR).$(LIB_MINOR)"
	ln -sf -- "libsha2.$(LIBEXT).$(LIB_MAJOR).$(LIB_MINOR)" "$(DESTDIR)$(PREFIX)/lib/libsha2.$(LIBEXT).$(LIB_MAJOR)"
	ln -sf -- "libsha2.$(LIBEXT).$(LIB_MAJOR)" "$(DESTDIR)$(PREFIX)/lib/libsha2.$(LIBEXT)"
	cp -- libsha2.h "$(DESTDIR)$(PREFIX)/include"
	cp -- $(MAN0) "$(DESTDIR)$(MANPREFIX)/man0"
	cp -- $(MAN3) "$(DESTDIR)$(MANPREFIX)/man3"
	cp -- LICENSE "$(DESTDIR)$(PREFIX)/share/licenses/libsha2"

uninstall:
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsha2.a"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsha2.$(LIBEXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsha2.$(LIBEXT).$(LIB_MAJOR)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsha2.$(LIBEXT).$(LIB_MAJOR).$(LIB_MINOR)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/include/libsha2.h"
	-cd -- "$(DESTDIR)$(MANPREFIX)/man0" && rm -f -- $(MAN0)
	-cd -- "$(DESTDIR)$(MANPREFIX)/man3" && rm -f -- $(MAN3)
	-rm -rf -- "$(DESTDIR)$(PREFIX)/share/licenses/libsha2"

clean:
	-rm -f -- *.o *.lo *.su *.a *.so

.SUFFIXES:
.SUFFIXES: .lo .o .c

.PHONY: all check install uninstall clean
