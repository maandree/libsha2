.POSIX:

CONFIGFILE = config.mk
include $(CONFIGFILE)

OS = linux
# Linux:   linux
# Mac OS:  macos
# Windows: windows
include mk/$(OS).mk


LIB_MAJOR = 1
LIB_MINOR = 0
LIB_VERSION = $(LIB_MAJOR).$(LIB_MINOR)


HDR =\
	libsha2.h\
	common.h

OBJ =\
	algorithm_output_size.o\
	behex_lower.o\
	behex_upper.o\
	digest.o\
	hmac_digest.o\
	hmac_init.o\
	hmac_marshal.o\
	hmac_state_output_size.o\
	hmac_unmarshal.o\
	hmac_update.o\
	init.o\
	marshal.o\
	process.o\
	state_output_size.o\
	sum_fd.o\
	unhex.o\
	unmarshal.o\
	update.o

MAN0 =\
	libsha2.h.0

MAN3 =\
	libsha2_algorithm_output_size.3\
	libsha2_behex_lower.3\
	libsha2_behex_upper.3\
	libsha2_digest.3\
	libsha2_hmac_digest.3\
	libsha2_hmac_init.3\
	libsha2_hmac_marshal.3\
	libsha2_hmac_state_output_size.3\
	libsha2_hmac_unmarshal.3\
	libsha2_hmac_update.3\
	libsha2_init.3\
	libsha2_marshal.3\
	libsha2_state_output_size.3\
	libsha2_sum_fd.3\
	libsha2_unhex.3\
	libsha2_unmarshal.3\
	libsha2_update.3

LOBJ = $(OBJ:.o=.lo)


all: libsha2.a libsha2.$(LIBEXT) test
$(OBJ): $(HDR)
$(LOBJ): $(HDR)

.c.o:
	$(CC) -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

.c.lo:
	$(CC) -fPIC -c -o $@ $< $(CFLAGS) $(CPPFLAGS)

test: test.o libsha2.a
	$(CC) -o $@ test.o libsha2.a $(LDFLAGS)

libsha2.$(LIBEXT): $(LOBJ)
	$(CC) $(LIBFLAGS) -o $@ $(LOBJ) $(LDFLAGS)

libsha2.a: $(OBJ)
	-rm -f -- $@
	$(AR) rc $@ $(OBJ)
	$(AR) -s $@

check: test
	./test

install:
	mkdir -p -- "$(DESTDIR)$(PREFIX)/lib"
	mkdir -p -- "$(DESTDIR)$(PREFIX)/include"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man0"
	mkdir -p -- "$(DESTDIR)$(MANPREFIX)/man3"
	cp -- libsha2.a "$(DESTDIR)$(PREFIX)/lib"
	cp -- libsha2.$(LIBEXT) "$(DESTDIR)$(PREFIX)/lib/libsha2.$(LIBMINOREXT)"
	$(FIX_INSTALL_NAME) "$(DESTDIR)$(PREFIX)/lib/libsha2.$(LIBMINOREXT)"
	ln -sf -- "libsha2.$(LIBMINOREXT).$(LIB_MINOR)" "$(DESTDIR)$(PREFIX)/lib/libsha2.$(LIBMAJOREXT)"
	ln -sf -- "libsha2.$(LIBMAJOREXT)" "$(DESTDIR)$(PREFIX)/lib/libsha2.$(LIBEXT)"
	cp -- libsha2.h "$(DESTDIR)$(PREFIX)/include"
	cp -- $(MAN0) "$(DESTDIR)$(MANPREFIX)/man0"
	cp -- $(MAN3) "$(DESTDIR)$(MANPREFIX)/man3"

uninstall:
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsha2.a"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsha2.$(LIBEXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsha2.$(LIBMAJOREXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/lib/libsha2.$(LIBMINOREXT)"
	-rm -f -- "$(DESTDIR)$(PREFIX)/include/libsha2.h"
	-cd -- "$(DESTDIR)$(MANPREFIX)/man0" && rm -f -- $(MAN0)
	-cd -- "$(DESTDIR)$(MANPREFIX)/man3" && rm -f -- $(MAN3)

clean:
	-rm -f -- *.o *.lo *.su *.a *.$(LIBEXT) test

.SUFFIXES:
.SUFFIXES: .lo .o .c

.PHONY: all check install uninstall clean
