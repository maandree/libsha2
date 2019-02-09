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
	state_initialise.o\
	state_output_size.o\
	sum_fd.o\
	unhex.o\
	update.o\


all: libsha2.a libsha2.$(LIBEXT)
$(OBJ): $(@:.o=.c) $(HDR)
$(OBJ:.o=.lo): $(@:.lo=.c) $(HDR)

.c.o:
	$(CC) -c -o $@ $< $(CFLAGS)

.c.lo:
	$(CC) -fPIC -c -o $@ $< $(CFLAGS)

libsha2.$(LIBEXT): $(OBJ)
	$(CC) $(LIBFLAGS) -o $@ $(OBJ) $(LDFLAGS)

libsha2.a: $(OBJ)
	-rm -f -- $@
	$(AR) rc $@ $?
	$(AR) -s $@

clean:
	-rm -f -- *.o *.lo *.su *.a *.so

.SUFFIXES:
.SUFFIXES: .lo .o .c

.PHONY: all check install uninstall clean
