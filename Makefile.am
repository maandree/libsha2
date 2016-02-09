ACLOCAL_AMFLAGS = -I build-aux/m4

lib_LTLIBRARIES = libsha2.la
include_HEADERS = src/libsha2.h
pkginclude_HEADERS  = src/libsha2/digest.h
pkginclude_HEADERS += src/libsha2/files.h
pkginclude_HEADERS += src/libsha2/hex.h
pkginclude_HEADERS += src/libsha2/state.h
noinst_HEADERS =

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libsha2.pc

libsha2_la_SOURCES  = src/libsha2/digest.c
libsha2_la_SOURCES += src/libsha2/files.c
libsha2_la_SOURCES += src/libsha2/hex.c
libsha2_la_SOURCES += src/libsha2/state.c

EXTRA_DIST = autogen.sh
