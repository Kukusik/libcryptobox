AM_CFLAGS  = -Wall -Wextra -pedantic -Wshadow -Wpointer-arith -Wcast-align
AM_CFLAGS += -Wwrite-strings -Wmissing-prototypes -Wmissing-declarations
AM_CFLAGS += -Wnested-externs -Winline -Wno-long-long
AM_CFLAGS += -Wstrict-prototypes -Werror -std=c99 -O2
AM_CFLAGS += -D_BSD_SOURCE -D_XOPEN_SOURCE=700

lib_LTLIBRARIES = libcryptobox.la
nobase_include_HEADERS = cryptobox/secretbox.h cryptobox/strongbox.h
libcryptobox_la_SOURCES = secretbox.c strongbox.c constant_time.c
