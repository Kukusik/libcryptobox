AM_CFLAGS  = -Wall -Wextra -pedantic -Wshadow -Wpointer-arith -Wcast-align
AM_CFLAGS += -Wwrite-strings -Wmissing-prototypes -Wmissing-declarations
AM_CFLAGS += -Wnested-externs -Winline -Wno-long-long
AM_CFLAGS += -Wstrict-prototypes -Werror -ansi -O2
AM_CFLAGS += -D_BSD_SOURCE -D_XOPEN_SOURCE=700

# AM_CFLAGS  = -Werror -Wall -ansi
# AM_CFLAGS += -g

lib_LTLIBRARIES = libcryptobox.la
libcryptobox_la_SOURCES = secretbox.c
libcryptobox_la_INCLUDES = cryptobox/secretbox.h
