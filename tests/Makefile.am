AM_CFLAGS = -I/usr/local/include -I../src -ansi
AM_LDFLAGS = -L/usr/local/include

check_PROGRAMS = secretbox_test
secretbox_test_SOURCES = secretbox_test.c
secretbox_test_LDADD = -lcunit ../src/libcryptobox.la -lcrypto
