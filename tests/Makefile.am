AM_CFLAGS = -I/usr/local/include -I../src -std=c99 
AM_LDFLAGS = -L/usr/local/lib

check_PROGRAMS = secretbox_test strongbox_test

secretbox_test_SOURCES = secretbox_test.c
secretbox_test_LDADD = -lcunit ../src/libcryptobox.la -lcrypto

strongbox_test_SOURCES = strongbox_test.c
strongbox_test_LDADD = -lcunit ../src/libcryptobox.la -lcrypto
