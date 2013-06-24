AM_CFLAGS = -I/usr/local/include -I../src -std=c99
AM_LDFLAGS = -L/usr/local/include

check_PROGRAMS = secretbox_test strongbox_test constant_time_test

secretbox_test_SOURCES = secretbox_test.c
secretbox_test_LDADD = -lcunit ../src/libcryptobox.la -lcrypto

strongbox_test_SOURCES = strongbox_test.c
strongbox_test_LDADD = -lcunit ../src/libcryptobox.la -lcrypto

constant_time_test_SOURCES = constant_time_test.c ../src/constant_time.c
constant_time_test_CFLAGS = -I../src/
constant_time_test_LDADD = -lcunit
