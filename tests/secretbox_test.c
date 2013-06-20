/*
 * Copyright (c) 2013 Kyle Isom <kyle@tyrfingr.is>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA
 * OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 * ---------------------------------------------------------------------
 */


#include <sys/types.h>
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>


#define SHARED_KEY_LEN		32
#include <cryptobox/secretbox.h>

int no_continue = 0;

static void
print_buf(unsigned char *buf, size_t len)
{
	int		 i;

	for (i = 0; i  < len; i++) {
		if (i % 8 == 0)
			printf("\n\t");
		printf("%02hx ", buf[i]);
	}
	printf("\n");
}


static void
test_tag(void)
{
        unsigned char message[] = {0x01, 0x02, 0x03, 0x04};
	unsigned char test_key[] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	};
        unsigned char etag[] = {
                0x32, 0x53, 0xde, 0x02, 0x69, 0xab, 0x6f, 0x82,
                0x8e, 0xf2, 0xa4, 0x89, 0x5b, 0x15, 0xd8, 0x6b,
                0xb4, 0x7b, 0x57, 0x2f, 0x89, 0x88, 0xc6, 0x18,
                0x2b, 0xfd, 0xc5, 0x45, 0x35, 0xdb, 0x56, 0xce
        };
        unsigned char tag[32];
        CU_ASSERT(0 == memcmp(tag, etag, 32));

}


static void
test_identity(void)
{
	unsigned char test_key[] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	};
	unsigned char test_msg[] = {
		0x68, 0x65, 0x6c, 0x6c, 0x6f
	};

	struct secretbox_box	*box = NULL;
	unsigned char		*test_decrypted;

	box = secretbox_seal(test_key, test_msg, sizeof(test_msg));
	CU_ASSERT(box != NULL);
	test_decrypted = secretbox_open(test_key, box);
	CU_ASSERT(NULL != test_decrypted && 0 == memcmp(test_decrypted,
		  test_msg, strlen(test_msg)));
	printf("  message: %s\n", (char *)test_msg);
	printf("decrypted: %s\n", (char *)test_decrypted);
	free(test_decrypted);
}


static void
test_decrypt(void)
{
        unsigned char test_box[] = {
                0x81, 0xe1, 0x1c, 0xa2, 0xa0, 0x27, 0x8a, 0x99,
                0xed, 0xcf, 0xa7, 0xd0, 0xc9, 0x2c, 0x07, 0x40,
                0x2e, 0xf7, 0x27, 0xcc, 0x9d, 0xde, 0x2b, 0x21,
                0x6c, 0xc8, 0x97, 0x40, 0xfd, 0x57, 0xa7, 0xe0,
                0xec, 0x87, 0x78, 0x42, 0x8e, 0x81, 0x86, 0xef,
                0x61, 0xbb, 0xad, 0xbf, 0x17, 0xed, 0x12, 0x6e,
                0x53, 0x34, 0xb4, 0x5e, 0xe6
        };
        int test_box_len = 53;

        unsigned char test_key[] = {
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	};

        unsigned char           *msg = NULL;
        struct secretbox_box    *box = NULL;

        printf("\n\n*** can we open a pre-built box? ***\n");
        box = malloc(sizeof(struct secretbox_box));
        box->contents = malloc(test_box_len+1);
        box->len = test_box_len;
        memcpy(box->contents, test_box, box->len);

        msg = secretbox_open(test_key, box);
        CU_ASSERT(msg != NULL);
        if (NULL != msg) {
                printf("message: %s\n", msg);
                free(msg);
        }
}


/*
 * init_test is called each time a test is run, and cleanup is run after
 * every test.
 */
int init_test(void)
{
	return 0;
}

int cleanup_test(void)
{
	return 0;
}


/*
 * fireball is the code called when adding test fails: cleanup the test
 * registry and exit.
 */
void
fireball(void)
{
	int	error = 0;

	error = CU_get_error();
	if (error == 0)
		error = -1;

	fprintf(stderr, "fatal error in tests\n");
	CU_cleanup_registry();
	exit(error);
}


/*
 * The main function sets up the test suite, registers the test cases,
 * runs through them, and hopefully doesn't explode.
 */
int
main(void)
{
	CU_pSuite       tsuite = NULL;
	unsigned int    fails;

	if (!(CUE_SUCCESS == CU_initialize_registry())) {
		errx(EX_CONFIG, "failed to initialise test registry");
		return EXIT_FAILURE;
	}

	tsuite = CU_add_suite("secretbox_test", init_test, cleanup_test);
	if (NULL == tsuite)
		fireball();

	if (NULL == CU_add_test(tsuite, "tagging", test_tag))
		fireball();
	if (NULL == CU_add_test(tsuite, "opening box", test_decrypt))
		fireball();
        /*
	if (NULL == CU_add_test(tsuite, "basic checks", test_identity))
		fireball();
         */

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	fails = CU_get_number_of_tests_failed();
	warnx("%u tests failed", fails);

	CU_cleanup_registry();
	return fails;
}


/*
 * This is an empty test provided for reference.
 */
void
empty_test()
{
	CU_ASSERT(1 == 0);
}
