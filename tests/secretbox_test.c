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

	box = secretbox_seal(test_key, test_msg, strlen(test_msg));
	CU_ASSERT(box != NULL);
	test_decrypted = secretbox_open(test_key, box);
	CU_ASSERT(NULL != test_decrypted && 0 == memcmp(test_decrypted,
		  test_msg, strlen(test_msg)));
	printf("decrypted: %s\n", (char *)test_decrypted);
	free(test_decrypted);
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

	if (NULL == CU_add_test(tsuite, "basic checks", test_identity))
		fireball();

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
