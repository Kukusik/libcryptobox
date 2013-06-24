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


#include "constant_time.h"


static void
test_byte_compare(void)
{
	unsigned char i, j;

	for (i = 0; i < 2; i ++) {
		for (j = 0; j < 2 ; j++) {
			if (i == j) {
				CU_ASSERT(1 == constant_time_byte_compare(i, j));
			} else {
				CU_ASSERT(1 != constant_time_byte_compare(i, j));
			}
		}
	}
}

static void
test_equals(void)
{
	unsigned char	test1[] = "Hello, world.";
	unsigned char	test2[] = "Hello, world";
	int		t1len = sizeof test1;
	int		t2len = sizeof test2;

	CU_ASSERT(1 == constant_time_equals(test1, t1len, test1, t1len));
	CU_ASSERT(1 != constant_time_equals(test1, t1len, test2, t2len));
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

	tsuite = CU_add_suite("constant_time_test", init_test, cleanup_test);
	if (NULL == tsuite)
		fireball();

	if (NULL == CU_add_test(tsuite, "constant_time_byte_compare",
		test_byte_compare))
		fireball();

	if (NULL == CU_add_test(tsuite, "constant_time_equals", test_equals))
		fireball();

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	fails = CU_get_number_of_tests_failed();
	warnx("%u tests failed", fails);

	CU_cleanup_registry();
	return fails;
}
