/*
 * Copyright (c) 2013 by Kyle Isom <kyle@tyrfingr.is>.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

#include <sys/types.h>
#include <stdio.h>
#include "constant_time.h"


/*
 * Compare two bytes (unsigned char), and return 1 if they are equal.
 */
int
constant_time_byte_compare(unsigned char a, unsigned char b)
{
	unsigned char	c;

	c = ~(a ^ b);
	c &= (c >> 4);
	c &= (c >> 2);
	c &= (c >> 1);

	return (int)c;
}


/*
 * Compare two unsigned character arrays, and return 1 if they match. The
 * time taken by the comparison is dependent only on the length of the
 * arrays.
 */
int
constant_time_equals(unsigned char *a, int alen, unsigned char *b, int blen)
{
	size_t	i = 0;
	size_t	n = 0;
	int	eq = 0;
	int	c1, c2;

	n = alen;
	if (n > blen)
		n = blen;

	for (i = 0; i < n; i++)
		eq += constant_time_byte_compare(a[i], b[i]);
	c1 = constant_time_int_compare(alen, blen);
	c2 = constant_time_int_compare(eq, alen);

	return c1 && c2;
}


/*
 * Compare two integers, and return 1 if the two are equal.
 */
int
constant_time_int_compare(int a, int b)
{
	int div = 0;
	int c = 0;

	div = sizeof(int) * 8;
	c = ~(a ^ b);
	while (1) {
		div /= 2;
		c &= c >> div;
		if (div <= 1)
			break;
	}
	return c & 1;
}
