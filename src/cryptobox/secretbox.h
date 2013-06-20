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

#ifndef __CRYPTOBOX_SECRETBOX_H__
#define __CRYPTOBOX_SECRETBOX_H__

#include <sys/types.h>


struct secretbox_box {
        unsigned char   *contents;
        int              len;
};

const size_t    SECRETBOX_KEY_SIZE = 48;
const size_t    SECRETBOX_OVERHEAD = 48;

int                      secretbox_generate_key(unsigned char *);
struct secretbox_box    *secretbox_seal(unsigned char *, int, unsigned char *);
unsigned char           *secretbox_open(struct secretbox_box *, unsigned char *);
void                     secretbox_close(struct secretbox_box *);

#endif
