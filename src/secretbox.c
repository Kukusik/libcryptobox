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
#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdio.h>

#include <cryptobox/secretbox.h>


static int       secretbox_decrypt(unsigned char *, unsigned char *,
                                   unsigned char *, int);
static int       secretbox_encrypt(unsigned char *, unsigned char *,
                                   unsigned char *, int);
static int       secretbox_generate_nonce(unsigned char *);
static int       secretbox_tag(unsigned char *, unsigned char *, int,
                               unsigned char *);
static int       secretbox_check_tag(unsigned char *, unsigned char *, int);



#define SECRETBOX_IV_SIZE	16
#define SECRETBOX_CRYPT_SIZE	16
#define SECRETBOX_TAG_SIZE	32
/*
const size_t SECRETBOX_IV_SIZE  = 16;
const size_t SECRETBOX_CRYPT_SIZE = 16;
const size_t SECRETBOX_TAG_SIZE = 32;
 */


static void
dump(unsigned char *in, int inlen)
{
	int i = 0;

	for (i = 0; i < inlen; i++) {
		printf("%02hx ", in[i]);
	}
	printf("\n");
}


/*
 * Generate a suitable key for use with secretbox. It is the caller's
 * responsibility to ensure that the key has SECRETBOX_KEY_SIZE bytes
 * available.
 */
int
secretbox_generate_key(unsigned char *key)
{
        return RAND_bytes(key, SECRETBOX_KEY_SIZE);
}


/*
 * Generate a suitable nonce. It is the caller's responsiblity to ensure
 * the nonce variable has enough space to store a 128-bit nonce.
 */
int
secretbox_generate_nonce(unsigned char *nonce)
{
        return RAND_bytes(nonce, SECRETBOX_IV_SIZE);
}


/*
 * Encrypt the plaintext input using AES-128 in CTR mode.
 */
int
secretbox_encrypt(unsigned char *key, unsigned char *in, unsigned char *out,
                  int data_len)
{
        EVP_CIPHER_CTX   crypt;
        unsigned char    nonce[SECRETBOX_IV_SIZE];
        unsigned char    cryptkey[SECRETBOX_CRYPT_SIZE];
        int              ctlen = 0;
	int		 finale = 0;
        int              res = 0;

        if (!secretbox_generate_nonce(nonce)) {
                return -1;
        }
	memcpy(out, nonce, SECRETBOX_TAG_SIZE);
        memcpy(cryptkey, key, SECRETBOX_CRYPT_SIZE);
	printf("nonce: ");
	dump(nonce, SECRETBOX_IV_SIZE);

        EVP_CIPHER_CTX_init(&crypt);
        if (EVP_EncryptInit_ex(&crypt, EVP_aes_128_ctr(), NULL, cryptkey, nonce))
        if (EVP_EncryptUpdate(&crypt, out+SECRETBOX_IV_SIZE, &ctlen, in, data_len))
        if (EVP_EncryptFinal_ex(&crypt, out+SECRETBOX_IV_SIZE+ctlen, &finale))
        if (ctlen+finale == data_len)
                res = 1;
        EVP_CIPHER_CTX_cleanup(&crypt);
        memset(cryptkey, 0x0, SECRETBOX_CRYPT_SIZE);
        return res;
}


/*
 * Compute the message tag for buffer passed in.
 */
int
secretbox_tag(unsigned char *key, unsigned char *in, int inlen,
              unsigned char *tag)
{
        unsigned char   tagkey[SECRETBOX_TAG_SIZE];
        unsigned int    md_len;
        int             res = 0;

        memcpy(tagkey, key+SECRETBOX_CRYPT_SIZE, SECRETBOX_TAG_SIZE);
	printf("tagkey: ");
	dump(tagkey, SECRETBOX_TAG_SIZE);
	printf("target: ");
	dump(in, inlen);
        tag = HMAC(EVP_sha256(), tag, SECRETBOX_TAG_SIZE, in, inlen,
                   tag, &md_len);
        memset(tagkey, 0x0, SECRETBOX_TAG_SIZE);
        if (NULL != tag)
                res = 1;
	printf("message tag: ");
	dump(tag, SECRETBOX_TAG_SIZE);
        return res;
}


/*
 * Seal a message into a box.
 */
struct secretbox_box *
secretbox_seal(unsigned char *key, unsigned char *m, int mlen)
{
        struct secretbox_box    *box = NULL;
        unsigned char           *c;
	int			 ctlen;

	ctlen = mlen+SECRETBOX_IV_SIZE;
        if (NULL == (c = malloc(mlen + OVERHEAD + 1)))
                return NULL;

        if (secretbox_encrypt(key, m, c, mlen))
        if (secretbox_tag(key, c, ctlen, c+ctlen)) {
                if (NULL != (box = malloc(sizeof(struct secretbox_box)))) {
                        box->contents = c;
                        box->len = mlen+OVERHEAD;
                }
        }

        if (NULL == box) {
                memset(c, 0, mlen+OVERHEAD);
                free(c);
        } else {
		printf("box: ");
		dump(box->contents, box->len);
	}
        return box;
}


/*
 * Decrypt the ciphertext input using AES-128 in CTR mode.
 */
int
secretbox_decrypt(unsigned char *key, unsigned char *in, unsigned char *out,
                  int data_len)
{
        EVP_CIPHER_CTX   crypt;
        unsigned char    nonce[SECRETBOX_IV_SIZE+1];
        unsigned char    cryptkey[SECRETBOX_CRYPT_SIZE+1];
        int              ptlen = 0;
        int              res = 0;
	int		 finale = 0;

        memcpy(nonce, in, SECRETBOX_IV_SIZE);
	if (0 != memcmp(nonce, in, SECRETBOX_CRYPT_SIZE))
		abort();
        memcpy(cryptkey, key, SECRETBOX_CRYPT_SIZE);
	if (0 != memcmp(cryptkey, key, SECRETBOX_CRYPT_SIZE))
		abort();

        EVP_CIPHER_CTX_init(&crypt);
        if (EVP_DecryptInit_ex(&crypt, EVP_aes_128_ctr(), NULL, cryptkey, nonce))
        if (EVP_DecryptUpdate(&crypt, out, &ptlen, in+SECRETBOX_IV_SIZE,
                              data_len))
        if (EVP_DecryptFinal_ex(&crypt, out, &finale))
        if (ptlen+finale == data_len)
                res = 1;
        EVP_CIPHER_CTX_cleanup(&crypt);
        memset(cryptkey, 0x0, SECRETBOX_CRYPT_SIZE);
        return res;
}


/*
 * Check the message tag. Returns 1 if the tags match, and 0 if
 * there is a failure.
 */
int
secretbox_check_tag(unsigned char *key, unsigned char *in, int inlen)
{
        unsigned char    tagkey[SECRETBOX_TAG_SIZE];
        unsigned char    tag[SECRETBOX_TAG_SIZE];
        unsigned char    atag[SECRETBOX_TAG_SIZE];
        int              msglen = 0;
        int              match = 0;

        msglen = inlen - SECRETBOX_TAG_SIZE;
	printf("message length: %d\n", msglen);
	printf("%d = %d - %d\n", msglen, inlen, SECRETBOX_TAG_SIZE);
        memcpy(tagkey, key+SECRETBOX_CRYPT_SIZE, SECRETBOX_TAG_SIZE);
        memcpy(tag, in+msglen, SECRETBOX_TAG_SIZE);
        if (secretbox_tag(key, in, msglen, atag)) {
		if (memcmp(atag, tag, SECRETBOX_TAG_SIZE) == 0) {
			match = 1;
		} else {
			printf("memcmp fails\n");
			printf("atag: ");
			dump(atag, SECRETBOX_TAG_SIZE);
			printf("tag: ");
			dump(tag, SECRETBOX_TAG_SIZE);
		}
	} else {
		printf("failed to compute tag\n");
	}
        memset(tagkey, 0, SECRETBOX_TAG_SIZE);
        return match;
}


/*
 * Recover the message from a box.
 */
unsigned char *
secretbox_open(unsigned char *key, struct secretbox_box *box)
{
        unsigned char   *message = NULL;
	int		 decryptlen = 0;

	if (box == NULL)
		return NULL;
	decryptlen = (box->len) - OVERHEAD;
        if (NULL != (message = malloc(decryptlen + 1))) {
		if (secretbox_decrypt(key, box->contents, message, decryptlen)) {
			if (secretbox_check_tag(key, box->contents, box->len)) {
				return message;
			} else {
				printf("tag check fails\n");
			}
		} else {
			printf("decrypt fails\n");
		}
	} else {
		printf("malloc fails\n");
	}
        if (NULL != message)
                memset(message, 0, decryptlen+1);
        free(message);
        return NULL;
}
