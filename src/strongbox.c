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

#include <cryptobox/strongbox.h>


static int       strongbox_decrypt(unsigned char *, unsigned char *,
                                   unsigned char *, int);
static int       strongbox_encrypt(unsigned char *, unsigned char *,
                                   unsigned char *, int);
static int       strongbox_generate_nonce(unsigned char *);
static int       strongbox_tag(unsigned char *, unsigned char *, int,
                               unsigned char *);
static int       strongbox_check_tag(unsigned char *, unsigned char *, int);



const size_t STRONGBOX_IV_SIZE  = 16;
const size_t STRONGBOX_CRYPT_SIZE = 32;
const size_t STRONGBOX_TAG_SIZE = 32;


/*
 * Generate a suitable key for use with strongbox. It is the caller's
 * responsibility to ensure that the key has STRONGBOX_KEY_SIZE bytes
 * available.
 */
int
strongbox_generate_key(unsigned char *key)
{
        return RAND_bytes(key, STRONGBOX_KEY_SIZE);
}


/*
 * Generate a suitable nonce. It is the caller's responsiblity to ensure
 * the nonce variable has enough space to store a 128-bit nonce.
 */
int
strongbox_generate_nonce(unsigned char *nonce)
{
        return RAND_bytes(nonce, STRONGBOX_IV_SIZE);
}


/*
 * Encrypt the plaintext input using AES-256 in CTR mode.
 */
int
strongbox_encrypt(unsigned char *key, unsigned char *in, unsigned char *out,
                  int data_len)
{
        EVP_CIPHER_CTX   crypt;
        unsigned char    nonce[STRONGBOX_IV_SIZE];
        unsigned char    cryptkey[STRONGBOX_CRYPT_SIZE];
        int              ctlen = 0;
	int		 finale = 0;
        int              res = 0;

        if (!strongbox_generate_nonce(nonce)) {
                return -1;
        }
	memcpy(out, nonce, STRONGBOX_IV_SIZE);
        memcpy(cryptkey, key, STRONGBOX_CRYPT_SIZE);

        EVP_CIPHER_CTX_init(&crypt);
        if (EVP_EncryptInit_ex(&crypt, EVP_aes_256_ctr(), NULL, cryptkey, nonce))
        if (EVP_EncryptUpdate(&crypt, out+STRONGBOX_IV_SIZE, &ctlen, in, data_len))
        if (EVP_EncryptFinal_ex(&crypt, out+STRONGBOX_IV_SIZE+ctlen, &finale))
        if (ctlen+finale == data_len)
                res = 1;
        EVP_CIPHER_CTX_cleanup(&crypt);
        memset(cryptkey, 0x0, STRONGBOX_CRYPT_SIZE);
        return res;
}


/*
 * Compute the message tag for buffer passed in.
 */
int
strongbox_tag(unsigned char *key, unsigned char *in, int inlen,
              unsigned char *tag)
{
        unsigned char    tagkey[STRONGBOX_TAG_SIZE+1];
        unsigned int     md_len;
        int              res = 0;

        memcpy(tagkey, key+STRONGBOX_CRYPT_SIZE, STRONGBOX_TAG_SIZE);
        tag = HMAC(EVP_sha256(), tagkey, STRONGBOX_TAG_SIZE, in, inlen,
                   tag, &md_len);
        memset(tagkey, 0x0, STRONGBOX_TAG_SIZE);
        if (NULL != tag)
                res = 1;
        return res;
}


/*
 * Seal a message into a box.
 */
unsigned char *
strongbox_seal(unsigned char *m, int mlen, int *box_len, unsigned char *key)
{
        unsigned char           *box;
	int			 ctlen;

	ctlen = mlen+STRONGBOX_IV_SIZE;
        if (NULL == (box = malloc(mlen+STRONGBOX_OVERHEAD)))
                return NULL;

        if (strongbox_encrypt(key, m, box, mlen))
        if (strongbox_tag(key, box, ctlen, box+ctlen)) {
		*box_len = mlen+STRONGBOX_OVERHEAD;
		return box;
        }

        if (NULL != box) {
                memset(box, 0, mlen+STRONGBOX_OVERHEAD);
                free(box);
	}
	*box_len = 0;
        return NULL;
}


/*
 * Decrypt the ciphertext input using AES-256 in CTR mode.
 */
int
strongbox_decrypt(unsigned char *key, unsigned char *in, unsigned char *out,
                  int data_len)
{
        EVP_CIPHER_CTX   crypt;
        unsigned char    nonce[STRONGBOX_IV_SIZE];
        unsigned char    cryptkey[STRONGBOX_CRYPT_SIZE];
        int              ptlen = 0;
        int              res = 0;
	int		 finale = 0;

        memcpy(nonce, in, STRONGBOX_IV_SIZE);
        memcpy(cryptkey, key, STRONGBOX_CRYPT_SIZE);

        EVP_CIPHER_CTX_init(&crypt);
        if (EVP_DecryptInit_ex(&crypt, EVP_aes_256_ctr(), NULL, cryptkey, nonce))
        if (EVP_DecryptUpdate(&crypt, out, &ptlen, in+STRONGBOX_IV_SIZE,
                              data_len))
        if (EVP_DecryptFinal_ex(&crypt, out, &finale))
        if (ptlen+finale == data_len)
                res = 1;
        EVP_CIPHER_CTX_cleanup(&crypt);
        memset(cryptkey, 0x0, STRONGBOX_CRYPT_SIZE);
        return res;
}


/*
 * Check the message tag. Returns 1 if the tags match, and 0 if
 * there is a failure.
 */
int
strongbox_check_tag(unsigned char *key, unsigned char *in, int inlen)
{
        unsigned char    tagkey[STRONGBOX_TAG_SIZE];
        unsigned char    tag[STRONGBOX_TAG_SIZE];
        unsigned char    atag[STRONGBOX_TAG_SIZE];
        int              msglen = 0;
        int              match = 0;

        msglen = inlen - STRONGBOX_TAG_SIZE;
        memcpy(tagkey, key+STRONGBOX_CRYPT_SIZE, STRONGBOX_TAG_SIZE);
        memcpy(tag, in+msglen, STRONGBOX_TAG_SIZE);
        if (strongbox_tag(key, in, msglen, atag))
	if (memcmp(atag, tag, STRONGBOX_TAG_SIZE) == 0)
			match = 1;
        memset(tagkey, 0, STRONGBOX_TAG_SIZE);
        return match;
}


/*
 * Recover the message from a box.
 */
unsigned char *
strongbox_open(unsigned char *box, int box_len, unsigned char *key)
{
        unsigned char   *message = NULL;
	int		 decryptlen = 0;

	if (box == NULL)
		return NULL;
	decryptlen = box_len - STRONGBOX_OVERHEAD;
        if (NULL != (message = malloc(decryptlen)))
        if (strongbox_decrypt(key, box, message, decryptlen))
	if (strongbox_check_tag(key, box, box_len))
		return message;
        if (NULL != message)
                memset(message, 0, decryptlen+1);
        free(message);
        return NULL;
}


/*
 * Reclaim the memory used by a box.
 */
void
strongbox_close(struct strongbox_box *box)
{
        if (NULL != box)
                free(box->contents);
        free(box);
}

