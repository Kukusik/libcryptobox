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

#include <cryptobox/secretbox.h>


static int       secretbox_decrypt(unsigned char *, unsigned char *,
                                   unsigned char *, int);
static int       secretbox_encrypt(unsigned char *, unsigned char *,
                                   unsigned char *, int);
static int       secretbox_generate_nonce(unsigned char *);
static int       secretbox_tag(unsigned char *, unsigned char *, int,
                               unsigned char *);
static int       secretbox_check_tag(unsigned char *, unsigned char *, int);



const size_t SECRETBOX_IV_SIZE  = 16;
const size_t SECRETBOX_CRYPT_SIZE = 16;
const size_t SECRETBOX_TAG_SIZE = 32;


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
        int              res = 0;

        if (!secretbox_generate_nonce(nonce)) {
                return -1;
        }

        memcpy(cryptkey, key, SECRETBOX_CRYPT_SIZE);

        EVP_CIPHER_CTX_init(&crypt);
        if (EVP_EncryptInit_ex(&crypt, EVP_aes_128_ctr(), NULL, cryptkey, nonce))
        if (EVP_EncryptUpdate(&crypt, out, &ctlen, in, data_len))
        if (EVP_EncryptFinal_ex(&crypt, out, &ctlen))
        if (ctlen == data_len)
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
        int             res = -1;

        memcpy(tagkey, key+SECRETBOX_CRYPT_SIZE, SECRETBOX_TAG_SIZE);
        tag = HMAC(EVP_sha256(), tag, SECRETBOX_TAG_SIZE, in, inlen,
                   tag, &md_len);
        memset(tagkey, 0x0, SECRETBOX_TAG_SIZE);
        if (NULL != tag)
                res = 0;
        return res;
}


/*
 * Seal a message into a box.
 */
struct secretbox_box *
secretbox_seal(unsigned char *key, unsigned char *m, int mlen)
{
        struct secretbox_box    *box;
        unsigned char           *c;

        if (NULL == (c = malloc(mlen + OVERHEAD + 1)))
                return NULL;

        if (secretbox_encrypt(key, m, c, mlen))
        if (secretbox_tag(key, c, mlen, c+mlen)) {
                if (NULL != (box = malloc(sizeof(struct secretbox_box)))) {
                        box->contents = c;
                        box->len = mlen+OVERHEAD;
                }
        }

        if (NULL == box) {
                memset(c, 0, mlen+OVERHEAD);
                free(c);
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
        unsigned char    nonce[SECRETBOX_IV_SIZE];
        unsigned char    cryptkey[SECRETBOX_CRYPT_SIZE];
        int              ptlen = 0;
        int              res = 0;

        memcpy(nonce, in, SECRETBOX_IV_SIZE);
        memcpy(cryptkey, key, SECRETBOX_CRYPT_SIZE);

        EVP_CIPHER_CTX_init(&crypt);
        if (EVP_DecryptInit_ex(&crypt, EVP_aes_128_ctr(), NULL, key, nonce))
        if (EVP_DecryptUpdate(&crypt, out, &ptlen, in+SECRETBOX_IV_SIZE,
                              data_len))
        if (EVP_DecryptFinal_ex(&crypt, out, &ptlen))
        if (ptlen == data_len)
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
        memcpy(tagkey, key+SECRETBOX_CRYPT_SIZE, SECRETBOX_TAG_SIZE);
        memcpy(tag, in+msglen, SECRETBOX_TAG_SIZE);
        if (secretbox_tag(key, in, msglen, atag))
        if (memcmp(atag, tag, SECRETBOX_TAG_SIZE) == 1)
                match = 1;
        memset(tagkey, 0, SECRETBOX_TAG_SIZE);
        return match;
}


/*
 * Recover the message from a box.
 */
unsigned char *
secretbox_open(unsigned char *key, struct secretbox_box *box)
{
        unsigned char   *message;

        if (NULL != (message = malloc(box->len-OVERHEAD+1)))
        if (secretbox_decrypt(key, box->contents, message, box->len-OVERHEAD))
        if (secretbox_check_tag(key, box->contents, box->len))
                return message;
        if (NULL != message)
                memset(message, 0, box->len-OVERHEAD+1);
        free(message);
        return NULL;
}
