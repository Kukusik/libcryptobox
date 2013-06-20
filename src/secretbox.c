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
#include <openssl/rand.h>
#include <openssl/evp.h>

#include <cryptobox/secretbox.h>


static int       secretbox_generate_nonce(unsigned char *);


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
        int              ctlen = 0:
        int              res = -1;

        if (!secretbox_generate_nonce(nonce)) {
                return -1;
        }

        memcpy(cryptkey, key, SECRETBOX_CRYPT_SIZE);

        EVP_CIPHER_CTX_init(&crypt);
        if (EVP_EncryptInit_ex(&crypt, EVP_aes_128_ctr(), NULL, key, nonce))
        if (EVP_EncryptUpdate(&crypt, out, &ctlen, in, data_len))
        if (EVP_EncryptFinal_ex(&ctx, out, &ctlen))
        if (ctlen == data_len)
                status = 0;
        EVP_CIPHER_CTX_cleanup(&crypt);
        memset(cryptkey, 0x0, SECRETBOX_CRYPT_SIZE);
        return status;
}


/*
 * Compute the message tag for buffer passed in.
 */
int
secretbox_tag(unsigned char *key, unsigned char *in, int inlen,
              unsigned char *tag)
{
        unsigned char   tagkey[SECRETBOX_TAG_SIZE];
        int             md_len;
        int             res = -1;

        memcpy(tagkey, key+SECRETBOX_CRYPT_SIZE, SECRETBOX_TAG_SIZE);
        tag = HMAC(EVP_sha256(), tag, SECRETBOX_TAG_SIZE, in, inlen,
                   tag, SECRETBOX_TAG_SIZE);
        memset(tagkey, 0x0, SECRETBOX_TAG_SIZE);
        if (NULL != tag)
                res = 0;
        return res;
}
