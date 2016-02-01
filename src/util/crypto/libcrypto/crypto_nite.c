/*
   SSSD

   Encryption/Decryption primitives

   Authors:
       Simo Sorce <simo@redhat.com>

   Copyright (C) Simo Sorce 2016

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "config.h"
#include <talloc.h>
#include <errno.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

struct cipher_mech {
    const EVP_CIPHER * (*cipher)(void);
} mechs[] = {
    { EVP_aes_256_cbc_hmac_sha1 }
};


int sss_encrypt(TALLOC_CTX *mem_ctx, int enctype,
                uint8_t *key, size_t keylen,
                const uint8_t *plaintext, size_t plainlen,
                uint8_t **ciphertext, size_t *cipherlen)
{
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX ctx;
    uint8_t *out = NULL;
    int evpkeylen;
    int evpivlen;
    int outlen, tmplen;
    int ret;

    if (!plaintext || !plainlen) return EINVAL;

    if (enctype != AES256_HMAC_SHA256) return EINVAL;
    cipher = mechs[AES256_HMAC_SHA256].cipher();

    evpkeylen = EVP_CIPHER_key_length(cipher);
    if (!key || keylen != evpkeylen) return EINVAL;

    evpivlen = EVP_CIPHER_iv_length(cipher);
    outlen = plainlen + (2 * EVP_CIPHER_block_size(cipher)) + evpivlen;
    out = talloc_zero_size(mem_ctx, outlen);

    if (evpivlen != 0) {
        RAND_bytes(out, evpivlen);
    }

    EVP_CIPHER_CTX_init(&ctx);
    ret = EVP_EncryptInit_ex(&ctx, cipher, 0, key, evpivlen ? out : NULL);
    if (!ret) return EFAULT;

    outlen = evpivlen;
    tmplen = 0;
    ret = EVP_EncryptUpdate(&ctx, out + outlen, &tmplen, plaintext, plainlen);
    if (!ret) return EFAULT;

    outlen += tmplen;

    ret = EVP_EncryptFinal_ex(&ctx, out + outlen, &tmplen);
    if (!ret) return EFAULT;

    outlen += tmplen;

    *ciphertext = out;
    *cipherlen = outlen;
    ret = EOK;

done:
    EVP_CIPHER_CTX_cleanup(&ctx);
    return ret;
}

int sss_decrypt(TALLOC_CTX *mem_ctx, int enctype,
                uint8_t *key, size_t keylen,
                const uint8_t *ciphertext, size_t cipherlen,
                uint8_t **plaintext, size_t *plainlen)
{
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX ctx;
    const uint8_t *iv = NULL;
    uint8_t *out;
    int evpkeylen;
    int evpivlen;
    int outlen, tmplen;
    int ret;

    if (!ciphertext || !cipherlen) return EINVAL;

    if (enctype != AES256_HMAC_SHA256) return EINVAL;
    cipher = mechs[AES256_HMAC_SHA256].cipher();

    evpkeylen = EVP_CIPHER_key_length(cipher);
    if (!key || keylen != evpkeylen) return EINVAL;

    evpivlen = EVP_CIPHER_iv_length(cipher);
    out = talloc_zero_size(mem_ctx, cipherlen);

    if (evpivlen != 0) {
        iv = ciphertext;
    }

    EVP_CIPHER_CTX_init(&ctx);
    ret = EVP_DecryptInit_ex(&ctx, cipher, 0, key, iv);
    if (!ret) return EFAULT;

    ret = EVP_DecryptUpdate(&ctx, out, &outlen,
                            ciphertext + evpivlen, cipherlen - evpivlen);
    if (!ret) return EFAULT;

    ret = EVP_DecryptFinal_ex(&ctx, out + outlen, &tmplen);
    if (!ret) return EFAULT;

    outlen += tmplen;

    *plaintext = out;
    *plainlen = outlen;
    return EOK;
}
