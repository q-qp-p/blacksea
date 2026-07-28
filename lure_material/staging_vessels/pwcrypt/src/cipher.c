#include "pwcrypt.h"

#include <openssl/evp.h>

int cipher_decrypt(const char *name,
                   const unsigned char *key, size_t key_len,
                   const unsigned char *iv,  size_t iv_len,
                   const unsigned char *ct,  size_t ct_len,
                   unsigned char *pt, size_t *pt_len) {
    const EVP_CIPHER *c = EVP_get_cipherbyname(name);
    if (!c) return -1;
    if ((size_t)EVP_CIPHER_key_length(c) > key_len) return -1;
    if ((size_t)EVP_CIPHER_iv_length(c)  > iv_len)  return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, total = 0;
    if (EVP_DecryptInit_ex(ctx, c, NULL, key, iv) != 1) goto err;
    if (EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ct_len) != 1) goto err;
    total = len;
    if (EVP_DecryptFinal_ex(ctx, pt + total, &len) != 1) goto err;
    total += len;
    *pt_len = (size_t)total;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

int cipher_encrypt(const char *name,
                   const unsigned char *key, size_t key_len,
                   const unsigned char *iv,  size_t iv_len,
                   const unsigned char *pt,  size_t pt_len,
                   unsigned char *ct, size_t *ct_len) {
    const EVP_CIPHER *c = EVP_get_cipherbyname(name);
    if (!c) return -1;
    if ((size_t)EVP_CIPHER_key_length(c) > key_len) return -1;
    if ((size_t)EVP_CIPHER_iv_length(c)  > iv_len)  return -1;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, total = 0;
    if (EVP_EncryptInit_ex(ctx, c, NULL, key, iv) != 1) goto err;
    if (EVP_EncryptUpdate(ctx, ct, &len, pt, (int)pt_len) != 1) goto err;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, ct + total, &len) != 1) goto err;
    total += len;
    *ct_len = (size_t)total;
    EVP_CIPHER_CTX_free(ctx);
    return 0;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}
