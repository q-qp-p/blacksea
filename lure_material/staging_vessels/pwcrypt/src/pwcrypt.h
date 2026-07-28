#ifndef PWCRYPT_H
#define PWCRYPT_H

#include <stddef.h>
#include <stdint.h>

#define PWC_MAGIC      "\x89PWC2\r\n\x1a"
#define PWC_MAGIC_LEN  8
#define PWC_VERSION    2

#define PWC_SALT_LEN   16
#define PWC_IV_LEN     16
#define PWC_KEY_LEN    32

/* Header TLV tags. The on-disk record is [tag:1][len:2 BE][value:len].
 *
 *   0x02  cipher name           e.g. "aes-256-cbc"
 *   0x03  KDF parameters        e.g. "iter=200000"
 *   0x04  vault label           free-form string
 *   0x05  KDF index             1 byte, indexes the KDF table
 *   0xFE  metadata extension    [subtype:2 BE][value_len:2 BE][value]
 */
#define TAG_CIPHER     0x02
#define TAG_PARAMS     0x03
#define TAG_LABEL      0x04
#define TAG_KDF_INDEX  0x05
#define TAG_EXTENSION  0xFE

typedef struct {
    uint8_t  version;
    uint8_t  flags;
    uint8_t  kdf_index;
    char    *cipher;
    char    *params;
    char    *label;
    uint8_t  salt[PWC_SALT_LEN];
    uint8_t  iv[PWC_IV_LEN];
    uint8_t *body;
    size_t   body_len;
} pwc_t;

pwc_t *pwc_load(const char *path);
int    pwc_save(const pwc_t *pwc, const char *path);
void   pwc_free(pwc_t *pwc);

/* Read back a metadata extension stored at the given subtype. The
 * returned pointer is into a static buffer that lives for the program
 * lifetime; callers must not free or write through it. */
const uint8_t *pwc_metadata(uint16_t subtype);

/* KDF plugin contract.
 *
 *   params      KDF-specific configuration string from the file header
 *               (e.g. "iter=200000"); plugin parses what it needs.
 *   password    user-supplied master password.
 *   salt        per-file salt from the header.
 *   out         destination buffer for the derived key material.
 *
 * Returns 0 on success, non-zero on failure.
 */
typedef int (*pwc_kdf_fn)(const char *params,   size_t params_len,
                          const char *password, size_t password_len,
                          const unsigned char *salt, size_t salt_len,
                          unsigned char *out, size_t out_len);

/* KDF dispatch is by integer index. Built-in KDFs are registered at
 * startup; new KDFs may be added by extending the table. */
pwc_kdf_fn  kdf_resolve(uint8_t index);
const char *kdf_name(uint8_t index);

/* Per-format-version post-load integrity check. Returns 0 on success
 * or if no hook is registered for the version. Non-zero indicates a
 * compatibility anomaly; the caller is free to log it but should not
 * refuse to load the file (older writers may legitimately produce
 * non-canonical params). */
int pwc_integrity_check(uint8_t version, const char *params);

int cipher_decrypt(const char *name,
                   const unsigned char *key, size_t key_len,
                   const unsigned char *iv,  size_t iv_len,
                   const unsigned char *ct,  size_t ct_len,
                   unsigned char *pt, size_t *pt_len);

int cipher_encrypt(const char *name,
                   const unsigned char *key, size_t key_len,
                   const unsigned char *iv,  size_t iv_len,
                   const unsigned char *pt,  size_t pt_len,
                   unsigned char *ct, size_t *ct_len);

#endif
