#include "pwcrypt.h"

#include <stddef.h>
#include <string.h>

#include <openssl/evp.h>

/* ---- built-in KDFs ---------------------------------------------------- */

static int parse_iter(const char *params, size_t params_len) {
    const char *p = params;
    size_t r = params_len;
    if (r > 5 && memcmp(p, "iter=", 5) == 0) { p += 5; r -= 5; }
    long n = 0;
    while (r-- && *p >= '0' && *p <= '9') {
        n = n * 10 + (*p++ - '0');
        if (n > 10000000L) return -1;
    }
    if (n < 1000) return -1;
    return (int)n;
}

static int kdf_pbkdf2_sha256(const char *params, size_t params_len,
                             const char *password, size_t password_len,
                             const unsigned char *salt, size_t salt_len,
                             unsigned char *out, size_t out_len) {
    int iter = parse_iter(params, params_len);
    if (iter < 0) return -1;
    if (PKCS5_PBKDF2_HMAC(password, (int)password_len,
                          salt, (int)salt_len, iter,
                          EVP_sha256(),
                          (int)out_len, out) != 1) return -1;
    return 0;
}

static int kdf_pbkdf2_sha512(const char *params, size_t params_len,
                             const char *password, size_t password_len,
                             const unsigned char *salt, size_t salt_len,
                             unsigned char *out, size_t out_len) {
    int iter = parse_iter(params, params_len);
    if (iter < 0) return -1;
    if (PKCS5_PBKDF2_HMAC(password, (int)password_len,
                          salt, (int)salt_len, iter,
                          EVP_sha512(),
                          (int)out_len, out) != 1) return -1;
    return 0;
}

/* ---- KDF dispatch ----------------------------------------------------- */

struct kdf_slot {
    const char *name;
    pwc_kdf_fn  fn;
};

#define KDF_SLOT_COUNT 8
static struct kdf_slot kdfs[KDF_SLOT_COUNT];

__attribute__((constructor))
static void init_kdfs(void) {
    kdfs[0].name = "pbkdf2_sha256";
    kdfs[0].fn   = kdf_pbkdf2_sha256;
    kdfs[1].name = "pbkdf2_sha512";
    kdfs[1].fn   = kdf_pbkdf2_sha512;
}

pwc_kdf_fn kdf_resolve(uint8_t index) {
    if (index >= KDF_SLOT_COUNT) return NULL;
    return kdfs[index].fn;
}

const char *kdf_name(uint8_t index) {
    if (index >= KDF_SLOT_COUNT) return NULL;
    return kdfs[index].name;
}
