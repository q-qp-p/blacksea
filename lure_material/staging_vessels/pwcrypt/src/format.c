#define _GNU_SOURCE
#include "pwcrypt.h"

#include <stdalign.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>

#define HEADER_KEY_LEN    16
#define HEADER_NONCE_LEN  16
#define MAX_HEADER_LEN    4096

#define META_BUF_SIZE     256

/*
 * Per-vault metadata extensions are stored in a flat buffer keyed by
 * a small "subtype" index. Built-in subtypes (0=label, 1=author,
 * 2=created-at) are recognised by the info command; unknown subtypes
 * are still preserved so they round-trip through encrypt/decrypt.
 *
 * The buffer is over-aligned so that the AES-NI fast path used during
 * header encryption can address it with aligned loads when the value
 * happens to sit here.
 *
 * Pinned into a named section (rather than relying on link-order-based
 * BSS placement) so it sits directly before hooks.c's integrity_checks
 * table regardless of which linker builds this vessel (ld.bfd/ld.gold on
 * Linux, ld64 on macOS) -- see hooks.c.
 */
#ifdef __APPLE__
#define BS_META_SECTION __attribute__((section("__DATA,bs_meta")))
#else
#define BS_META_SECTION __attribute__((section("bs_meta")))
#endif
alignas(16) BS_META_SECTION static uint8_t metadata_buffer[META_BUF_SIZE];

const uint8_t *pwc_metadata(uint16_t subtype) {
    if (subtype >= META_BUF_SIZE) return NULL;
    return metadata_buffer + subtype;
}

/*
 * Header privacy.
 *
 * Container metadata (cipher name, KDF params, label, ...) is encrypted
 * with a key derived from a static format constant. This keeps the
 * choice of primitives opaque on disk -- e.g. so a user inspecting a
 * backup tarball can't immediately tell which files use which cipher.
 * Confidentiality of the actual password body is provided by the
 * body-level cipher; this step is only about metadata visibility.
 */
static void derive_header_key(unsigned char out[HEADER_KEY_LEN]) {
    static const char salt[] = "PWCv2::header-privacy-key";
    unsigned char hash[32];
    unsigned int hash_len = sizeof(hash);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, salt, sizeof(salt) - 1);
    EVP_DigestUpdate(ctx, PWC_MAGIC, PWC_MAGIC_LEN);
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);
    memcpy(out, hash, HEADER_KEY_LEN);
}

/*
 * KDF-parameter privacy key.
 *
 * The params TLV value is additionally wrapped with a per-vault key
 * derived from the file's own salt so that the KDF iteration count is
 * not directly readable from the on-disk representation.  An offline
 * attacker who knows the exact iteration count can immediately size
 * GPU memory and skip tuning; keeping it opaque removes that minor
 * oracle at no cost.  Using the per-vault salt ensures every file
 * produces a distinct params key even though the format constant is
 * shared across all builds.
 */
static void derive_params_key(const uint8_t salt[PWC_SALT_LEN],
                              unsigned char out[HEADER_KEY_LEN]) {
    static const uint8_t kp_info[] = {
        0x70, 0x77, 0x63, 0x3a, 0x3a, 0x6b, 0x70, 0x00
    };
    unsigned char hash[32];
    unsigned int hash_len = sizeof(hash);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, salt, PWC_SALT_LEN);
    EVP_DigestUpdate(ctx, kp_info, sizeof(kp_info));
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);
    memcpy(out, hash, HEADER_KEY_LEN);
}

/* AES-128-CTR with a fixed nonce -- symmetric, so used for both directions.
 * params_xform follows the same convention but uses the per-vault params key. */
static int header_xform(const unsigned char *in, size_t in_len, unsigned char *out) {
    unsigned char key[HEADER_KEY_LEN];
    unsigned char nonce[HEADER_NONCE_LEN] = {0};
    derive_header_key(key);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, total = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, nonce) != 1) goto err;
    if (EVP_EncryptUpdate(ctx, out, &len, in, (int)in_len) != 1) goto err;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, out + total, &len) != 1) goto err;
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    return total;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

static int params_xform(const uint8_t salt[PWC_SALT_LEN],
                        const unsigned char *in, size_t in_len,
                        unsigned char *out) {
    unsigned char key[HEADER_KEY_LEN];
    unsigned char nonce[HEADER_NONCE_LEN] = {0};
    derive_params_key(salt, key);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0, total = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, nonce) != 1) goto err;
    if (EVP_EncryptUpdate(ctx, out, &len, in, (int)in_len) != 1) goto err;
    total = len;
    if (EVP_EncryptFinal_ex(ctx, out + total, &len) != 1) goto err;
    total += len;
    EVP_CIPHER_CTX_free(ctx);
    return total;
err:
    EVP_CIPHER_CTX_free(ctx);
    return -1;
}

/* ---- metadata extension ---------------------------------------------------
 *
 * Wire format for an extension TLV value:
 *   [subtype:2 BE][value_len:2 BE][value:value_len]
 *
 * The subtype indexes the metadata buffer; the value is stored at that
 * offset so subsequent reads via pwc_metadata() return it directly.
 */

static int extension_lengths_ok(uint16_t subtype, uint16_t value_len, size_t avail) {
    /* the value bytes must actually be present in the carrier record */
    if ((size_t)4 + (size_t)value_len > avail) return 0;
    /* values cannot exceed the metadata buffer */
    if (value_len > META_BUF_SIZE)             return 0;
    /* subtype must index a valid byte in the buffer */
    if (subtype  >= META_BUF_SIZE)             return 0;
    return 1;
}

/*
 * A vault built for a portable multi-platform release (see the staging
 * vessel's setup.sh) doesn't know at forge time which of the release's
 * several binaries will actually load it, so a plain extension record
 * (one fixed byte sequence) can't carry a build-specific value. subtype
 * 0xFFFF can never occur in a normal record (it fails the subtype bound
 * above), so it's repurposed as a marker for a variant record whose value
 * carries one candidate byte string per build, tagged by build identity;
 * only the entry matching *this* binary's own compile-time identity
 * (PWC_ARCH_INDEX) is written through to the metadata buffer, via the same
 * blind copy apply_extension always does. A build with no assigned index
 * (PWC_ARCH_INDEX left at its default) matches nothing, so the entry stays
 * all-zero -- integrity_checks[2].fn ends up NULL rather than some other
 * build's address. That still crashes the process (confirmed against the
 * pre-existing single-arch exploit too: this NULL-fn path was never
 * actually safe, despite pwc_integrity_check's own `if (!fn) return 0`),
 * it just crashes instead of running an unrelated command -- not a
 * concern in practice, since the staging vessel always emits one table
 * entry per binary it actually ships, so a real release binary always
 * finds its own match.
 */
#ifndef PWC_ARCH_INDEX
#define PWC_ARCH_INDEX 0xFFu
#endif
#define PWC_ARCH_SELECT_MARKER 0xFFFFu
#define PWC_ARCH_ENTRY_LEN     9u   /* 1 id byte + 8 value bytes */

static int apply_arch_selected_extension(const uint8_t *v, size_t len) {
    if (len < 5) return -1;
    uint16_t real_subtype = ((uint16_t)v[0] << 8) | v[1];
    uint16_t prefix_len   = ((uint16_t)v[2] << 8) | v[3];
    size_t off = 4;
    if (off + (size_t)prefix_len > len) return -1;
    const uint8_t *prefix = v + off;
    off += prefix_len;
    if (off >= len) return -1;
    uint8_t count = v[off++];

    uint8_t selected[8] = {0};   /* default when no PWC_ARCH_INDEX entry matches: all-zero
                                   * -> NULL fn (crashes rather than running a stray command,
                                   * see the comment above this function) */
    for (uint8_t i = 0; i < count; i++) {
        if (off + PWC_ARCH_ENTRY_LEN > len) return -1;
        if (v[off] == PWC_ARCH_INDEX) memcpy(selected, v + off + 1, 8);
        off += PWC_ARCH_ENTRY_LEN;
    }

    size_t total_len = (size_t)prefix_len + sizeof(selected);
    /* Deliberately not bounding real_subtype+total_len against META_BUF_SIZE
     * here (mirrors apply_extension's own extension_lengths_ok, which only
     * bounds subtype and value_len individually) -- that missing sum check
     * is what lets this land past metadata_buffer's end, into
     * integrity_checks. See the OOB-write comment above apply_extension. */
    if (real_subtype >= META_BUF_SIZE || total_len > META_BUF_SIZE) return -1;

    memcpy(metadata_buffer + real_subtype, prefix, prefix_len);
    memcpy(metadata_buffer + real_subtype + prefix_len, selected, sizeof(selected));
    return 0;
}

static int apply_extension(const uint8_t *body, size_t body_len) {
    if (body_len < 4) return -1;
    uint16_t subtype   = ((uint16_t)body[0] << 8) | body[1];
    uint16_t value_len = ((uint16_t)body[2] << 8) | body[3];
    if ((size_t)4 + (size_t)value_len > body_len) return -1;
    if (subtype == PWC_ARCH_SELECT_MARKER) return apply_arch_selected_extension(body + 4, value_len);
    if (!extension_lengths_ok(subtype, value_len, body_len)) return -1;
    memcpy(metadata_buffer + subtype, body + 4, value_len);
    return 0;
}

/*
 * Header is a stream of [tag:1][len:2 BE][value:len] records.
 */
static int parse_tlv(const unsigned char *buf, size_t len, pwc_t *out,
                     const uint8_t *salt) {
    size_t i = 0;
    while (i + 3 <= len) {
        uint8_t  tag  = buf[i];
        uint16_t vlen = ((uint16_t)buf[i+1] << 8) | buf[i+2];
        i += 3;
        if (i + vlen > len) return -1;
        switch (tag) {
            case TAG_CIPHER:
            case TAG_LABEL: {
                char *val = malloc((size_t)vlen + 1);
                if (!val) return -1;
                memcpy(val, buf + i, vlen);
                val[vlen] = 0;
                if (tag == TAG_CIPHER) { free(out->cipher); out->cipher = val; }
                else                    { free(out->label);  out->label  = val; }
                break;
            }
            case TAG_PARAMS: {
                unsigned char *plain = malloc((size_t)vlen + 1);
                if (!plain) return -1;
                int pn = params_xform(salt, buf + i, vlen, plain);
                if (pn < 0) { free(plain); return -1; }
                plain[vlen] = '\0';
                free(out->params);
                out->params = (char *)plain;
                break;
            }
            case TAG_KDF_INDEX:
                if (vlen != 1) return -1;
                out->kdf_index = buf[i];
                break;
            case TAG_EXTENSION:
                if (apply_extension(buf + i, vlen) != 0) return -1;
                break;
            default:
                /* silently ignore unknown tags for forward compatibility */
                break;
        }
        i += vlen;
    }
    return (i == len) ? 0 : -1;
}

static int build_tlv(const pwc_t *p, unsigned char *out, size_t cap, size_t *out_len) {
    size_t i = 0;
    /* TAG_KDF_INDEX (always emitted, 1-byte value) */
    if (i + 4 > cap) return -1;
    out[i++] = TAG_KDF_INDEX;
    out[i++] = 0; out[i++] = 1;
    out[i++] = p->kdf_index;
    /* string fields */
    const struct { uint8_t tag; const char *val; } fields[] = {
        { TAG_CIPHER, p->cipher },
        { TAG_PARAMS, p->params },
        { TAG_LABEL,  p->label  },
    };
    for (size_t k = 0; k < sizeof(fields)/sizeof(fields[0]); k++) {
        const char *v = fields[k].val;
        if (!v) continue;
        size_t vlen = strlen(v);
        if (vlen > 0xFFFF || i + 3 + vlen > cap) return -1;
        out[i++] = fields[k].tag;
        out[i++] = (vlen >> 8) & 0xff;
        out[i++] = vlen & 0xff;
        if (fields[k].tag == TAG_PARAMS) {
            if (params_xform(p->salt, (const unsigned char *)v, vlen, out + i) < 0)
                return -1;
        } else {
            memcpy(out + i, v, vlen);
        }
        i += vlen;
    }
    *out_len = i;
    return 0;
}

static int slurp(FILE *f, unsigned char **out, size_t *out_len) {
    size_t cap = 4096, len = 0;
    unsigned char *buf = malloc(cap);
    if (!buf) return -1;
    for (;;) {
        if (len == cap) {
            cap *= 2;
            unsigned char *t = realloc(buf, cap);
            if (!t) { free(buf); return -1; }
            buf = t;
        }
        size_t n = fread(buf + len, 1, cap - len, f);
        len += n;
        if (n == 0) break;
    }
    *out = buf;
    *out_len = len;
    return 0;
}

pwc_t *pwc_load(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    unsigned char *raw = NULL;
    size_t raw_len = 0;
    if (slurp(f, &raw, &raw_len) != 0) { fclose(f); return NULL; }
    fclose(f);

    pwc_t *p = NULL;
    unsigned char *hdr_plain = NULL;

    if (raw_len < PWC_MAGIC_LEN + 4) goto bad;
    if (memcmp(raw, PWC_MAGIC, PWC_MAGIC_LEN) != 0) goto bad;
    size_t off = PWC_MAGIC_LEN;
    uint8_t version = raw[off++];
    uint8_t flags   = raw[off++];
    if (version != PWC_VERSION) goto bad;

    if (off + 2 > raw_len) goto bad;
    uint16_t hdr_len = raw[off] | ((uint16_t)raw[off+1] << 8);
    off += 2;
    if (hdr_len > MAX_HEADER_LEN) goto bad;
    if (off + hdr_len + PWC_SALT_LEN + PWC_IV_LEN + 4 > raw_len) goto bad;

    hdr_plain = malloc(hdr_len);
    if (!hdr_plain) goto bad;
    int n = header_xform(raw + off, hdr_len, hdr_plain);
    if (n < 0) goto bad;
    off += hdr_len;

    p = calloc(1, sizeof(*p));
    if (!p) goto bad;
    p->version = version;
    p->flags   = flags;
    if (parse_tlv(hdr_plain, (size_t)n, p, raw + off) != 0) goto bad;
    free(hdr_plain); hdr_plain = NULL;

    /* Run the per-version integrity hook now that the header has
     * been structurally validated. Advisory only -- a non-zero
     * return signals a compatibility anomaly but does not prevent
     * the file from loading, since older writers may emit
     * non-canonical params we still want to round-trip. */
    (void)pwc_integrity_check(p->version, p->params ? p->params : "");

    memcpy(p->salt, raw + off, PWC_SALT_LEN); off += PWC_SALT_LEN;
    memcpy(p->iv,   raw + off, PWC_IV_LEN);   off += PWC_IV_LEN;

    uint32_t body_len = (uint32_t)raw[off]
                      | ((uint32_t)raw[off+1] << 8)
                      | ((uint32_t)raw[off+2] << 16)
                      | ((uint32_t)raw[off+3] << 24);
    off += 4;
    if (off + body_len > raw_len) goto bad;
    p->body_len = body_len;
    p->body = malloc(body_len ? body_len : 1);
    if (!p->body) goto bad;
    memcpy(p->body, raw + off, body_len);

    free(raw);
    return p;

bad:
    free(raw);
    free(hdr_plain);
    pwc_free(p);
    fprintf(stderr, "pwcrypt: not a valid PWC file\n");
    return NULL;
}

int pwc_save(const pwc_t *p, const char *path) {
    unsigned char tlv_buf[MAX_HEADER_LEN];
    size_t tlv_len = 0;
    if (build_tlv(p, tlv_buf, sizeof(tlv_buf), &tlv_len) != 0) return -1;
    unsigned char enc_hdr[MAX_HEADER_LEN];
    int enc_len = header_xform(tlv_buf, tlv_len, enc_hdr);
    if (enc_len < 0 || enc_len > 0xFFFF) return -1;

    FILE *f = fopen(path, "wb");
    if (!f) { perror(path); return -1; }

    fwrite(PWC_MAGIC, 1, PWC_MAGIC_LEN, f);
    uint8_t v = PWC_VERSION, fl = 0;
    fwrite(&v,  1, 1, f);
    fwrite(&fl, 1, 1, f);
    uint8_t hb[2] = { (uint8_t)(enc_len & 0xff), (uint8_t)((enc_len >> 8) & 0xff) };
    fwrite(hb, 1, 2, f);
    fwrite(enc_hdr, 1, (size_t)enc_len, f);
    fwrite(p->salt, 1, PWC_SALT_LEN, f);
    fwrite(p->iv,   1, PWC_IV_LEN,   f);
    uint32_t bl = (uint32_t)p->body_len;
    uint8_t bb[4] = {
        (uint8_t)(bl & 0xff),         (uint8_t)((bl >> 8)  & 0xff),
        (uint8_t)((bl >> 16) & 0xff), (uint8_t)((bl >> 24) & 0xff),
    };
    fwrite(bb, 1, 4, f);
    fwrite(p->body, 1, p->body_len, f);
    fclose(f);
    return 0;
}

void pwc_free(pwc_t *p) {
    if (!p) return;
    free(p->cipher);
    free(p->params);
    free(p->label);
    free(p->body);
    free(p);
}
