#define _GNU_SOURCE
#include "pwcrypt.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/rand.h>

#ifdef __APPLE__
#include <spawn.h>
#include <errno.h>

extern char **environ;

/* macOS gives every user process ASLR with no linker-level opt-out
 * (`-no_pie`/`-no-pie` is silently ignored, especially on arm64, where
 * non-PIE executables aren't supported by the kernel at all). The
 * self-check below needs a fixed, link-time-predictable text/BSS layout
 * the same way the Linux build gets one from `-no-pie`.
 *
 * The fix: re-exec ourselves once through `posix_spawn` with the
 * private `_POSIX_SPAWN_DISABLE_ASLR` flag (0x0100 -- the same one
 * lldb/debugserver use to launch a debuggee deterministically). That
 * pins the process to the binary's link-time addresses, matching
 * exactly what `nm`/`otool` report on the file. Not in any public
 * header, hence the local define. A marker env var stops the re-exec
 * from looping. */
#ifndef _POSIX_SPAWN_DISABLE_ASLR
#define _POSIX_SPAWN_DISABLE_ASLR 0x0100
#endif

static void pin_load_address(char **argv) {
    if (getenv("PWCRYPT_ASLR_PINNED")) return;
    setenv("PWCRYPT_ASLR_PINNED", "1", 1);

    posix_spawnattr_t attr;
    if (posix_spawnattr_init(&attr) != 0) return;
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC | _POSIX_SPAWN_DISABLE_ASLR);
    posix_spawn(NULL, argv[0], NULL, &attr, argv, environ);
    /* POSIX_SPAWN_SETEXEC replaces this process on success and never
     * returns here. If we do reach this line, the re-exec failed --
     * fall through and run normally (ASLR'd) rather than refuse to run. */
    posix_spawnattr_destroy(&attr);
}
#endif

static void usage(void) {
    fprintf(stderr,
        "pwcrypt - small password vault decrypter\n"
        "\n"
        "Usage:\n"
        "  pwcrypt info    <file>\n"
        "  pwcrypt decrypt <file> <master-password>\n"
        "  pwcrypt encrypt <file> <master-password> <plaintext>\n"
        "  pwcrypt edit    <file> <master-password>\n"
        "\n"
        "Options:\n"
        "  -h, --help    show this help\n"
    );
}

static int derive_key(const pwc_t *p, const char *password,
                      unsigned char *key, size_t key_len) {
    pwc_kdf_fn kdf = kdf_resolve(p->kdf_index);
    if (!kdf) {
        fprintf(stderr, "pwcrypt: unknown KDF (index %u)\n", p->kdf_index);
        return -1;
    }
    const char *params = p->params ? p->params : "";
    if (kdf(params, strlen(params),
            password, strlen(password),
            p->salt, sizeof(p->salt),
            key, key_len) != 0) {
        fprintf(stderr, "pwcrypt: key derivation failed\n");
        return -1;
    }
    return 0;
}

/*
 * Vault identifier: a stable, password-free fingerprint of the KDF
 * configuration. Two vaults that share the same KDF, salt, and params
 * produce the same identifier, which is handy for spotting accidental
 * duplicates across backups without unlocking either file.
 */
static int kdf_fingerprint(const pwc_t *p, unsigned char *out, size_t out_len) {
    pwc_kdf_fn fn = kdf_resolve(p->kdf_index);
    if (!fn) return -1;
    const char *params = p->params ? p->params : "";
    return fn(params, strlen(params),
              "", 0,
              p->salt, sizeof(p->salt),
              out, out_len);
}

static int cmd_info(const char *path) {
    pwc_t *p = pwc_load(path);
    if (!p) return 1;
    const char *kn = kdf_name(p->kdf_index);
    printf("Format version : %u\n", p->version);
    printf("KDF            : %s\n", kn ? kn : "(unknown)");
    printf("Cipher         : %s\n", p->cipher ? p->cipher : "(unset)");
    if (p->label && *p->label)
        printf("Label          : %s\n", p->label);
    /* well-known metadata extension subtypes */
    const uint8_t *author    = pwc_metadata(1);
    const uint8_t *createdat = pwc_metadata(2);
    if (author    && author[0])    printf("Author         : %s\n", (const char *)author);
    if (createdat && createdat[0]) printf("Created        : %s\n", (const char *)createdat);
    printf("Body length    : %zu bytes\n", p->body_len);

    unsigned char fp[8] = {0};
    if (kdf_fingerprint(p, fp, sizeof(fp)) == 0) {
        printf("Vault ID       : ");
        for (size_t i = 0; i < sizeof(fp); i++) printf("%02x", fp[i]);
        printf("\n");
    }

    pwc_free(p);
    return 0;
}

static int cmd_decrypt(const char *path, const char *password) {
    pwc_t *p = pwc_load(path);
    if (!p) return 1;

    unsigned char key[PWC_KEY_LEN];
    if (derive_key(p, password, key, sizeof(key)) != 0) {
        pwc_free(p);
        return 1;
    }

    unsigned char pt[8192];
    size_t pt_len = sizeof(pt);
    if (cipher_decrypt(p->cipher,
                       key, sizeof(key),
                       p->iv, sizeof(p->iv),
                       p->body, p->body_len,
                       pt, &pt_len) != 0) {
        fprintf(stderr, "pwcrypt: decryption failed (corrupt file or wrong password)\n");
        pwc_free(p);
        return 1;
    }

    fwrite(pt, 1, pt_len, stdout);
    if (pt_len == 0 || pt[pt_len - 1] != '\n') fputc('\n', stdout);

    pwc_free(p);
    return 0;
}

static int cmd_encrypt(const char *path, const char *password, const char *plaintext) {
    pwc_t p = {0};
    p.version   = PWC_VERSION;
    p.kdf_index = 0;
    p.cipher    = strdup("aes-256-cbc");
    p.params    = strdup("iter=200000");
    if (!p.cipher || !p.params) {
        fprintf(stderr, "pwcrypt: out of memory\n");
        return 1;
    }
    if (RAND_bytes(p.salt, sizeof(p.salt)) != 1 ||
        RAND_bytes(p.iv,   sizeof(p.iv))   != 1) {
        fprintf(stderr, "pwcrypt: RNG failure\n");
        return 1;
    }

    unsigned char key[PWC_KEY_LEN];
    if (derive_key(&p, password, key, sizeof(key)) != 0) return 1;

    size_t pt_len = strlen(plaintext);
    unsigned char ct[8192];
    size_t ct_len = sizeof(ct);
    if (cipher_encrypt(p.cipher,
                       key, sizeof(key),
                       p.iv, sizeof(p.iv),
                       (const unsigned char *)plaintext, pt_len,
                       ct, &ct_len) != 0) {
        fprintf(stderr, "pwcrypt: encryption failed\n");
        return 1;
    }
    p.body = ct;
    p.body_len = ct_len;

    int rc = pwc_save(&p, path);
    free(p.cipher); free(p.params); free(p.label);
    return rc;
}

/*
 * Decrypt the secret to a temporary file and open it in the user's
 * preferred editor (taken from $EDITOR; falls back to vi). Useful for
 * reviewing long secrets that don't fit comfortably on a terminal.
 */
static int cmd_edit(const char *path, const char *password) {
    pwc_t *p = pwc_load(path);
    if (!p) return 1;

    unsigned char key[PWC_KEY_LEN];
    if (derive_key(p, password, key, sizeof(key)) != 0) {
        pwc_free(p);
        return 1;
    }

    unsigned char pt[8192];
    size_t pt_len = sizeof(pt);
    if (cipher_decrypt(p->cipher,
                       key, sizeof(key),
                       p->iv, sizeof(p->iv),
                       p->body, p->body_len,
                       pt, &pt_len) != 0) {
        fprintf(stderr, "pwcrypt: decryption failed (corrupt file or wrong password)\n");
        pwc_free(p);
        return 1;
    }

    char tmpf[] = "/tmp/pwcrypt-XXXXXX";
    int fd = mkstemp(tmpf);
    if (fd < 0) { perror("mkstemp"); pwc_free(p); return 1; }
    if ((size_t)write(fd, pt, pt_len) != pt_len) {
        perror("write"); close(fd); unlink(tmpf); pwc_free(p); return 1;
    }
    close(fd);

    const char *editor = getenv("EDITOR");
    if (!editor || !*editor) editor = "vi";

    char cmd[1024];
    snprintf(cmd, sizeof cmd, "%s %s", editor, tmpf);
    int rc = system(cmd);

    unlink(tmpf);
    pwc_free(p);
    return rc == 0 ? 0 : 1;
}

int main(int argc, char **argv) {
#ifdef __APPLE__
    pin_load_address(argv);
#endif
    if (argc < 2) { usage(); return 1; }
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        usage();
        return 0;
    }
    if (strcmp(argv[1], "info") == 0 && argc == 3) {
        return cmd_info(argv[2]);
    }
    if (strcmp(argv[1], "decrypt") == 0 && argc == 4) {
        return cmd_decrypt(argv[2], argv[3]);
    }
    if (strcmp(argv[1], "encrypt") == 0 && argc == 5) {
        return cmd_encrypt(argv[2], argv[3], argv[4]);
    }
    if (strcmp(argv[1], "edit") == 0 && argc == 4) {
        return cmd_edit(argv[2], argv[3]);
    }
    usage();
    return 1;
}
