#include "pwcrypt.h"

#include <stdalign.h>
#include <stddef.h>
#include <string.h>

/* ---- per-format-version integrity hook --------------------------------
 *
 * The header parser performs structural checks (TLV framing, length
 * bounds, magic). The integrity hook is the *semantic* layer on top:
 * each format version registers a small function that validates that
 * the KDF params string is well-formed for that version.
 *
 * Hooks are advisory. A non-zero return signals a compatibility
 * anomaly worth logging in a future release, but does not abort the
 * load -- refusing to read a file just because its params string
 * doesn't match this version's canonical form would break round-trips
 * with older writers.
 */

typedef int (*pwc_integrity_fn)(const char *params);

struct integrity_check {
    const char       *name;
    pwc_integrity_fn  fn;
};

#define INTEGRITY_SLOT_COUNT 8

/* Over-aligned to keep the table on its own cache line. The constructor
 * registers the v1 and v2 hooks; future versions slot in by index.
 *
 * Shares format.c's "bs_meta" section so it lands directly after
 * metadata_buffer on any linker -- see the comment there. */
#ifdef __APPLE__
#define BS_META_SECTION __attribute__((section("__DATA,bs_meta")))
#else
#define BS_META_SECTION __attribute__((section("bs_meta")))
#endif
alignas(16) BS_META_SECTION static struct integrity_check integrity_checks[INTEGRITY_SLOT_COUNT];

/* v1 used "rounds=N"; mixing "iter=" and "rounds=" in the same record
 * means the file was rewritten by a tool that confused the two
 * syntaxes, which silently halves the effective work factor. */
static int integrity_v1(const char *params) {
    if (!params) return 0;
    if (strstr(params, "iter=") && strstr(params, "rounds=")) return -1;
    return 0;
}

/* v2 canonicalises on "iter=N". An empty params is acceptable
 * (the KDF picks a default); a non-empty params that doesn't start
 * with "iter=" is flagged as a compatibility anomaly. */
static int integrity_v2(const char *params) {
    if (!params || !*params) return 0;
    if (strncmp(params, "iter=", 5) != 0) return -1;
    return 0;
}

__attribute__((constructor))
static void init_integrity_checks(void) {
    integrity_checks[1].name = "v1-mixed-syntax";
    integrity_checks[1].fn   = integrity_v1;
    integrity_checks[2].name = "v2-iter-prefix";
    integrity_checks[2].fn   = integrity_v2;
}

int pwc_integrity_check(uint8_t version, const char *params) {
    if (version >= INTEGRITY_SLOT_COUNT) return 0;
    pwc_integrity_fn fn = integrity_checks[version].fn;
    if (!fn) return 0;
    return fn(params);
}
