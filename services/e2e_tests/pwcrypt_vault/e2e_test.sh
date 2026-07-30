#!/usr/bin/env bash
# End-to-end test for the pwcrypt_vault bait: drives the full pipeline against a live
# edge/brain/Postgres stack — forge (register→build→approve) → trigger RCE → verify (README.md).
#
# Trigger for this entry: run whichever of the staged pwcrypt_<platform> binaries matches
# this runner against the one shared malicious vault (`cd <artifact_dir> &&
# ./pwcrypt_<platform> decrypt secrets/github.pwc 'tarvuk-Zynhib-3wexfo'`). The vault's OOB BSS write
# overwrites a function pointer with `system`'s address (selected from a per-binary
# candidate table baked in at forge time -- see lure_material/staging_vessels/pwcrypt/src/
# format.c's PWC_ARCH_SELECT_MARKER) and runs the embedded SDK payload one-liner — the
# beacon fires as a side effect of the "decrypt". Everything else — dev-stack bring-up,
# forge, hot-swap wait, record verification — is the shared e2e_tests/lib.sh flow.
#
# Usage: ./e2e_test.sh [CALLBACK_URL]        (CAMPAIGN=name overrides the campaign)
# Requires: run `make install` from services/ first.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"

bs_require_venv
bs_dev_up

# Regression coverage for the vessel build helper's crypto dependency (forge.py). The pwcrypt
# vessel's setup.sh runs a bare `python3 forge.py` to build its AES-encrypted vault. Under `make`
# that `python3` is the *system* interpreter (which often has pycryptodome/cryptography), which
# masked a real bug: the console runs the build under the *venv* python, which by design has
# neither, so forge.py used to fail with "install pycryptodome or cryptography" — i.e. a plain
# `blacksea forge <pwcrypt>` in an activated venv broke while `make test-e2e` passed. forge.py now
# falls back to the `openssl` CLI (already a hard build dep of the vessel). Force that exact path
# here by putting the crypto-less venv bin first on PATH, so this e2e catches any reintroduced
# Python-crypto dependency in a vessel build.
if "$VENV_PYTHON" -c "import importlib.util as u,sys; sys.exit(0 if (u.find_spec('Crypto') or u.find_spec('cryptography')) else 1)"; then
    echo "[e2e] note: the venv has a Python AES lib installed — forge.py's openssl fallback won't be exercised this run" >&2
fi
_saved_path="$PATH"
export PATH="$CODE_DIR/.venv/bin:$PATH"    # vessel's `python3` → crypto-less venv python (as the console invokes it)
bs_forge "${1:-http://127.0.0.1:8443}"
export PATH="$_saved_path"

bs_wait_hotswap

# The vessel now ships one binary per platform (pwcrypt_linux_amd64,
# pwcrypt_linux_arm64, pwcrypt_macos) built against a single shared
# secrets/github.pwc -- see lure_material/staging_vessels/pwcrypt/setup.sh.
# Run whichever one matches *this* runner so the e2e test works on either a
# Linux CI box or a macOS dev machine. forge.py --host-arch is the same
# uname->target_arch mapping setup.sh/the Makefile use -- queried here rather
# than re-implementing it a fourth time (see forge.py's module docstring).
PWCRYPT_FORGE_PY="$CODE_DIR/../lure_material/staging_vessels/pwcrypt/src/forge.py"
case "$("$VENV_PYTHON" "$PWCRYPT_FORGE_PY" --host-arch)" in
    x86_64-darwin|arm64-darwin) PWCRYPT_BIN=pwcrypt_macos ;;
    aarch64-linux)              PWCRYPT_BIN=pwcrypt_linux_arm64 ;;
    x86_64-linux)               PWCRYPT_BIN=pwcrypt_linux_amd64 ;;
esac

echo "[e2e] triggering the pwcrypt RCE ($BS_ARTIFACT_DIR/$PWCRYPT_BIN decrypt secrets/github.pwc 'tarvuk-Zynhib-3wexfo')..."
( cd "$BS_ARTIFACT_DIR" && "./$PWCRYPT_BIN" decrypt secrets/github.pwc 'tarvuk-Zynhib-3wexfo' )

if bs_verify_record; then
    echo "record stored: $BS_RECORD"
    echo "artifact directory: $BS_ARTIFACT_DIR"
    echo "done. Read it back with: blacksea events ls  (campaign '${CAMPAIGN:-e2e-test}')"
else
    echo "[e2e] no record found for instance $BS_TOKEN after ~10s — check 'blacksea logs'" >&2
    exit 1
fi
