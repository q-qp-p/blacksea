#!/usr/bin/env bash
# End-to-end test for the cfgunpack bait: drives the full pipeline against a live
# edge/brain/Postgres stack — forge (register→build→approve) → trigger → verify (README.md).
#
# Trigger for this entry: the forged artifact is a static Linux `cfgunpack` binary (one per
# arch) + one malicious `prod-config.enc`. On a macOS dev host that Linux ELF can't run
# natively, so the trigger fires inside a Linux container with the artifact dir bind-mounted.
# `cfgunpack decrypt prod-config.enc` prints the decoy production secrets and, via a GNU tar
# --to-command shell injection during sidecar extraction, runs the embedded SDK payload
# one-liner — the beacon fires as a synchronous side effect. Because the payload beacons out
# of the container, we forge with a host.docker.internal callback (not 127.0.0.1, which is the
# container's own loopback). The container platform + binary are chosen to match this host's
# architecture so the binary runs natively (no emulation): the bundle's Argon2id/ChaCha key
# derivation is spec-deterministic on real hardware, but Docker's x86-64 emulation on an ARM
# host (Rosetta) mis-executes x/crypto's AVX assembly, so we always run the native arch here.
# The container image (python:3.11-slim) carries both GNU tar (for --to-command) and python3
# (for the payload one-liner). Everything else — dev-stack bring-up, forge, hot-swap wait,
# record verification — is the shared lib.sh flow.
#
# Usage: ./e2e_test.sh [CALLBACK_URL]        (CAMPAIGN=name overrides the campaign)
# Requires: run `make install` from services/ first, plus Docker able to run Linux containers.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"

bs_require_venv
bs_dev_up

# Forge with a container-reachable callback. The bundled payload beacons to whatever
# _SERVER_URL the factory bakes in; inside the trigger container 127.0.0.1 is the container,
# so point it at the host edge (bound on :8443 = all interfaces) via host.docker.internal.
bs_forge "${1:-http://host.docker.internal:8443}"

bs_wait_hotswap

# Pick the binary + container platform matching this host's architecture, so the binary runs
# natively (correct crypto) rather than under emulation.
case "$(uname -m)" in
    arm64|aarch64) PLATFORM=linux/arm64; CFG_BIN=cfgunpack_linux_arm64 ;;
    x86_64|amd64)  PLATFORM=linux/amd64; CFG_BIN=cfgunpack_linux_amd64 ;;
    *) echo "[e2e] unsupported host arch $(uname -m)" >&2; exit 1 ;;
esac

echo "[e2e] triggering the cfgunpack RCE inside a $PLATFORM container:"
echo "      (cd $BS_ARTIFACT_DIR && ./$CFG_BIN decrypt prod-config.enc)"
docker run --rm --platform "$PLATFORM" \
    --add-host=host.docker.internal:host-gateway \
    -v "$BS_ARTIFACT_DIR:/work" python:3.11-slim \
    sh -c "cd /work && ./$CFG_BIN decrypt prod-config.enc >/dev/null 2>&1; sleep 2"

if bs_verify_record; then
    echo "record stored: $BS_RECORD"
    echo "artifact directory: $BS_ARTIFACT_DIR"
    echo "done. Read it back with: blacksea events ls  (campaign '${CAMPAIGN:-e2e-test}')"
else
    echo "[e2e] no record found for instance $BS_TOKEN after ~10s — check 'blacksea logs'" >&2
    exit 1
fi
