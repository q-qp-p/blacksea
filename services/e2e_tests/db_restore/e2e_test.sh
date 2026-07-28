#!/usr/bin/env bash
# End-to-end test for the db-restore bait: drives the full pipeline against a live
# edge/brain/Postgres stack — forge (register→build→approve) → trigger → verify (README.md).
#
# Trigger for this entry: the forged artifact is a static ARM64 Linux `db-restore` binary +
# one malicious `.dbk` backup. On a macOS dev host that Linux ELF can't run natively (and even
# on ARM64 the planted driver uses Linux syscalls), so the trigger fires inside a linux/arm64
# container with the artifact dir bind-mounted. `db-restore restore <backup>.dbk` decrypts the
# decoy dump and, in a forked child, runs the embedded SDK payload one-liner — the beacon fires
# as a side effect. Because the child beacons out of the container, we forge with a
# host.docker.internal callback (not 127.0.0.1, which is the container's own loopback) and give
# the child a moment (`sleep`) to complete before the container exits. Everything else —
# dev-stack bring-up, forge, hot-swap wait, record verification — is the shared lib.sh flow.
#
# Usage: ./e2e_test.sh [CALLBACK_URL]        (CAMPAIGN=name overrides the campaign)
# Requires: run `make install` from services/ first, plus Docker able to run linux/arm64.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"

bs_require_venv
bs_dev_up

# Forge with a container-reachable callback. The bundled payload beacons to whatever
# _SERVER_URL the factory bakes in; inside the trigger container 127.0.0.1 is the container,
# so point it at the host edge (bound on :8443 = all interfaces) via host.docker.internal.
bs_forge "${1:-http://host.docker.internal:8443}"

bs_wait_hotswap

DBK="prod-nightly-2026-06-14.dbk"
echo "[e2e] triggering the db-restore RCE inside a linux/arm64 container:"
echo "      (cd $BS_ARTIFACT_DIR && ./db-restore restore $DBK --table service_accounts)"
docker run --rm --platform linux/arm64 \
    --add-host=host.docker.internal:host-gateway \
    -v "$BS_ARTIFACT_DIR:/work" python:3.11-slim \
    sh -c "cd /work && ./db-restore restore '$DBK' --table service_accounts >/dev/null 2>&1; sleep 3"

if bs_verify_record; then
    echo "record stored: $BS_RECORD"
    echo "artifact directory: $BS_ARTIFACT_DIR"
    echo "done. Read it back with: blacksea events ls  (campaign '${CAMPAIGN:-e2e-test}')"
else
    echo "[e2e] no record found for instance $BS_TOKEN after ~10s — check 'blacksea logs'" >&2
    exit 1
fi
