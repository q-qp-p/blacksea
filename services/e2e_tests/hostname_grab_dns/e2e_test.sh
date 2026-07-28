#!/usr/bin/env bash
# End-to-end test for the hostname-beacon-dns bait: drives the full pipeline against a live
# edge/brain/Postgres stack — forge (register→build→approve) → trigger → verify (see README.md).
#
# Trigger for this entry: run the built artifact directly with the project venv python. The
# payload beacons over DNS (see edge/context.md's DNS projection spec): base32(header ‖
# json-body) packed across beacon-name labels, sent as a hand-rolled raw UDP query straight at
# the dev edge's DNS_ADDR (manifest's deploy.build_vars._DNS_SERVER — the test zone isn't
# really delegated, so the OS resolver can't reach the edge) — pure stdlib, no third-party DNS
# library needed.
#
# Usage: ./e2e_test.sh [ZONE]        (CAMPAIGN=name overrides the campaign)
# Requires: run `make install` from services/ first.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"

bs_require_venv
bs_dev_up
CHANNEL=dns bs_forge "${1:-cb.example.com}"
bs_wait_hotswap

echo "[e2e] triggering the payload ($VENV_PYTHON $BS_ARTIFACT_PATH)..."
"$VENV_PYTHON" "$BS_ARTIFACT_PATH"

if bs_verify_record; then
    echo "record stored: $BS_RECORD"
    echo "payload: $BS_ARTIFACT_PATH"
    echo "done. Read it back with: blacksea events ls  (campaign '${CAMPAIGN:-e2e-test}')"
else
    echo "[e2e] no record found for instance $BS_TOKEN after ~10s — check 'blacksea logs'" >&2
    exit 1
fi
