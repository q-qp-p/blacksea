#!/usr/bin/env bash
# End-to-end test for the agent_fp bait: drives the full pipeline against a live
# edge/brain/Postgres stack — forge (register→build→approve) → trigger → verify (see README.md).
#
# Trigger for this entry: run the built artifact directly with the project venv python.
# The payload encrypts with a pure-stdlib HMAC-SHA256 AEAD — no third-party libraries needed.
# Everything else — dev-stack bring-up, forge, hot-swap wait, record verification — is the
# shared e2e_tests/lib.sh flow.
#
# Usage: ./e2e_test.sh [CALLBACK_URL]        (CAMPAIGN=name overrides the campaign)
# Requires: run `make install` from services/ first.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"

bs_require_venv
bs_dev_up
bs_forge "${1:-http://127.0.0.1:8443}"
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
