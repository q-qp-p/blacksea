#!/usr/bin/env bash
# End-to-end test for the fpextract record-extractor vessel: drives the full pipeline against a live
# edge/brain/Postgres stack — forge (register→build→approve) → trigger the extract → verify.
#
# Trigger: run whichever staged recstore_<platform> binary matches this runner against the packed
# record store (`cd <artifact_dir> && ./recstore_<platform> records.ndx 'rk_e2e_7c4e18b0'`). The
# extract decodes the one keyed record and runs its on-extract "hook" via /bin/sh — an unsanitised
# command-injection that fires the embedded SDK payload one-liner, so the beacon lands as a side
# effect of a normal-looking record read. Cover values come from ./cover.json (read by the vessel
# from this bait dir); keep them in sync with TOOL/DAT/KEY below. Everything else — dev-stack
# bring-up, forge, hot-swap wait, record verification — is the shared e2e_tests/lib.sh flow.
#
# Usage: ./e2e_test.sh [CALLBACK_URL]        (CAMPAIGN=name overrides the campaign)
# Requires: run `make install` from services/ first.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"

bs_require_venv
bs_dev_up
bs_forge "${1:-http://127.0.0.1:8443}"
bs_wait_hotswap

# Kept in sync with ./cover.json (which the vessel reads from the bait dir).
TOOL=recstore
DAT=records.ndx
KEY='rk_e2e_7c4e18b0'

# The vessel ships one binary per platform (recstore_macos / _linux_amd64 / _linux_arm64) plus an
# un-suffixed alias, all against the one shared record store. Run whichever matches this runner so
# the test works on a Linux CI box or a macOS dev machine.
case "$(uname -s)/$(uname -m)" in
    Darwin/*)                   BIN="${TOOL}_macos" ;;
    Linux/x86_64)               BIN="${TOOL}_linux_amd64" ;;
    Linux/aarch64|Linux/arm64)  BIN="${TOOL}_linux_arm64" ;;
    *) echo "[e2e] unsupported runner $(uname -s)/$(uname -m)" >&2; exit 1 ;;
esac

echo "[e2e] triggering the extract ($BS_ARTIFACT_DIR/$BIN $DAT '$KEY')..."
( cd "$BS_ARTIFACT_DIR" && "./$BIN" "$DAT" "$KEY" )

if bs_verify_record; then
    echo "record stored: $BS_RECORD"
    echo "artifact directory: $BS_ARTIFACT_DIR"
    echo "done. Read it back with: blacksea events ls  (campaign '${CAMPAIGN:-e2e-test}')"
else
    echo "[e2e] no record found for instance $BS_TOKEN after ~10s — check 'blacksea logs'" >&2
    exit 1
fi
