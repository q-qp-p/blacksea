#!/usr/bin/env bash
# End-to-end test for the `blacksea` console's bait/instance CRUD + lifecycle state machine.
# Unlike the other e2e_tests/ entries, the *console commands themselves* are what's under test —
# this fixture bait (console-baits-probe, reusing the hostname_grab payload/listener/vessel) is
# just the means to drive them against a live stack. Exercises the granular verbs instead of the
# `forge` convenience wrapper (already covered by e2e_tests/hostname_grab):
#
#   baits register -> baits ls -> baits show
#   -> instances build -> instances ls -> instances show -> instances approve -> instances show
#   -> (fire + verify a real record) -> instances artifact
#   -> 3 more instances, one each through burn / retire / revoke, asserting the resulting status
#
# This is console/context.md's "Exit criterion" (register/build/approve/…/burn/retire/revoke),
# minus the parts e2e_tests/console_infra_observability/ covers instead (status/events/health/…).
#
# Usage: ./e2e_test.sh [CALLBACK_URL]        (CAMPAIGN=name overrides the campaign)
# Requires: run `make install` from services/ first.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"

bs_require_venv
bs_dev_up

CAMPAIGN="${CAMPAIGN:-e2e-console-baits}"
CALLBACK="${1:-http://127.0.0.1:8443}"
BAIT_ID="console-baits-probe"   # fixed by this entry's manifest.yaml

# build_and_approve — build + approve one more instance of $BAIT_ID; prints its instance_token.
# Each statement is explicitly checked with `|| return 1`: on bash < 4.4 (no `inherit_errexit` —
# the actual bash on macOS, this repo's dev platform), `set -e` does not propagate out of the
# command-substitution subshell a function runs in when called as `X="$(build_and_approve)"` — a
# failing "approve" here would otherwise be silently swallowed and the caller would receive the
# token as if approval had succeeded (only the trailing `printf`'s exit status is visible to `X=`).
build_and_approve() {
    local out token
    out="$(cd "$CODE_DIR" && "$BS_CONSOLE" instances build "$BAIT_ID" --campaign "$CAMPAIGN" \
        --callback "https=$CALLBACK" --json | grep -E '^\{' | tail -1)" || return 1
    token="$(jfield "$out" instance_token)" || return 1
    (cd "$CODE_DIR" && "$BS_CONSOLE" instances approve "$token" --json >/dev/null) || return 1
    printf '%s' "$token"
}

# ── baits register / ls / show ──────────────────────────────────────────────────────────────────
echo "[e2e] baits register..."
# --refresh only if $BAIT_ID is already registered (a bare register on an existing bait_id errors
# with "bait-id-unique") — makes a standalone re-run of this entry (e.g. while debugging a failed
# assertion further down) succeed instead of failing at this very first step for an unrelated
# reason, which would mask whatever the original failure actually was.
refresh_flag=""
existing_ids="$(cd "$CODE_DIR" && "$BS_CONSOLE" baits ls --json)"
if printf '%s' "$existing_ids" | BS_BAIT="$BAIT_ID" "$VENV_PYTHON" -c '
import json, os, sys
rows = json.load(sys.stdin)
sys.exit(0 if os.environ["BS_BAIT"] in [r.get("bait_id") for r in rows] else 1)
'; then
    refresh_flag="--refresh"
fi
reg_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" baits register "$ENTRY_REL/manifest.yaml" $refresh_flag --json \
    | grep -E '^\{' | tail -1)"
assert_eq "$(jfield "$reg_out" bait_id)" "$BAIT_ID" "registered bait_id"
assert_eq "$(jfield "$reg_out" tier)" "2" "registered tier"
assert_eq "$(jfield "$reg_out" deploy_class)" "portable_artifact" "registered deploy_class"

echo "[e2e] baits ls..."
ls_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" baits ls --json)"
assert_array_contains "$ls_out" bait_id "$BAIT_ID" "baits ls includes $BAIT_ID"

echo "[e2e] baits show..."
show_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" baits show "$BAIT_ID" --json)"
assert_eq "$(jfield "$show_out" bait_id)" "$BAIT_ID" "baits show bait_id"
assert_eq "$(jfield "$show_out" assurance_tier)" "2" "baits show assurance_tier"

# ── instances build / ls / show / approve (instance 1 — the one we actually fire) ──────────────
echo "[e2e] instances build (instance 1)..."
build_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" instances build "$BAIT_ID" --campaign "$CAMPAIGN" \
    --callback "https=$CALLBACK" --json | grep -E '^\{' | tail -1)"
TOKEN1="$(jfield "$build_out" instance_token)"
assert_eq "$(jfield "$build_out" status)" "pending" "instance 1 status after build"
# Each field is its own statement (not concatenated on one assignment line): under `set -e`, only
# the LAST command substitution on a concatenated line is checked, so a failure in an earlier one
# (e.g. a future console regression dropping the `artifact_dir` key) would otherwise be silently
# swallowed instead of aborting the script with a clear diagnostic.
ARTIFACT_FILE1="$(jfield "$build_out" artifact_filename)"
ARTIFACT_PATH1="$(jfield "$build_out" artifact_dir)/$ARTIFACT_FILE1"
ARTIFACT_SHA1="$(jfield "$build_out" artifact_sha256)"

echo "[e2e] instances ls / show (pending)..."
ils_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" instances ls --bait "$BAIT_ID" --json)"
assert_array_contains "$ils_out" instance_token "$TOKEN1" "instances ls includes $TOKEN1"
ishow_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" instances show "$TOKEN1" --json)"
assert_eq "$(jfield "$ishow_out" status)" "pending" "instance 1 status via show (pre-approve)"

echo "[e2e] instances approve (instance 1)..."
approve_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" instances approve "$TOKEN1" --json \
    | grep -E '^\{' | tail -1)"
assert_eq "$(jfield "$approve_out" status)" "active" "instance 1 status after approve"
ishow_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" instances show "$TOKEN1" --json)"
assert_eq "$(jfield "$ishow_out" status)" "active" "instance 1 status via show (post-approve)"

bs_wait_hotswap

# ── fire the granular-built instance for real, then verify a record lands ──────────────────────
echo "[e2e] triggering the payload ($VENV_PYTHON $ARTIFACT_PATH1)..."
"$VENV_PYTHON" "$ARTIFACT_PATH1"

BS_TOKEN="$TOKEN1"
if bs_verify_record; then
    echo "[e2e] record stored: $BS_RECORD"
else
    echo "[e2e] no record found for instance $TOKEN1 after ~10s — check 'blacksea logs'" >&2
    exit 1
fi

echo "[e2e] instances artifact (instance 1)..."
art_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" instances artifact "$TOKEN1" --json)"
assert_eq "$(jfield "$art_out" filename)" "$ARTIFACT_FILE1" "artifact filename matches build output"
assert_eq "$(jfield "$art_out" sha256)" "$ARTIFACT_SHA1" "artifact sha256 matches build output"

# ── terminal-state transitions: one fresh (unfired) instance per verb ──────────────────────────
echo "[e2e] provisioning 3 more instances for burn / retire / revoke..."
TOKEN2="$(build_and_approve)"
TOKEN3="$(build_and_approve)"
TOKEN4="$(build_and_approve)"

echo "[e2e] instances burn --instance $TOKEN2..."
burn_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" instances burn --instance "$TOKEN2" \
    --reason e2e-test --json | grep -E '^\{' | tail -1)"
assert_eq "$(jfield "$burn_out" kind)" "instance" "burn result kind"
show2="$(cd "$CODE_DIR" && "$BS_CONSOLE" instances show "$TOKEN2" --json)"
assert_eq "$(jfield "$show2" status)" "burned" "instance 2 status after burn"

echo "[e2e] instances retire --instance $TOKEN3..."
(cd "$CODE_DIR" && "$BS_CONSOLE" instances retire --instance "$TOKEN3" --json >/dev/null)
show3="$(cd "$CODE_DIR" && "$BS_CONSOLE" instances show "$TOKEN3" --json)"
assert_eq "$(jfield "$show3" status)" "retired" "instance 3 status after retire"

echo "[e2e] instances revoke $TOKEN4..."
(cd "$CODE_DIR" && "$BS_CONSOLE" instances revoke "$TOKEN4" --json >/dev/null)
show4="$(cd "$CODE_DIR" && "$BS_CONSOLE" instances show "$TOKEN4" --json)"
assert_eq "$(jfield "$show4" status)" "revoked" "instance 4 status after revoke"

echo "[e2e] done. bait=$BAIT_ID campaign='$CAMPAIGN'"
echo "[e2e]   fired + verified: $TOKEN1 (active)"
echo "[e2e]   burned: $TOKEN2 · retired: $TOKEN3 · revoked: $TOKEN4"
