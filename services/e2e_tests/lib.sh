#!/usr/bin/env bash
# Shared helpers for e2e_tests/ entries — see e2e_tests/README.md for the full contract.
#
# Source this from an entry's e2e_test.sh as the first thing after `set`:
#     source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"
#
# Sourcing it derives every path from the sourcing script's own location — nothing is
# hardcoded, so dropping in a new e2e_tests/<name>/ entry needs no edits here or to the
# Makefile. It exposes (all as shell functions/vars, no subshell state loss):
#
#   $CODE_DIR         absolute path to the services/ root (repo build root)
#   $ENTRY_DIR        absolute path to this entry (e2e_tests/<name>/)
#   $ENTRY_REL        this entry relative to CODE_DIR (e2e_tests/<name>) — for `blacksea forge`
#   $VENV_PYTHON      the shared project venv interpreter
#   $BS_CONSOLE       the shared project venv `blacksea` console
#
#   bs_require_venv           abort with a helpful message unless `make install` has been run
#   bs_dev_up                 idempotently bring up the dev stack pointed at e2e_tests/, and
#                             record the edge/brain log positions for bs_wait_hotswap
#   bs_forge [CALLBACK]       forge (register→build→approve) this entry's manifest under
#                             campaign $CAMPAIGN (default e2e-test), overriding the
#                             deploy.callbacks channel named by $CHANNEL (default "https");
#                             sets BS_TOKEN, BS_ARTIFACT_PATH, BS_ARTIFACT_DIR
#   bs_wait_hotswap           block until the edge + brain have hot-swapped in the new
#                             snapshot/key (so the fire below hits a live directory)
#   bs_verify_record          poll Postgres for a record from BS_TOKEN; sets BS_RECORD
#                             (empty + non-zero return if none appears)
#
#   jfield JSON KEY                    print one top-level field's value from a `--json` document
#   assert_eq ACTUAL EXPECTED LABEL    plain string comparison; FAILs (exit 1) and prints a
#                                       labeled diagnostic on mismatch, else prints an OK line
#   assert_array_contains ARR KEY VAL LABEL   VAL is among KEY's values across a `--json` array

# Resolve locations from the sourcing script (BASH_SOURCE[1]), falling back to this file.
_e2e_src="${BASH_SOURCE[1]:-${BASH_SOURCE[0]}}"
ENTRY_DIR="$(cd "$(dirname "$_e2e_src")" && pwd)"
_E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"     # .../e2e_tests
CODE_DIR="$(cd "$_E2E_DIR/.." && pwd)"                       # .../services
VENV_PYTHON="$CODE_DIR/.venv/bin/python"
BS_CONSOLE="$CODE_DIR/.venv/bin/blacksea"
ENTRY_REL="${ENTRY_DIR#"$CODE_DIR"/}"                        # e2e_tests/<name>

bs_require_venv() {
    if [[ ! -x "$VENV_PYTHON" || ! -x "$BS_CONSOLE" ]]; then
        echo "error: shared venv not found. Run 'make install' from $CODE_DIR first." >&2
        exit 1
    fi
}

# Idempotently bring up the whole stack (dead-drop edge + brain + infra) via `blacksea up` — the
# sole stack bring-up entry point (console supervisor). Run from CODE_DIR so the console loads
# config/blacksea.env and resolves the Postgres/registry/key-dir coordinates from it.
# BS_BRAIN_KEYDIR_POLL_S=1: the brain's 10s default would leave a multi-second gap between forge's
# approve and the pool re-reading its key directory — this only affects the processes this run
# manages (config-aware restart in console/supervisor.py).
bs_dev_up() {
    # The brain reads baits from the control-plane catalog (populated by bs_forge below) +
    # the frozen listener under registry/artifacts (D2/O10) — no baits dir to point it at.
    echo "[e2e] bringing up the dev stack (dead-drop edge + brain)..."
    ( cd "$CODE_DIR" && BS_BRAIN_KEYDIR_POLL_S=1 "$BS_CONSOLE" up )
    BS_EDGE_LOG="$CODE_DIR/.dev/edge.log"
    BS_BRAIN_LOG="$CODE_DIR/.dev/brain.log"
    BS_BRAIN_LINES_BEFORE="$(wc -l < "$BS_BRAIN_LOG" 2>/dev/null || echo 0)"
}

# Forge (register→build→approve) this entry's manifest and capture the instance token +
# artifact path. --json emits one clean result line; other notes may print too, so the JSON
# is isolated with grep '^{'. Sets BS_TOKEN, BS_ARTIFACT_PATH, BS_ARTIFACT_DIR.
# CHANNEL (default "https") selects which deploy.callbacks entry $1 overrides — set
# CHANNEL=dns for a DNS-channel entry, e.g. CHANNEL=dns bs_forge 127.0.0.1:15353.
bs_forge() {
    local campaign="${CAMPAIGN:-e2e-test}"
    local channel="${CHANNEL:-https}"
    local callback="${1:-http://127.0.0.1:8443}"
    echo "[e2e] forging instance (register+build+approve, campaign '$campaign')..."
    local forge_out json_line
    forge_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" forge \
        "$ENTRY_REL/manifest.yaml" --campaign "$campaign" --callback "$channel=$callback" --json)"
    echo "$forge_out"
    json_line="$(printf '%s\n' "$forge_out" | grep -E '^\{' | tail -1)"
    if [ -z "$json_line" ]; then
        echo "error: could not find forge JSON output above" >&2
        exit 1
    fi
    BS_TOKEN="$(printf '%s' "$json_line" | "$VENV_PYTHON" -c 'import sys,json;print(json.load(sys.stdin)["instance_token"])')"
    BS_ARTIFACT_PATH="$(printf '%s' "$json_line" | "$VENV_PYTHON" -c 'import sys,json;print(json.load(sys.stdin)["artifact_path"])')"
    BS_ARTIFACT_DIR="$(dirname "$BS_ARTIFACT_PATH")"
}

# The edge is a dumb dead-drop: it holds no directory and forwards every hit regardless, so there
# is nothing for it to "pick up". Only the brain must catch up — it sees the new instance's `_KEY`
# once its poller re-reads brain_keydir.json (≤ BS_BRAIN_KEYDIR_POLL_S). Wait for that, or
# the one-shot beacon fires before the brain can decrypt/route it and gets dead-lettered (no
# retry). Needs bs_dev_up first.
bs_wait_hotswap() {
    echo "[e2e] waiting for the brain to pick up the new key..."
    local i
    local ok=0
    for i in $(seq 1 20); do
        if tail -n "+$((BS_BRAIN_LINES_BEFORE + 1))" "$BS_BRAIN_LOG" 2>/dev/null | grep -q "brain keydir reloaded"; then
            ok=1; break
        fi
        sleep 0.5
    done
    [ "$ok" = "1" ] || echo "[e2e] warning: brain hasn't confirmed the new key after 10s — trying anyway" >&2
}

# Poll Postgres for the record produced by BS_TOKEN. Sets BS_RECORD; returns non-zero (with an
# empty BS_RECORD) if nothing lands within ~10s.
bs_verify_record() {
    echo "[e2e] waiting for the brain to process the hit..."
    BS_RECORD=""
    local i
    for i in $(seq 1 20); do
        BS_RECORD="$(docker compose --env-file "$CODE_DIR/config/blacksea.env" --project-directory "$CODE_DIR" \
            exec -T postgres psql -U blacksea -d blacksea -t -A -F' | ' -c \
            "SELECT record_id, event_type, sig_valid, details FROM records WHERE instance_token='$BS_TOKEN' ORDER BY ingested_at DESC LIMIT 1;")"
        [ -n "$BS_RECORD" ] && break
        sleep 0.5
    done
    [ -n "$BS_RECORD" ]
}

# ── tiny JSON assertion helpers ─────────────────────────────────────────────────────────────────
# Every `blacksea ... --json` invocation prints one compact JSON document to stdout, no wrapper
# (render.py's contract) — these read it back for assertions in entries that drive granular
# console verbs instead of (or in addition to) the high-level bs_forge/bs_verify_record flow.

# jfield JSON_OBJECT KEY — print one top-level field's value.
jfield() {
    printf '%s' "$1" | BS_KEY="$2" "$VENV_PYTHON" -c \
        'import json, os, sys; d = json.load(sys.stdin); print(d[os.environ["BS_KEY"]])'
}

# assert_eq ACTUAL EXPECTED LABEL — plain string comparison.
assert_eq() {
    if [ "$1" != "$2" ]; then
        echo "[e2e] FAIL: $3 (got '$1', want '$2')" >&2
        exit 1
    fi
    echo "[e2e] OK: $3 = $1"
}

# assert_array_contains JSON_ARRAY KEY VALUE LABEL — VALUE is among KEY's values across the array.
assert_array_contains() {
    if ! printf '%s' "$1" | BS_KEY="$2" BS_WANT="$3" "$VENV_PYTHON" -c '
import json, os, sys
rows = json.load(sys.stdin)
key, want = os.environ["BS_KEY"], os.environ["BS_WANT"]
sys.exit(0 if want in [str(r.get(key)) for r in rows] else 1)
'; then
        echo "[e2e] FAIL: $4" >&2
        exit 1
    fi
    echo "[e2e] OK: $4"
}
