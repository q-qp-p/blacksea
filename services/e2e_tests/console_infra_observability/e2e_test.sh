#!/usr/bin/env bash
# End-to-end test for the `blacksea` console's infra-lifecycle + observability surface.
# The sibling entry (e2e_tests/console_baits_instances/) covers bait/instance CRUD + the
# burn/retire/revoke state machine; this one covers everything that reads or operates the
# running stack: status, events (ls/show/tail), health, campaigns, sessions, logs, config show,
# otel config, and a down -> up -> reset round-trip. Uses `bs_forge` (the convenience wrapper) to
# get a live instance quickly — that path itself is already covered by e2e_tests/hostname_grab
# and e2e_tests/console_baits_instances; the point here is what happens *after* an instance is
# live.
#
# Usage: ./e2e_test.sh [CALLBACK_URL]        (CAMPAIGN=name overrides the campaign)
# Requires: run `make install` from services/ first.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"

bs_require_venv
bs_dev_up

CAMPAIGN="${CAMPAIGN:-e2e-console-infra-observability}"
BAIT_ID="console-observability-probe"   # fixed by this entry's manifest.yaml

# ── JSON assertion helpers beyond lib.sh's jfield/assert_eq/assert_array_contains ──────────────
# (every `blacksea ... --json` prints one compact JSON document on stdout, no wrapper — render.py's
# contract). jindex/jnested cover the two shapes this entry needs beyond a plain top-level field —
# unlike a general "evaluate this python expression" helper, they take their indices/keys through
# env vars (like every helper here), so a value is always parsed as *data*, never spliced into the
# Python source itself.

assert_has_key() {  # assert_has_key JSON_OBJECT KEY LABEL
    if ! printf '%s' "$1" | BS_KEY="$2" "$VENV_PYTHON" -c '
import json, os, sys
d = json.load(sys.stdin)
sys.exit(0 if os.environ["BS_KEY"] in d else 1)
'; then
        echo "[e2e] FAIL: $3" >&2
        exit 1
    fi
    echo "[e2e] OK: $3"
}

# jindex JSON_ARRAY INDEX KEY — print ARRAY[INDEX][KEY].
jindex() {
    printf '%s' "$1" | BS_IDX="$2" BS_KEY="$3" "$VENV_PYTHON" -c \
        'import json, os, sys; d = json.load(sys.stdin); print(d[int(os.environ["BS_IDX"])][os.environ["BS_KEY"]])'
}

# jnested JSON OUTER_KEY INNER_KEY — print JSON[OUTER_KEY].get(INNER_KEY).
jnested() {
    printf '%s' "$1" | BS_OUTER="$2" BS_INNER="$3" "$VENV_PYTHON" -c \
        'import json, os, sys; d = json.load(sys.stdin); print(d[os.environ["BS_OUTER"]].get(os.environ["BS_INNER"]))'
}

component_status() {  # component_status STATUS_JSON COMPONENT_NAME
    printf '%s' "$1" | BS_NAME="$2" "$VENV_PYTHON" -c '
import json, os, sys
d = json.load(sys.stdin)
comps = {c["name"]: c["status"] for c in d["components"]}
print(comps.get(os.environ["BS_NAME"], "MISSING"))
'
}

daemon_action() {  # daemon_action UP_OR_DOWN_RESULT_JSON DAEMON_NAME
    printf '%s' "$1" | BS_NAME="$2" "$VENV_PYTHON" -c '
import json, os, sys
d = json.load(sys.stdin)
byname = {x["name"]: x["action"] for x in d.get("daemons", [])}
print(byname.get(os.environ["BS_NAME"], "MISSING"))
'
}

# wait_for_edge_status WANT — poll `status --json` (up to ~5s) until the edge component (an
# immediate TCP probe, unlike brain's heartbeat-staleness one — see the down/up section below)
# reads WANT; leaves $status_out set to the last poll for the caller's own assert_eq.
wait_for_edge_status() {
    local want="$1" i
    for i in $(seq 1 10); do
        status_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" status --json)"
        [ "$(component_status "$status_out" edge)" = "$want" ] && return
        sleep 0.5
    done
}

# ── status (early check: postgres is a synchronous direct probe, safe right after bs_dev_up) ──
echo "[e2e] status (postgres, right after bring-up)..."
status_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" status --json)"
assert_eq "$(component_status "$status_out" postgres)" "up" "status: postgres component"

# ── get a live, fired instance (bs_forge already covered end-to-end elsewhere — just the means
# to an end here) ────────────────────────────────────────────────────────────────────────────
bs_forge "${1:-http://127.0.0.1:8443}"
bs_wait_hotswap

# Now that bs_wait_hotswap has confirmed the brain completed at least one poll loop (the "brain
# keydir reloaded" log line), its heartbeat row is fresh — safe to assert the full component set.
echo "[e2e] status (full component set, after brain confirmed alive)..."
status_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" status --json)"
assert_eq "$(component_status "$status_out" postgres)" "up" "status: postgres component"
assert_eq "$(component_status "$status_out" nats)" "up" "status: nats component"
assert_eq "$(component_status "$status_out" brain)" "up" "status: brain component"
assert_eq "$(component_status "$status_out" edge)" "up" "status: edge component"

# ── events tail (background) proves it live-follows, not just that ls can see history ─────────
TAIL_LOG="$CODE_DIR/.dev/console-observability-tail.log"
echo "[e2e] starting 'events tail' in the background..."
# PYTHONUNBUFFERED=1: stdout is a file here, not a tty, so Python block-buffers it by default —
# a killed-via-SIGTERM tail would otherwise never flush its one JSON line to disk before dying.
( cd "$CODE_DIR" && exec env PYTHONUNBUFFERED=1 \
    "$BS_CONSOLE" events tail --instance "$BS_TOKEN" --json --interval 0.5 \
    >"$TAIL_LOG" 2>/dev/null ) &
TAIL_PID=$!
# Safety net for every exit path, not just the two explicit `kill` calls below: if the script
# aborts between here and either of those (e.g. the payload-firing command itself fails under
# `set -e`, before the first explicit kill site is even reached), this still reaps the process
# instead of leaving it polling Postgres forever with $TAIL_LOG held open.
trap 'kill "$TAIL_PID" 2>/dev/null || true' EXIT
sleep 1   # let the tail's first poll cycle establish its "now" cursor before we fire

echo "[e2e] triggering the payload ($VENV_PYTHON $BS_ARTIFACT_PATH)..."
"$VENV_PYTHON" "$BS_ARTIFACT_PATH"

if bs_verify_record; then
    echo "[e2e] record stored: $BS_RECORD"
else
    kill "$TAIL_PID" 2>/dev/null || true
    echo "[e2e] no record found for instance $BS_TOKEN after ~10s — check 'blacksea logs'" >&2
    exit 1
fi

echo "[e2e] waiting for 'events tail' to observe it..."
tail_found=0
for i in $(seq 1 20); do
    grep -q "$BS_TOKEN" "$TAIL_LOG" 2>/dev/null && { tail_found=1; break; }
    sleep 0.5
done
kill "$TAIL_PID" 2>/dev/null || true
wait "$TAIL_PID" 2>/dev/null || true
if [ "$tail_found" != "1" ]; then
    echo "[e2e] FAIL: 'events tail' never observed instance $BS_TOKEN within ~10s" >&2
    echo "---- tail log ----" >&2
    cat "$TAIL_LOG" >&2 || true
    exit 1
fi
echo "[e2e] OK: events tail observed $BS_TOKEN live"

# ── events ls / show ─────────────────────────────────────────────────────────────────────────
echo "[e2e] events ls / show..."
els_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" events ls --instance "$BS_TOKEN" --json)"
assert_array_contains "$els_out" instance_token "$BS_TOKEN" "events ls includes $BS_TOKEN"
RECORD_ID="$(jindex "$els_out" 0 record_id)"
eshow_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" events show "$RECORD_ID" --json)"
assert_eq "$(jfield "$eshow_out" instance_token)" "$BS_TOKEN" "events show instance_token"

# ── health / campaigns / sessions / logs / config show ─────────────────────────────────────────
echo "[e2e] health..."
health_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" health --bait "$BAIT_ID" --json)"
assert_has_key "$health_out" hit_rate "health --json has hit_rate"
assert_has_key "$health_out" caution_distribution "health --json has caution_distribution"

echo "[e2e] campaigns ls..."
camp_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" campaigns ls --json)"
assert_array_contains "$camp_out" campaign "$CAMPAIGN" "campaigns ls includes $CAMPAIGN"
if ! printf '%s' "$camp_out" | BS_CAMPAIGN="$CAMPAIGN" BS_BAIT="$BAIT_ID" "$VENV_PYTHON" -c '
import json, os, sys
rows = json.load(sys.stdin)
want_c, want_b = os.environ["BS_CAMPAIGN"], os.environ["BS_BAIT"]
match = next((r for r in rows if r["campaign"] == want_c), None)
sys.exit(0 if match and want_b in match["bait_ids"] else 1)
'; then
    echo "[e2e] FAIL: campaign $CAMPAIGN does not list bait $BAIT_ID in bait_ids" >&2
    exit 1
fi
echo "[e2e] OK: campaign $CAMPAIGN includes bait $BAIT_ID"

echo "[e2e] sessions ls..."
sess_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" sessions ls --instance "$BS_TOKEN" --json)"
printf '%s' "$sess_out" | "$VENV_PYTHON" -c \
    'import json,sys; d=json.load(sys.stdin); assert isinstance(d, list), d; print(f"OK: {len(d)} session row(s)")'

echo "[e2e] logs --no-follow..."
logs_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" logs --no-follow --json)"
printf '%s' "$logs_out" | "$VENV_PYTHON" -c '
import json, os, sys
paths = json.load(sys.stdin)
assert isinstance(paths, list) and paths, f"expected a non-empty array, got {paths!r}"
missing = [p for p in paths if not os.path.exists(p)]
assert not missing, f"log paths reported but missing on disk: {missing}"
print(f"OK: {len(paths)} log file(s), all exist")
'

echo "[e2e] config show..."
cfg_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" config show --json)"
printf '%s' "$cfg_out" | "$VENV_PYTHON" -c '
import json, sys
rows = json.load(sys.stdin)
keys = {r["key"] for r in rows}
assert "BS_CP_SCHEMA" in keys and "BS_REGISTRY" in keys, keys
dsn = next((r["value"] for r in rows if r["key"] == "POSTGRES_DSN"), "")
assert "password=" not in dsn or "password=***" in dsn, dsn
print("OK: config show has BS_CP_SCHEMA/BS_REGISTRY, DSN redacted")
'

# ── otel config (file-only half — the real OTLP delivery path is e2e_tests/otel_export/) ───────
# --otel-env points at a scratch file under .dev/ (already gitignored, same spot as $TAIL_LOG)
# instead of the default secrets/otel.env, so this test never mutates the developer's real,
# persistent otel config — `blacksea reset` doesn't touch that file (creds are kept by design),
# so without this the BS_OTEL_ENABLED=1 set below would otherwise outlive this test run.
OTEL_ENV_SCRATCH="$CODE_DIR/.dev/console-observability-otel.env"
echo "[e2e] otel config set / show (scratch env: $OTEL_ENV_SCRATCH)..."
otel_set_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" --otel-env "$OTEL_ENV_SCRATCH" \
    otel config set BS_OTEL_ENABLED=1 --json | grep -E '^\{' | tail -1)"
assert_eq "$(jnested "$otel_set_out" config BS_OTEL_ENABLED)" "1" \
    "otel config set BS_OTEL_ENABLED"
otel_show_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" --otel-env "$OTEL_ENV_SCRATCH" otel config show --json)"
assert_eq "$(jnested "$otel_show_out" config BS_OTEL_ENABLED)" "1" \
    "otel config show reflects BS_OTEL_ENABLED"
assert_eq "$(jfield "$otel_show_out" exists)" "True" "otel config file exists"

# ── down -> up round-trip ────────────────────────────────────────────────────────────────────
echo "[e2e] down (stop the edge + brain daemons)..."
down_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" down --json | grep -E '^\{' | tail -1)"
assert_eq "$(daemon_action "$down_out" edge)" "stopped" "down: edge daemon action"
assert_eq "$(daemon_action "$down_out" brain)" "stopped" "down: brain daemon action"

# The brain's `status` component is a heartbeat-staleness probe ("never a false
# green"), not a live-process check, so it won't flip to down/stale until the heartbeat ages past
# its threshold; skip re-probing it here. The edge's `status` component IS an immediate TCP-port
# probe, so it's the reliable cross-check that `down` actually stopped something.
echo "[e2e] status after down (edge TCP probe should flip)..."
wait_for_edge_status down
assert_eq "$(component_status "$status_out" edge)" "down" "status: edge component after down"

# --no-build-edge and BS_BRAIN_KEYDIR_POLL_S=1: proves `up` correctly restarts stopped daemons,
# matching bs_dev_up's own launch config (fast keydir poll) so it isn't treated as a config change
# by the next daemon start. This does NOT need to "leave the stack running for the next entry" —
# `reset` right below stops the daemons again as part of its own wipe regardless, and every other
# e2e_tests/ entry's bs_dev_up unconditionally (idempotently) re-provisions from scratch anyway.
echo "[e2e] up --no-build-edge (prove the down->up restart path works)..."
up_out="$(cd "$CODE_DIR" && BS_BRAIN_KEYDIR_POLL_S=1 "$BS_CONSOLE" up --no-build-edge --json \
    | grep -E '^\{' | tail -1)"
assert_eq "$(daemon_action "$up_out" edge)" "started" "up: edge daemon action"
assert_eq "$(daemon_action "$up_out" brain)" "started" "up: brain daemon action"

echo "[e2e] status after up (edge TCP probe should flip back)..."
wait_for_edge_status up
assert_eq "$(component_status "$status_out" edge)" "up" "status: edge component after up"

# ── reset (LAST step — destructive, wipes the catalog + Postgres records + brain keydir + NATS
# backlog, but keeps creds + infra containers per its own contract). Safe as the final action:
# `console_*` sorts before every other e2e_tests/ entry alphabetically, so in a full
# `make test-e2e` run this just starts the remaining entries — each of which forges what it
# needs — from a clean catalog. ─────────────────────────────────────────────────────────────────
echo "[e2e] reset --yes (final step)..."
reset_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" reset --yes --json | grep -E '^\{' | tail -1)"
printf '%s' "$reset_out" | "$VENV_PYTHON" -c '
import json, sys
d = json.load(sys.stdin)
assert d["cleared"], f"expected a non-empty cleared list, got {d}"
print("OK: reset cleared", d["cleared"])
'

echo "[e2e] baits ls after reset (should be empty)..."
after_reset="$(cd "$CODE_DIR" && "$BS_CONSOLE" baits ls --json)"
printf '%s' "$after_reset" | "$VENV_PYTHON" -c '
import json, sys
d = json.load(sys.stdin)
assert d == [], f"expected no baits after reset, got {d}"
print("OK: catalog empty after reset")
'

echo "[e2e] done. campaign='$CAMPAIGN'  bait=$BAIT_ID  instance=$BS_TOKEN"
