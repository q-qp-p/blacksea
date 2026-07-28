#!/usr/bin/env bash
# End-to-end test for the OTLP telemetry emitter (blacksea.otel_export).
#
# Proves the whole export path: a real bait fires → the brain assembles a Record into Postgres →
# the standalone emitter tails that Record → maps it to an OTLP LogRecord → pushes it over
# OTLP/HTTP to a live OpenTelemetry Collector, which we assert received it (by the hit's unique
# instance_token). Reuses the shared e2e flow (dev-stack bring-up, forge, hot-swap, fire, verify)
# for the bait half; the OTLP half is this script's extra work.
#
# Requires: `make install` from services/, and Docker (for infra + the Collector container).
# Usage: ./e2e_test.sh [CALLBACK_URL]        (CAMPAIGN=name overrides the campaign)
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../lib.sh"

# ── OTLP Collector settings ───────────────────────────────────────────────────
# A dedicated container + host port so we never collide with an operator's own Collector on
# the standard 4318. The sample config (our shipped ops material) routes received logs to the
# `debug` exporter → the Collector's stdout, which we read back via `docker logs`.
COLLECTOR_NAME="bs-otel-e2e"
COLLECTOR_PORT="4418"
COLLECTOR_CONFIG="$CODE_DIR/src/blacksea/otel_export/ops/collector-config.example.yaml"
COLLECTOR_IMAGE="otel/opentelemetry-collector-contrib:latest"
EMITTER_LOG="$CODE_DIR/.dev/otel-e2e-emitter.log"
EMITTER_PID=""

cleanup() {
    [ -n "$EMITTER_PID" ] && kill "$EMITTER_PID" 2>/dev/null || true
    docker rm -f "$COLLECTOR_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

bs_require_venv
bs_dev_up
bs_forge "${1:-http://127.0.0.1:8443}"
bs_wait_hotswap

# ── stand up the Collector ────────────────────────────────────────────────────
docker rm -f "$COLLECTOR_NAME" >/dev/null 2>&1 || true
echo "[e2e] starting OTLP Collector '$COLLECTOR_NAME' on :$COLLECTOR_PORT (sample config, debug exporter)..."
docker run -d --name "$COLLECTOR_NAME" -p "$COLLECTOR_PORT:4318" \
    -v "$COLLECTOR_CONFIG:/etc/otelcol-contrib/config.yaml" \
    "$COLLECTOR_IMAGE" >/dev/null
# Wait until the Collector both logs "ready" AND actually accepts a TCP connection on its OTLP
# port. The log line alone can precede the receiver binding — if the emitter's first export races
# a not-yet-listening receiver, the OTLP SDK retries with exponential backoff (~tens of seconds),
# delaying delivery past the assertion window below (the flake this guards against).
echo "[e2e] waiting for the Collector to be ready (log + OTLP port $COLLECTOR_PORT accepting)..."
for _ in $(seq 1 60); do
    if docker logs "$COLLECTOR_NAME" 2>&1 | grep -q "Everything is ready" \
       && "$VENV_PYTHON" -c "import socket,sys; s=socket.socket(); s.settimeout(1); sys.exit(s.connect_ex(('127.0.0.1', $COLLECTOR_PORT)))" 2>/dev/null; then
        break
    fi
    sleep 0.5
done

# ── fire the bait (record lands in Postgres) ──────────────────────────────────
# Seed the emitter's cursor just before the fire so it backfills exactly this hit (and not the
# whole historical table).
START_MS="$("$VENV_PYTHON" -c 'import time; print(int(time.time()*1000) - 2000)')"
echo "[e2e] triggering the payload ($VENV_PYTHON $BS_ARTIFACT_PATH)..."
"$VENV_PYTHON" "$BS_ARTIFACT_PATH"

if ! bs_verify_record; then
    echo "[e2e] no record in Postgres for instance $BS_TOKEN — cannot exercise OTLP export" >&2
    exit 1
fi
echo "[e2e] record stored: $BS_RECORD"

# ── run the emitter → push the record over OTLP ───────────────────────────────
set -a; . "$CODE_DIR/config/blacksea.env"; set +a
export POSTGRES_DSN="host=localhost port=5432 dbname=blacksea user=blacksea password=$POSTGRES_PASSWORD"
# No PYTHONPATH needed: `blacksea.*` is importable from the single editable install (`make install`).
echo "[e2e] running the OTLP emitter → http://localhost:$COLLECTOR_PORT (cursor seed ${START_MS}ms)..."
BS_OTEL_ENABLED=1 \
BS_OTEL_ENDPOINT="http://localhost:$COLLECTOR_PORT" \
BS_OTEL_START_TIME="$START_MS" \
BS_OTEL_POLL_INTERVAL=1 \
BS_OTEL_DEPLOYMENT_ID="e2e" \
    "$VENV_PYTHON" -m blacksea.otel_export >"$EMITTER_LOG" 2>&1 &
EMITTER_PID=$!

# ── assert the LogRecord reached the Collector ────────────────────────────────
# The hit's instance_token is unique to this run and rides as blacksea.instance_token on the
# LogRecord, so grepping the Collector's debug output for it is an unambiguous "it arrived".
# Poll up to ~60s: even with a ready receiver, the record traverses the emitter's batch/export
# queue → the network → the Collector's batch processor → the debug exporter's stdout flush, and a
# single OTLP retry (if any) adds backoff on top. The window must comfortably cover that tail so a
# delivered-but-slow record is not misreported as lost (the collector logs proved it arrives).
echo "[e2e] waiting for the Collector to receive the LogRecord (instance_token $BS_TOKEN)..."
found=0
for _ in $(seq 1 60); do
    if docker logs "$COLLECTOR_NAME" 2>&1 | grep -q "$BS_TOKEN"; then found=1; break; fi
    # surface an early emitter crash instead of waiting out the whole budget
    if ! kill -0 "$EMITTER_PID" 2>/dev/null; then break; fi
    sleep 1
done

# stop the emitter (SIGTERM → force_flush → clean exit)
kill "$EMITTER_PID" 2>/dev/null || true
wait "$EMITTER_PID" 2>/dev/null || true
EMITTER_PID=""

if [ "$found" = "1" ]; then
    echo "[e2e] ✅ OTLP LogRecord for $BS_TOKEN received by the Collector:"
    docker logs "$COLLECTOR_NAME" 2>&1 | grep -E "blacksea\.(bait_id|instance_token|record_id)|Body:" | head -12
    echo "done. bait=otel-export-probe  campaign='${CAMPAIGN:-e2e-test}'"
else
    echo "[e2e] ❌ Collector never received a LogRecord for $BS_TOKEN within ~60s" >&2
    echo "---- emitter log (tail) ----" >&2
    tail -n 30 "$EMITTER_LOG" >&2 || true
    echo "---- collector logs (tail) ----" >&2
    docker logs "$COLLECTOR_NAME" 2>&1 | tail -30 >&2 || true
    exit 1
fi
