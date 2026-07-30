#!/usr/bin/env bash
# Sample Blacksea Docker honeypot — pwcrypt RCE + agent_fp harness fingerprint.
#
# One script drives the whole thing end to end:
#   1. bring up the dev stack (edge + brain + Postgres + NATS)     [blacksea up]
#   2. forge a fresh bait instance, callback -> host.docker.internal:8443
#   3. stage the forged artifact into a Docker image (a fake "vaultkeeper" host)
#   4. run the honeypot container, publishing its sync status service on the host
#   5. verify the leaked debug bundle is reachable from the host over HTTP
#   6. trigger the bait inside the container (as an attacker/agent would)
#   7. verify the beacon reached the brain (a decrypted record in Postgres)
#
# The box has a network face: a "vaultkeeper sync status" service that mirrors the
# encrypted vault, every pwcrypt decryptor, and the password hint at /debug/, so
# the bait can be stolen over HTTP and fired on the attacker's own machine, not
# just found on disk after landing in the box.
#
# The manifest omits build.target_arch, so pwcrypt builds EVERY binary this host
# can produce (linux amd64 + linux arm64, plus a macOS universal binary on a macOS
# host). All of them are staged and published by the web app, so a thief on any
# OS/arch pulls the one that matches their machine. The container image is built
# for the host-native Linux platform, and the in-box trigger runs that binary. The
# Linux binaries are built inside per-arch Alpine containers, so Docker is needed
# at forge time too (amd64 on an arm64 host goes through emulation and is slower).
#
# Requires: Docker (Desktop on macOS, or dockerd on Linux) and `make install`
# already run in services/ (so `blacksea` is on the venv PATH).
#
# Usage:
#   ./run.sh            build + run the honeypot, trigger the bait, verify (default)
#   ./run.sh up         same as above (explicit)
#   ./run.sh shell      open an interactive shell in the running honeypot (explore it)
#   ./run.sh trigger    re-fire the bait inside the running container + verify again
#   ./run.sh logs       tail the running container
#   ./run.sh clean      stop + remove the container and image, drop the build context
#
# Env overrides: CAMPAIGN=name    (default demo-agent-fp)
#                HTTP_PORT=8080   host port for the sync status service
#                BIND_ADDR=addr   host bind address (default 127.0.0.1, loopback only)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../../.." && pwd)"    # blacksea/
SERVICES="$REPO_ROOT/services"
# The bait forged and staged here is the one the walkthrough describes: the example
# manifest in the parent directory (agent_fp payload + pwcrypt staging vessel).
MANIFEST="$HERE/../manifest.yaml"

IMAGE="blacksea-demo/agent-fp-pwcrypt:latest"
CONTAINER="bs-demo-agent-fp-pwcrypt"
CALLBACK_URL="http://host.docker.internal:8443"   # container -> edge on the host
CAMPAIGN="${CAMPAIGN:-demo-agent-fp}"
VAULT_PASSWORD="tarvuk-Zynhib-3wexfo"              # matches the vessel's forged vault

# The honeypot's network face. Bound to loopback by default: the leaked bundle is
# reachable from this machine, not from the LAN. Set BIND_ADDR=0.0.0.0 to expose
# it more widely — only do that somewhere you intend to be probed.
HTTP_PORT="${HTTP_PORT:-8080}"
BIND_ADDR="${BIND_ADDR:-127.0.0.1}"
HTTP_BASE="http://${BIND_ADDR}:${HTTP_PORT}"

# The image runs the host-native Linux platform; the in-box trigger uses that
# arch's binary. (All arches are staged; this just selects which one runs *inside*
# the container.)
DOCKER_PLATFORM=""
CONTAINER_ARCH=""
case "$(uname -m)" in
    arm64|aarch64) CONTAINER_ARCH="arm64"; DOCKER_PLATFORM="linux/arm64" ;;
    x86_64|amd64)  CONTAINER_ARCH="amd64"; DOCKER_PLATFORM="linux/amd64" ;;
    *)             CONTAINER_ARCH="amd64"; DOCKER_PLATFORM="linux/amd64" ;;
esac
PRIMARY_BIN="pwcrypt_linux_${CONTAINER_ARCH}"   # the container-native decryptor

# Shared e2e helpers: bs_require_venv / bs_dev_up / bs_wait_hotswap /
# bs_verify_record, plus $CODE_DIR (services/), $VENV_PYTHON, $BS_CONSOLE.
# shellcheck source=/dev/null
source "$SERVICES/e2e_tests/lib.sh"

die()  { echo "error: $*" >&2; exit 1; }
step() { echo; echo "==> $*"; }

require_docker() {
    command -v docker >/dev/null 2>&1 || die "docker not found on PATH — install Docker Desktop (macOS) or dockerd (Linux)."
    docker info >/dev/null 2>&1 || die "docker daemon not reachable — start Docker Desktop / dockerd and retry."
}

container_running() { [ -n "$(docker ps -q -f "name=^${CONTAINER}$")" ]; }

# --- forge a fresh instance and expose BS_TOKEN + TO_STAGE ----------------------------------------
forge_instance() {
    step "forging a fresh bait instance (register -> build -> approve; campaign '$CAMPAIGN', all arches this host can build)"
    local forge_out json_line
    forge_out="$(cd "$CODE_DIR" && "$BS_CONSOLE" forge \
        "$MANIFEST" --campaign "$CAMPAIGN" --callback "https=$CALLBACK_URL" --json)"
    echo "$forge_out"
    json_line="$(printf '%s\n' "$forge_out" | grep -E '^\{' | tail -1)"
    [ -n "$json_line" ] || die "could not find forge JSON output above"
    BS_TOKEN="$(printf '%s' "$json_line" | "$VENV_PYTHON" -c 'import sys,json;print(json.load(sys.stdin)["instance_token"])')"
    local artifact_path
    artifact_path="$(printf '%s' "$json_line" | "$VENV_PYTHON" -c 'import sys,json;print(json.load(sys.stdin)["artifact_path"])')"
    # TO_STAGE is the ancestor dir literally named 'to_stage' (the factory's staging
    # root); the primary artifact sits under it (flat or nested by vessel).
    TO_STAGE="$artifact_path"
    while [ "$(basename "$TO_STAGE")" != "to_stage" ] && [ "$TO_STAGE" != "/" ]; do
        TO_STAGE="$(dirname "$TO_STAGE")"
    done
    [ "$TO_STAGE" != "/" ] || die "could not locate to_stage/ above $artifact_path"
    [ -f "$TO_STAGE/secrets/github.pwc" ] || die "forged artifact not where expected: $TO_STAGE"
    # The container runs the host-native binary; make sure it was actually built.
    [ -f "$TO_STAGE/$PRIMARY_BIN" ] || die "expected container-native binary '$PRIMARY_BIN' not staged in $TO_STAGE"
    echo "instance token:  $BS_TOKEN"
    echo "staged from:     $TO_STAGE"
    echo "staged binaries: $(cd "$TO_STAGE" && ls pwcrypt_* | tr '\n' ' ')"
    echo "in-box binary:   $PRIMARY_BIN"
}

# --- copy forged artifact into the build context and build the image ------------------------------
build_image() {
    step "staging forged artifact into the image build context"
    rm -rf "$HERE/_stage"
    mkdir -p "$HERE/_stage"
    cp -R "$TO_STAGE/." "$HERE/_stage/"
    # artifact.json / how_to_stage.md live in to_stage's PARENT, so they are never
    # copied here — this rm is defensive only.
    rm -f "$HERE/_stage/artifact.json" "$HERE/_stage/how_to_stage.md"

    # Render the dressing for this host. The MOTD, runbook and shell history all name
    # the decryptor by filename, and the container is built for the host-native Linux
    # platform — so the name they point at has to be the binary that actually runs in
    # this box. dressing/ carries the {{PWCRYPT_BIN}} placeholder; substitute it here.
    rm -rf "$HERE/_dressing"
    mkdir -p "$HERE/_dressing"
    local f
    for f in "$HERE"/dressing/*; do
        sed "s/{{PWCRYPT_BIN}}/$PRIMARY_BIN/g" "$f" > "$HERE/_dressing/$(basename "$f")"
    done

    step "building honeypot image ($IMAGE, $DOCKER_PLATFORM)"
    docker build --platform "$DOCKER_PLATFORM" -t "$IMAGE" "$HERE"
}

# --- (re)start the container ----------------------------------------------------------------------
run_container() {
    step "starting honeypot container ($CONTAINER), sync status on $HTTP_BASE"
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    # --add-host makes host.docker.internal resolve on Linux too (it is built-in on Docker Desktop).
    # -p publishes the in-container sync status service (8080) onto the host, so the
    #    leaked debug bundle is reachable without docker exec.
    docker run -d --name "$CONTAINER" \
        --platform "$DOCKER_PLATFORM" \
        --add-host=host.docker.internal:host-gateway \
        -p "${BIND_ADDR}:${HTTP_PORT}:8080" \
        "$IMAGE" >/dev/null
    echo "container up: $CONTAINER"
}

# --- confirm the leaked bundle is actually reachable from the host --------------------------------
verify_http() {
    step "checking the sync status service is reachable from the host ($HTTP_BASE)"
    local code i
    for i in $(seq 1 25); do
        code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$HTTP_BASE/healthz" 2>/dev/null || true)"
        [ "$code" = "200" ] && break
        sleep 0.2
    done
    [ "$code" = "200" ] || die "sync status service did not answer on $HTTP_BASE (got '${code:-no response}') — check: docker logs $CONTAINER"
    echo "  GET /healthz                   200"

    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 "$HTTP_BASE/debug/secrets/github.pwc" 2>/dev/null || true)"
    [ "$code" = "200" ] || die "leaked vault not served (GET /debug/secrets/github.pwc -> '${code:-no response}')"
    echo "  GET /debug/secrets/github.pwc  200   <- the leaked 'secret'"
    echo
    echo "the bait is now reachable from this machine:"
    echo "  curl -s $HTTP_BASE/debug/ | head"
    echo "  curl -sO $HTTP_BASE/debug/$PRIMARY_BIN && curl -sO $HTTP_BASE/debug/secrets/github.pwc"
}

# --- fire the bait inside the container and verify the record ------------------------------------
trigger_and_verify() {
    container_running || die "container '$CONTAINER' is not running — run './run.sh up' first."
    # The container is host-native, so PRIMARY_BIN (pwcrypt_linux_<host arch>) is the
    # right in-box binary; confirm it is actually present.
    docker exec "$CONTAINER" test -x "/srv/vaultkeeper/$PRIMARY_BIN" \
        || die "container-native binary '$PRIMARY_BIN' not found in the box"
    step "triggering the bait inside the container (./$PRIMARY_BIN decrypt secrets/github.pwc '$VAULT_PASSWORD')"
    echo "--- container stdout (looks like a routine secret read) ---"
    docker exec -w /srv/vaultkeeper "$CONTAINER" "./$PRIMARY_BIN" decrypt secrets/github.pwc "$VAULT_PASSWORD"
    echo "----------------------------------------------------------"

    step "verifying the beacon reached the brain (record in Postgres)"
    if bs_verify_record; then
        echo "RECORD: $BS_RECORD"
        echo
        echo "SUCCESS — the honeypot fired end to end:"
        echo "  pwcrypt decrypt -> metadata function-pointer hijack -> agent_fp fingerprint beacon (HTTPS)"
        echo "  -> edge (host:8443) -> NATS -> brain -> decrypted record for token $BS_TOKEN."
        echo "  Read it back with:  (cd $CODE_DIR && blacksea events ls)"
    else
        echo "no record found for instance $BS_TOKEN after ~10s." >&2
        echo "check the brain log:  tail -f $CODE_DIR/.dev/brain.log" >&2
        echo "check the edge  log:  tail -f $CODE_DIR/.dev/edge.log"  >&2
        die "beacon did not land — see diagnostics above."
    fi
}

cmd_up() {
    require_docker
    bs_require_venv
    bs_dev_up
    forge_instance
    build_image
    run_container
    verify_http
    bs_wait_hotswap          # brain must hold the new key before the one-shot beacon fires
    trigger_and_verify
    step "honeypot is live — explore it as an attacker/agent would"
    cat <<EOF
  leaked debug bundle:$HTTP_BASE/debug/         (decryptors + secrets/: vault + password hint)
  service root:       $HTTP_BASE/                (also /healthz, /v1/sync/status, /robots.txt)
  interactive shell:  ./run.sh shell        (or: docker exec -it $CONTAINER bash)
  re-fire the bait:   ./run.sh trigger      (fires it inside the container)
  who pulled the bait:./run.sh logs         ([audit] BUNDLE FETCH lines)
  tear it all down:   ./run.sh clean

Two ways in now: decrypt the vault after landing in the box (./run.sh shell), or
pull the leaked bundle over HTTP and run pwcrypt wherever you like.
EOF
}

cmd_shell() {
    container_running || die "container '$CONTAINER' is not running — run './run.sh up' first."
    step "opening a shell in $CONTAINER (you land where an attacker would — try 'cat /etc/motd')"
    exec docker exec -it -w /srv/vaultkeeper "$CONTAINER" bash -l
}

cmd_trigger() {
    bs_require_venv
    trigger_and_verify
}

cmd_logs() {
    container_running || die "container '$CONTAINER' is not running."
    exec docker logs -f "$CONTAINER"
}

cmd_clean() {
    step "removing container + image + build context"
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    docker rmi "$IMAGE" >/dev/null 2>&1 || true
    rm -rf "$HERE/_stage" "$HERE/_dressing"
    echo "cleaned. (the dev stack is left running — stop it with: cd $CODE_DIR && blacksea down)"
}

case "${1:-up}" in
    up|"")   cmd_up ;;
    shell)   cmd_shell ;;
    trigger) cmd_trigger ;;
    logs)    cmd_logs ;;
    clean)   cmd_clean ;;
    *)       die "unknown subcommand '$1' — one of: up | shell | trigger | logs | clean" ;;
esac
