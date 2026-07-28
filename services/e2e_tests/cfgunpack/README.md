# cfgunpack — GNU tar `--to-command` RCE delivery (hostname beacon payload)

Demonstrates the full Blacksea pipeline for a tier-2 HTTPS bait delivered via a **release-config bundle (un)packer RCE** instead of a plain file drop: `payload.py` (hostname_grab, reused) → control-plane factory (bundle + **cfgunpack vessel**) → `registry/artifacts/cfgunpack/…/{cfgunpack_linux_amd64, cfgunpack_linux_arm64, prod-config.enc, README.md, .bash_history}` → RCE trigger (`cfgunpack decrypt`) → edge (HTTPS) → NATS → brain → Postgres.

The bait reuses `hostname_grab`'s payload and listener (HTTPS beacon that collects the attacker's hostname); only the **staging vessel** changes. The cfgunpack vessel compiles a deliberately-vulnerable Go binary from source (`CGO_ENABLED=0` static ELF, one per Linux arch) and forges **one shared config bundle** whose `extras_transform_digest` header field — a base64 blob that reads like an integrity tag — is actually ChaCha20-Poly1305 ciphertext of shell arguments. When any subcommand (`info`/`list`/`verify`/`decrypt`) extracts the bundle's release-notes sidecar, the tool hands it to GNU tar's `--to-command`, which is shell-evaluated (`sh -c`) — and the decrypted arguments splice the bundled SDK payload's one-liner into that shell command. The decryption key is bound to the binary's build seed, so the bundle only decrypts against the binary it was built with; the vessel builds both in one pass keyed to a single seed, so the one bundle drives every binary. Running `cfgunpack decrypt prod-config.enc` prints a convincing set of production secrets **and** fires the beacon as an invisible side effect.

Demonstrates:
- The three-component authoring model (see `docs/bait-authoring.md`) with a real delivery vessel (not a NOP like `identity`)
- The `context.json`/`artifact.json` staging vessel contract (see `docs/bait-authoring.md` §5)
- A portable multi-arch release (Linux static amd64 + arm64, pure-Go `CGO_ENABLED=0` — see the portable-unix-binaries skill) sharing one forged bundle across both arches
- End-to-end RCE → SDK payload execution → beacon → record

**Not grounded in observed attacker behavior — for development and testing only.**

The `blacksea` console is the single operator front door — bring the stack up, forge the bait, and read the records all through the one command. (`make install` below is the only `make` step; it just creates the venv that puts `blacksea` on your PATH.)

---

## Prerequisites

```
make install       # from services/  — creates .venv, installs the blacksea distribution
```

After this, `blacksea` is on your PATH (`.venv/bin`). `blacksea up`, used below, builds the edge binary itself.

The cfgunpack vessel compiles its binaries at forge time, so the build host needs **`go`** and **`python3`** — no Docker or cross-toolchain (pure-Go cross-compilation builds both Linux arches; the Go module dependencies are vendored for offline builds). Docker is needed only to *trigger* the Linux binary on a non-Linux dev host (the automated test below runs the trigger inside a Linux container).

---

## Prepare a deployable instance (no trigger)

```
blacksea forge e2e_tests/cfgunpack/manifest.yaml
```

Registers `cfgunpack` with the control plane (or refreshes its stored manifest if already registered), builds a fresh per-instance artifact (real master key + `instance_token` — the cfgunpack vessel compiles the binaries and forges the bundle at build time), and approves it — all in one step, driven by the manifest's `deploy:` block. It does **not** run/trigger the RCE. Prints the path to the primary artifact under the final artifact directory (`registry/artifacts/cfgunpack/<timestamp>/to_stage/`) — the files to place on a honeypot, with `_SERVER_URL`/`_TOKEN`/`_KEY` already embedded in the payload inside the forged bundle. Add `--json` for a machine-readable result, or `--no-approve` to stop at a pending instance.

`register`/`build`/`approve` only touch the on-disk registry and key directories; none of them talk to a running edge/brain/NATS/Postgres, so `forge` needs no live stack. A live `blacksea up` stack (if running) picks up the newly-approved instance on its own within one poll interval.

---

## Full E2E test

Tests the complete stack: bait fires (cfgunpack RCE) → edge verifies → NATS → brain interprets → record in Postgres.

### One command

```
./e2e_test.sh
```

Brings up the dev stack if it isn't already (`blacksea up`), forges an instance (register the design, build a fresh instance, approve it) with a `host.docker.internal` callback so the containerized trigger can reach the host edge, waits for the edge and brain to hot-swap in the new snapshot/key, **triggers the cfgunpack RCE** inside a Linux container matching the host arch (`cd <artifact_dir> && ./cfgunpack_<arch> decrypt prod-config.enc` — the bundle's sidecar transform shell-injects `system(<embedded_payload_cmd>)`, the beacon reports), and polls Postgres until the resulting record shows up (or fails after ~10s). Safe to re-run — each run registers/refreshes the bait and builds a brand-new instance. Override the campaign with `CAMPAIGN=my-campaign ./e2e_test.sh` or the callback URL with `./e2e_test.sh http://host.docker.internal:9999`.

### Step 4 — trigger the RCE (what the script does)

Run the cfgunpack decrypt command from the artifact directory, picking the binary that matches your machine (`cfgunpack_linux_amd64` or `cfgunpack_linux_arm64`). On a Linux host you can run it directly; on a macOS host use a Linux container (the script does this automatically):

```
cd registry/artifacts/cfgunpack/<timestamp>/to_stage
./cfgunpack_linux_arm64 decrypt prod-config.enc    # or cfgunpack_linux_amd64
```

The tool parses the bundle header, extracts the release-notes sidecar through GNU tar's `--to-command`, and the transform args recovered from `extras_transform_digest` splice the bundled payload one-liner into the shell command tar runs per member. The payload builds the HMAC-SHA256 AEAD-encrypted beacon and POSTs it to the edge. The production secrets are also printed to stdout (the legitimate decrypt path still works — the RCE is a side effect, not the only path).

**Target requirements** (real deployment): a Linux host with **GNU tar** on `PATH` (the transform runs through GNU tar's `--to-command`; BusyBox tar — common on Alpine — does not implement it) and `python3` (the bundled payload is a `python3 -c` one-liner). See the per-build `how_to_stage.md` next to the artifact for the exact placement/trigger for that build.

### Step 5 — verify the record

```
blacksea events ls --bait cfgunpack
blacksea events show <record_id>     # full record incl. details.hostname
```

`blacksea logs` (the edge + brain daemon logs) shows the brain-side confirmation too.

---

Done testing? `blacksea reset` clears the registry, keydirs, Postgres records, and NATS backlog this walkthrough created, and `blacksea down` stops any processes still running.

---

## Files

| File | Role |
|---|---|
| `manifest.yaml` | Bait metadata consumed by the control-plane factory and brain pool; `payload_file`/`listener_class`/`staging_vessel` point into `lure_material/` |
| `e2e_test.sh` | Automated test: forges an instance, triggers the **cfgunpack decrypt RCE** inside a Linux container, and verifies a record lands in Postgres against a live `blacksea up` stack. Picked up by `make test-e2e`. Sources the shared `../lib.sh`. |

`payload.py` and `listener.py` live in `lure_material/payloads/hostname_grab/`; the cfgunpack staging vessel lives in `lure_material/staging_vessels/cfgunpack/` — see those directories for their role.
