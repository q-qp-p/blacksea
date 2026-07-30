# pwcrypt_vault — pwcrypt RCE delivery (hostname beacon payload)

Demonstrates the full Blacksea pipeline for a tier-2 HTTPS bait delivered via **pwcrypt RCE** instead of a plain file drop:
`payload.py` (hostname_grab, reused) → control-plane factory (bundle + **pwcrypt vessel**) → `registry/artifacts/pwcrypt-vault/…/{pwcrypt_linux_amd64, pwcrypt_linux_arm64, pwcrypt_macos, secrets/github.pwc, ...}` → RCE trigger (`pwcrypt_<platform> decrypt`) → edge (HTTPS) → NATS → brain → Postgres.

The bait reuses `hostname_grab`'s payload and listener (HTTPS beacon that collects the attacker's hostname); only the **staging vessel** changes. The pwcrypt vessel compiles a deliberately-vulnerable C binary from source (password-vault decryptor with an out-of-bounds BSS write RCE) for a fixed portable-release matrix — `pwcrypt_linux_amd64`/`pwcrypt_linux_arm64` (static musl) and a `pwcrypt_macos` universal binary — and forges **one shared vault** whose TLV "metadata extension" field carries a per-binary candidate `system` address (PLT/stub on the dynamically-linked macOS slices, the plain symbol address on the statically-linked Linux binaries); each binary picks its own entry from a compile-time-baked index (see `src/format.c`'s `PWC_ARCH_SELECT_MARKER`). The bundled SDK payload is embedded as a base64'd Python one-liner inside the vault's encrypted params field. Whichever binary matches the target host, running `pwcrypt_<platform> decrypt secrets/github.pwc 'tarvuk-Zynhib-3wexfo'` fires the RCE and executes the beacon.

Demonstrates:
- The three-component authoring model (see `docs/bait-authoring.md`) with a real delivery vessel (not a NOP like `identity`)
- The `context.json`/`artifact.json` staging vessel contract (see `docs/bait-authoring.md` §5)
- A portable multi-platform release (Linux static musl ×2 + a macOS universal binary) sharing one forged vault across every platform (see the portable-unix-binaries skill)
- End-to-end RCE → SDK payload execution → beacon → record

**Not grounded in observed attacker behavior — for development and testing only.**

The `blacksea` console is the single operator front door — bring the stack up, forge the bait,
and read the records all through the one command. (`make install` below is the only `make` step;
it just creates the venv that puts `blacksea` on your PATH.)

---

## Prerequisites

```
make install       # from services/  — creates .venv, installs the blacksea distribution
```

After this, `blacksea` is on your PATH (`.venv/bin`). `blacksea up`, used below, builds the edge
binary itself.

The pwcrypt vessel compiles its binaries at forge time, so the build host also needs **Docker**
for the Linux release binaries (built inside native-arch Alpine containers, which fetch packages
from the network) and, on macOS, the **Xcode Command Line Tools** for the universal macOS build.

---

## Prepare a deployable instance (no trigger)

```
blacksea forge e2e_tests/pwcrypt_vault/manifest.yaml
```

Registers `pwcrypt-vault` with the control plane (or refreshes its stored manifest if already registered), builds a fresh per-instance artifact (real master key + `instance_token` — the pwcrypt vessel compiles the binary and forges the vault at build time), and approves it — all in one step, driven by the manifest's `deploy:` block. It does **not** run/trigger the RCE. Prints the path to the primary artifact under the final artifact directory (`registry/artifacts/pwcrypt-vault/<timestamp>/to_stage/`) — the files to place on a honeypot, with `_SERVER_URL`/`_TOKEN`/`_KEY` already embedded in the vault. Add `--json` for a machine-readable result, or `--no-approve` to stop at a pending instance.

`register`/`build`/`approve` only touch the on-disk registry and key directories (see `src/blacksea/control_plane/context.md`); none of them talk to a running edge/brain/NATS/Postgres, so `forge` needs no live stack. A live `blacksea up` stack (if running) will pick up the newly-approved instance on its own within one poll interval — nothing else to do to make it "live" for a real edge. The `deploy:` block supplies `campaign` and the `https` callback URL; override either with `--campaign X` / `--callback https=URL`. For a real deployment, set the actual public edge URL in the manifest's `deploy.callbacks.https`.

For the full automated fire-and-verify test, see below.

---

## Full E2E test

Tests the complete stack: bait fires (pwcrypt RCE) → edge verifies → NATS → brain interprets → record in Postgres.

### One command

```
./e2e_test.sh
```

Brings up the dev stack if it isn't already (`blacksea up`), forges an instance (register the design, build a fresh instance under campaign `e2e-test`, approve it), waits for the edge and brain to hot-swap in the new snapshot/key, **triggers the pwcrypt RCE** (`cd <artifact_dir> && ./pwcrypt_<platform> decrypt secrets/github.pwc 'tarvuk-Zynhib-3wexfo'`, picking the binary that matches the runner — the vault's OOB write fires, `system(<embedded_payload_cmd>)` runs, the beacon reports), and polls Postgres until the resulting record shows up (or fails after ~10s). Safe to re-run — each run registers/refreshes the bait and builds a brand-new instance, same as running the manual steps below repeatedly. Override the campaign with `CAMPAIGN=my-campaign ./e2e_test.sh` or the callback URL with `./e2e_test.sh http://127.0.0.1:9999`.

The rest of this section walks through what that script does, one command at a time — useful for understanding the pipeline or debugging a failure.

### Step 0 — bring up the dev stack

```
blacksea up
```

(from `services/`) — starts Postgres + NATS (docker mode), then starts the edge (a dumb dead-drop — it holds no directory and just forwards every hit) and the brain (its own key-directory poller, hot-swap) as background daemons. The brain applies the DB schema automatically on first connect. Neither the edge nor the brain needs a restart later — the edge forwards regardless, and any bait approved via the control plane becomes decodable automatically once the brain re-reads its key directory (one `BS_BRAIN_KEYDIR_POLL_S` interval, default 10s; export `BS_BRAIN_KEYDIR_POLL_S=1` before `blacksea up` for faster local iteration).

### Steps 1-3 — register, build, approve

```
blacksea forge e2e_tests/pwcrypt_vault/manifest.yaml --campaign e2e-test --callback https=http://127.0.0.1:8443
```

Does all three in one shot (see "Prepare a deployable instance" above). Equivalently, run each step directly:

```
blacksea baits register e2e_tests/pwcrypt_vault
```

If the bait was registered before the AES-256-GCM migration (manifest still lists `_PRIVKEY`), refresh the stored manifest from disk instead:
```
blacksea baits register --refresh e2e_tests/pwcrypt_vault
```

Expected output:
```
registered + staged 'pwcrypt-vault' v1.0.0 (tier 2, portable_artifact)
```

### Build an instance

```
blacksea instances build pwcrypt-vault --campaign e2e-test --callback https=http://127.0.0.1:8443
```

The factory generates a fresh master key `_KEY` and `instance_token`, injects `_SERVER_URL`, `_TOKEN`, and `_KEY` into `payload.py`, bundles and stages it (the **pwcrypt vessel** runs here: compiles the pwcrypt binaries for every platform in the release matrix from source, forges the one shared malicious vault with the embedded payload one-liner), and writes `_KEY` straight to the brain's key directory — it is never persisted in the registry. (`campaign_id` is recorded brain-side from the token, never injected.) Output:

```
built instance <instance_token> of 'pwcrypt-vault' (campaign 'e2e-test', status pending)
  artifact: pwcrypt_linux_amd64 (sha256 …) in /path/to/services/registry/artifacts/pwcrypt-vault/<timestamp>/to_stage
  approve with:  blacksea instances approve <instance_token>
```

Note the `<instance_token>` — you need it for the next step.

### Approve the instance

```
blacksea instances approve <instance_token>
```

Transitions the instance to `active` and refreshes the brain key directory (`secrets/keys/brain_keydir.json`, the sole key directory) to disk. The dev-managed brain (Step 0) re-reads it on its own within one poll interval — nothing to do. The edge is a dumb dead-drop: it holds no directory and needs no update.

### Step 4 — trigger the RCE

Run the pwcrypt decrypt command from the artifact directory (`blacksea instances artifact <instance_token>` prints the exact `to_stage_dir`), picking the binary that matches your machine — `pwcrypt_linux_amd64`, `pwcrypt_linux_arm64`, or `pwcrypt_macos` (one universal binary for both Intel and Apple Silicon Macs):

```
cd registry/artifacts/pwcrypt-vault/<timestamp>/to_stage
./pwcrypt_linux_amd64 decrypt secrets/github.pwc 'tarvuk-Zynhib-3wexfo'    # or pwcrypt_linux_arm64 / pwcrypt_macos
```
(from `services/`)

The pwcrypt binary's header parser triggers the OOB BSS write during TLV parsing (before any password check), overwrites `integrity_checks[2].fn` with the address of `system` — selected from the vault's per-binary candidate table by this binary's own compile-time arch index, so the same `secrets/github.pwc` drives all three binaries (see `src/format.c`'s `PWC_ARCH_SELECT_MARKER`) — and calls it with the forged params string (`iter=200000;<embedded_payload_cmd>`) — KDF reads the iteration count, `/bin/sh` reads the command after the `;`. The payload runs, builds the HMAC-SHA256 AEAD-encrypted beacon, POSTs it to the edge. The secret is also printed to stdout (the legitimate decrypt path still works — the RCE is a side effect, not the only path).

### Step 5 — verify the record

Read it back with the console — newest first, filtered to this bait:

```
blacksea events ls --bait pwcrypt-vault
blacksea events show <record_id>     # full record incl. details.hostname
```

`blacksea logs` (the edge + brain daemon logs) shows the brain-side confirmation too — a line like:
```
stored record <record_id> (bait=pwcrypt-vault sig_valid=True event=payload_exec_collect)
```
(`sig_valid` reflects the brain's HMAC-SHA256 AEAD decrypt+auth result, not a signature — the column name is retained from the prior Ed25519-signing design, see src/blacksea/brain/context.md.)

---

Done testing? `blacksea reset` clears the registry, keydirs, Postgres records, and NATS backlog this walkthrough created, and `blacksea down` stops any processes still running.

---

## Files

| File | Role |
|---|---|
| `manifest.yaml` | Bait metadata consumed by the control-plane factory and brain pool; `payload_file`/`listener_class`/`staging_vessel` point into `lure_material/` |
| `e2e_test.sh` | Automated test: forges an instance, triggers the **pwcrypt decrypt RCE**, and verifies a record lands in Postgres against a live `blacksea up` stack. Picked up by `make test-e2e`. Sources the shared `../lib.sh`. |

`payload.py` and `listener.py` live in `lure_material/payloads/hostname_grab/`; the pwcrypt staging vessel lives in `lure_material/staging_vessels/pwcrypt/` — see those directories for their role.

## SDK modules involved

Same as `hostname_grab` (the payload/listener are identical):

| Module | Role |
|---|---|
| `blacksea.sdk.payload.envelope` | `build_encrypted_envelope` — packs the fixed binary core, seals it with a pure-stdlib HMAC-SHA256 AEAD, returns JSON envelope bytes |
| `blacksea.sdk.payload.http` | `send_https_encrypted` — builds + POSTs the HMAC-SHA256 AEAD envelope |
