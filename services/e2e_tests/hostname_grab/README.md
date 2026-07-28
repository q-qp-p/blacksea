# hostname_grab — hostname-beacon end-to-end test

> **Wired to `lure_material/`:** `payload.py`, `listener.py`, and `staging_vessel/` now live
> in `../../../lure_material/payloads/hostname_grab/` and
> `../../../lure_material/staging_vessels/identity/` (the reusable catalog — see
> `lure_material/README.md`). `manifest.yaml`'s `payload_file`/`listener_class`/
> `staging_vessel` fields point there via plain `../`-relative paths — the factory,
> ingestion, and the brain pool all resolve these fields with `os.path.join(bait_dir, ...)`,
> so a path that walks out of the bait directory works with no code changes. Verified via a
> full `./e2e_test.sh` run. A single-call **forge** now exists (`blacksea forge
> e2e_tests/hostname_grab/manifest.yaml`) — register + build + approve driven entirely by
> the manifest's `deploy:` block, no per-bait script. What's still missing: a friendlier way to
> reference a catalog entry by name instead of hand-written relative paths.

Demonstrates the full Blacksea pipeline for a tier-2 HTTPS bait:
`payload.py` → control-plane factory (bundle + stage) → `registry/artifacts/hostname-beacon/…/bait.py`
→ edge (HTTPS) → NATS → brain → Postgres.

The bait packs a fixed binary encrypted-core, seals it with the per-instance master key
`_KEY` using a pure-stdlib HMAC-SHA256 AEAD, and sends the `{ev, tok, enc}` envelope to the
edge. Envelope construction lives in `blacksea.sdk.payload.envelope` (inlined by the
bundler) — no third-party imports anywhere on this path, so it runs on any Python 3.11+.

The `blacksea` console is the single operator front door for everything below — bring the stack
up, forge the bait, and read the resulting records all through the one command. (`make install`
below is the only `make` step; it just creates the venv that puts `blacksea` on your PATH.)

---

## Prerequisites

```
make install       # from services/  — creates .venv, installs the blacksea distribution
```

After this, `blacksea` is on your PATH (`make install` symlinks it into `~/.local/bin`; no venv
activation needed). `blacksea up`, used below, builds the edge binary itself.

---

## Prepare a deployable instance (no trigger)

```
blacksea forge e2e_tests/hostname_grab/manifest.yaml
```

Registers `hostname-beacon` with the control plane (or refreshes its stored manifest if
already registered), builds a fresh per-instance artifact (real master key +
`instance_token`), and approves it — all in one step, driven by the manifest's `deploy:` block.
It does **not** run/trigger the payload. Prints the path to the final, self-contained artifact
(`registry/artifacts/hostname-beacon/<timestamp>/to_stage/bait.py`) — the actual file to place on
a honeypot, with `_SERVER_URL`/`_TOKEN`/`_KEY` already injected — not the source `payload.py`.
Add `--json` for a machine-readable result, or `--no-approve` to stop at a pending instance.

`register`/`build`/`approve` only touch the on-disk registry and key directories (see
`src/blacksea/control_plane/context.md`); none of them talk to a running edge/brain/NATS/Postgres,
so `forge` needs no live stack.
A live `blacksea up` stack (if running) will pick up the newly-approved instance on its own within
one poll interval — nothing else to do to make it "live" for a real edge. The `deploy:` block
supplies `campaign` and the `https` callback URL; override either for testing with
`--campaign X` / `--callback https=URL`. For a real deployment, set the actual public edge URL in
the manifest's `deploy.callbacks.https`.

To fire it by hand afterwards, run the artifact `forge` printed (pure stdlib — any Python 3.11+
works) and read the record back with the console:

```
.venv/bin/python <the artifact: path printed above>
blacksea events ls --bait hostname-beacon        # newest record on top
```

For the full automated fire-and-verify test, see below.

---

## Full E2E test

Tests the complete stack: bait fires → edge verifies → NATS → brain interprets → record in Postgres.

### One command

```
./e2e_test.sh
```

Brings up the dev stack if it isn't already (`blacksea up`), forges an
instance (register the design, build a fresh instance under campaign
`e2e-test`, approve it), waits for the edge and brain to hot-swap in the new
snapshot/key, triggers the payload, and polls Postgres until the resulting record shows up (or
fails after ~10s). Safe to re-run — each run registers/refreshes the bait and builds a
brand-new instance, same as running the manual steps below repeatedly. Override the campaign
with `CAMPAIGN=my-campaign ./e2e_test.sh` or the callback URL with
`./e2e_test.sh http://127.0.0.1:9999`.

The rest of this section walks through what that script does, one command at a time — useful
for understanding the pipeline or debugging a failure.

### Step 0 — bring up the dev stack

```
blacksea up
```

(from `services/`) — starts Postgres + NATS (docker mode), then starts the edge (a dumb dead-drop
— it holds no directory and just forwards every hit) and the brain (its own key-directory poller,
hot-swap) as background daemons. The brain applies the DB schema automatically on first
connect. Neither the edge nor the brain needs a restart later — the edge forwards regardless, and
any bait approved via the control plane becomes decodable automatically once the brain re-reads its
key directory (one `BS_BRAIN_KEYDIR_POLL_S` interval, default 10s; export
`BS_BRAIN_KEYDIR_POLL_S=1` before `blacksea up` for faster local iteration — the e2e harness does
exactly this).

### Steps 1-3 — register, build, approve

```
blacksea forge e2e_tests/hostname_grab/manifest.yaml --campaign e2e-test --callback https=http://127.0.0.1:8443
```

Does all three in one shot (see "Prepare a deployable instance" above). Equivalently, run each
step directly:

```
blacksea baits register e2e_tests/hostname_grab
```

If the bait was registered before the AES-256-GCM migration (manifest still lists
`_PRIVKEY`), refresh the stored manifest from disk instead:
```
blacksea baits register --refresh e2e_tests/hostname_grab
```

Expected output:
```
registered + staged 'hostname-beacon' v1.0.0 (tier 2, portable_artifact)
```

### Build an instance

```
blacksea instances build hostname-beacon --campaign e2e-test --callback https=http://127.0.0.1:8443
```

The factory generates a fresh master key `_KEY` and `instance_token`, injects
`_SERVER_URL`, `_TOKEN`, and `_KEY` into `payload.py`, bundles and stages it,
and writes `_KEY` straight to the brain's key directory — it is never persisted in
the registry. (`campaign_id` is recorded brain-side from the token, never injected.) Output:

```
built instance <instance_token> of 'hostname-beacon' (campaign 'e2e-test', status pending)
  artifact: bait.py (sha256 …) in /path/to/services/registry/artifacts/hostname-beacon/<timestamp>/to_stage
  approve with:  blacksea instances approve <instance_token>
```

Note the `<instance_token>` — you need it for the next step.

### Approve the instance

```
blacksea instances approve <instance_token>
```

Transitions the instance to `active` and refreshes the brain key directory
(`secrets/keys/brain_keydir.json`, the sole key directory) to disk. The dev-managed brain
(Step 0) re-reads it on its own within one poll interval — nothing to do. The edge is a dumb
dead-drop: it holds no directory and needs no update.

### Step 4 — trigger the payload

Run the built artifact `forge`/`build` printed as `artifact:` (pure stdlib — any Python 3.11+
works, venv or not):

```
.venv/bin/python registry/artifacts/hostname-beacon/<timestamp>/to_stage/bait.py
```
(from `services/`; `blacksea instances artifact <instance_token>` prints the exact path)

The payload collects the hostname, constructs and encrypts the envelope (HMAC-SHA256 AEAD),
and POSTs it to the edge. No output on success — errors are swallowed by design.

### Step 5 — verify the record

Read it back with the console — newest first, filtered to this bait:

```
blacksea events ls --bait hostname-beacon
blacksea events show <record_id>     # full record incl. details.hostname
```

Or follow new hits live while you fire (`Ctrl-C` to stop):

```
blacksea events tail --bait hostname-beacon
```

`blacksea logs` (the edge + brain daemon logs) shows the brain-side confirmation too — a line like:
```
stored record <record_id> (bait=hostname-beacon sig_valid=True event=payload_exec_collect)
```
(`sig_valid` reflects the brain's HMAC-SHA256 AEAD decrypt+auth result, not a signature — the
column name is retained from the prior Ed25519-signing design, see src/blacksea/brain/context.md.)

---

Done testing? `blacksea reset` clears the registry, keydirs, Postgres records, and NATS
backlog this walkthrough created, and `blacksea down` stops any processes still running.

---

## Files

| File | Role |
|---|---|
| `manifest.yaml` | Bait metadata consumed by the control-plane factory and brain pool; `payload_file`/`listener_class`/`staging_vessel` point into `lure_material/` |
| `e2e_test.sh` | Automated test: forges an instance, triggers the payload, and verifies a record lands in Postgres against a live `blacksea up` stack. Picked up by `make test-e2e`. Sources the shared `../lib.sh`. |

`payload.py` and `listener.py` moved to `lure_material/payloads/hostname_grab/`; the
NOP staging vessel (copies the bundle as-is) moved to
`lure_material/staging_vessels/identity/` — see those directories for their role.

## SDK modules involved

| Module | Role |
|---|---|
| `blacksea.sdk.payload.envelope` | `build_encrypted_envelope` — packs the fixed binary core, seals it with a pure-stdlib HMAC-SHA256 AEAD, returns JSON envelope bytes |
| `blacksea.sdk.payload.http` | `send_https_encrypted` — builds + POSTs the HMAC-SHA256 AEAD envelope |
