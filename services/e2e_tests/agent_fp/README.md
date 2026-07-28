# agent_fp — agent-harness-fingerprint end-to-end test

Demonstrates the full Blacksea pipeline for a tier-2 HTTPS bait aimed specifically at
**attributing the LLM-driven agent harness** operating the worker (Blacksea's core detection
target — see the repo-root `README.md`), rather than just recording that a hit happened:
`payload.py` → control-plane factory (bundle + stage) → `registry/artifacts/agent-fp/…/bait.py`
→ edge (HTTPS) → NATS → brain → Postgres.

`payload.py` and `listener.py` live in `../../../lure_material/payloads/agent_fp/` (the
reusable catalog — see `lure_material/README.md`); this entry's `staging_vessel` is the
NOP `identity` vessel (a plain file drop — same as `hostname_grab`), since the point of this
bait is the fingerprint collection + inference, not a novel delivery mechanism.

**What it collects.** `payload.py` runs a minimal grabber inside the target worker: it reads
`os.environ`, the cwd listing, `/proc/*/cmdline` (Linux only — yields nothing elsewhere), and any
`pyproject.toml`/`package.json`/`go.mod` under the cwd or `$HOME`. A few small fields it computes
locally and sends as-is (`host_lit`, `pkg`, `bins`, `model`); the rest of the noise-filtering (which
env vars / cwd entries / value tokens are generic OS clutter vs. harness-owned signal) happens
**server-side in the listener** — the payload instead sends narrower-but-raw precursor material
(`envk`: env var names, no values; `cwdnames`: cwd basenames; `boolenv`/`valenv`: only the handful
of env values ever worth reading — never arbitrary env values like `PATH` or secrets). This split
(2026-07-23) trades wire-body size for embedded-artifact size: the noise-filtering knowledge base
was ~45% of the bundled payload, which mattered because some staging vessels have a small
embedding budget (pwcrypt's vault header caps at 4096 bytes — the original payload didn't fit;
the split payload does, with room to spare). See `lure_material/payloads/agent_fp/listener.py`'s
module docstring and `FIELDS` table for the full raw-wire vocabulary, and `_resolve_report()` for
where the moved reduction happens. Only non-empty fields are ever put on the wire, so a quiet/clean
machine still sends a near-empty body. The JSON is encrypted (HMAC-SHA256 AEAD) and POSTed to the
edge exactly like `hostname_grab`.

**What the listener does.** `listener.py`'s `AgentFingerprintListener` resolves the wire JSON's
raw fields into the same `ns`/`ns_n`/`disc_k`/`cwd`/`cwd_n`/`valtok` shape the payload used to
compute itself (`_resolve_report()`), reconstructs a `Report` from the result, and runs
`RuleInference` — a deterministic, evidence-carrying, abstention-capable scorer — against the
32-harness signature knowledge base in `signatures.yaml` (CAI,
STRIX, claude_code, opencode, aider, cline, roo-code, gemini-cli, ...). The resulting
`AnalyzerOutput.details` carries `harness`, `family`, `confidence`, `model`, `runner_up`,
`wrapper`, `abstained`, and `evidence` — enough to see not just *that* a hit fired but *what
attributed it and why*, including the deliberate case where the engine abstains (too little or
too ambiguous signal) rather than guessing.

**Operator recon (2026-07-23, additive).** Alongside harness attribution, the payload also
collects three operator/actor-intel signals — useful regardless of which harness is driving the
worker — surfaced directly in `details` as their own keys, never mixed into the harness `fields`
evidence list or scored by `RuleInference`: `cred_surface` (which well-known credential/access
files exist — `~/.aws/credentials`, `~/.config/gcloud`, `~/.kube/config`,
`~/.docker/config.json`, an `~/.ssh/id_*` private key — presence only, contents never read),
`locale` (timezone name, UTC offset, `$LANG` — an OSINT signal for geographic origin / working
hours), and `history` (size + mtime of `.bash_history`/`.zsh_history`/`.python_history` — never
the command text, a rough freshness/activity proxy). Every collector, old and new, runs through
a `_safe()` wrapper so a failure or unsupported platform quirk in any one field degrades to that
field simply being absent rather than crashing the payload or losing the beacon; the listener
mirrors this with per-field guards in `_resolve_report()` and an outer safety net in
`interpret()`, so a malformed field costs only itself, never the rest of the record.

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
blacksea forge e2e_tests/agent_fp/manifest.yaml
```

Registers `agent-fp` with the control plane (or refreshes its stored manifest if already
registered — this also runs the golden tests declared in `listener.py`, blocking registration on
any failure), builds a fresh per-instance artifact (real master key + `instance_token`), and
approves it — all in one step, driven by the manifest's `deploy:` block. It does **not**
run/trigger the payload. Prints the path to the final, self-contained artifact
(`registry/artifacts/agent-fp/<timestamp>/to_stage/bait.py`) — the actual file to place on a
honeypot, with `_SERVER_URL`/`_TOKEN`/`_KEY` already injected — not the source `payload.py`.
Add `--json` for a machine-readable result, or `--no-approve` to stop at a pending instance.

To fire it by hand afterwards, run the artifact `forge` printed (pure stdlib — any Python 3.11+
works) and read the record back with the console:

```
.venv/bin/python <the artifact: path printed above>
blacksea events ls --bait agent-fp        # newest record on top
blacksea events show <record_id>          # full record incl. details.harness / .confidence / .evidence
```

For the full automated fire-and-verify test, see below.

---

## Full E2E test

Tests the complete stack: bait fires → edge verifies → NATS → brain interprets (runs
`RuleInference`) → record in Postgres.

### One command

```
./e2e_test.sh
```

Brings up the dev stack if it isn't already (`blacksea up`), forges an instance (register the
design, build a fresh instance under campaign `e2e-test`, approve it), waits for the edge and
brain to hot-swap in the new snapshot/key, triggers the payload, and polls Postgres until the
resulting record shows up (or fails after ~10s). Safe to re-run — each run registers/refreshes
the bait and builds a brand-new instance, same as running the manual steps below repeatedly.
Override the campaign with `CAMPAIGN=my-campaign ./e2e_test.sh` or the callback URL with
`./e2e_test.sh http://127.0.0.1:9999`.

Because the fingerprint is collected from *this* machine (whatever runs the test), the resulting
record's `details.harness` will most likely be `null`/abstained unless the test happens to run
inside an actual agent-harness worker — that is expected and is itself a golden-covered outcome
(see `lure_material/payloads/agent_fp/listener.py`'s "clean machine" case); the test only asserts
that a record lands, not which harness it names.

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
blacksea forge e2e_tests/agent_fp/manifest.yaml --campaign e2e-test --callback https=http://127.0.0.1:8443
```

Does all three in one shot (see "Prepare a deployable instance" above). Equivalently, run each
step directly:

```
blacksea baits register e2e_tests/agent_fp
```

Expected output:
```
registered + staged 'agent-fp' v1.0.0 (tier 2, portable_artifact)
```

### Build an instance

```
blacksea instances build agent-fp --campaign e2e-test --callback https=http://127.0.0.1:8443
```

The factory generates a fresh master key `_KEY` and `instance_token`, injects
`_SERVER_URL`, `_TOKEN`, and `_KEY` into `payload.py`, bundles and stages it,
and writes `_KEY` straight to the brain's key directory — it is never persisted in
the registry. (`campaign_id` is recorded brain-side from the token, never injected.) Output:

```
built instance <instance_token> of 'agent-fp' (campaign 'e2e-test', status pending)
  artifact: bait.py (sha256 …) in /path/to/services/registry/artifacts/agent-fp/<timestamp>/to_stage
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
.venv/bin/python registry/artifacts/agent-fp/<timestamp>/to_stage/bait.py
```
(from `services/`; `blacksea instances artifact <instance_token>` prints the exact path)

The payload collects the reduced fingerprint fields, constructs and encrypts the envelope
(HMAC-SHA256 AEAD), and POSTs it to the edge. No output on success — errors are swallowed by
design.

### Step 5 — verify the record

Read it back with the console — newest first, filtered to this bait:

```
blacksea events ls --bait agent-fp
blacksea events show <record_id>     # full record incl. details.harness / .confidence / .evidence
```

Or follow new hits live while you fire (`Ctrl-C` to stop):

```
blacksea events tail --bait agent-fp
```

`blacksea logs` (the edge + brain daemon logs) shows the brain-side confirmation too — a line like:
```
stored record <record_id> (bait=agent-fp sig_valid=True event=payload_exec_collect)
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

`payload.py`, `listener.py`, and `signatures.yaml` live in `lure_material/payloads/agent_fp/`;
the NOP staging vessel (copies the bundle as-is) is the shared `lure_material/staging_vessels/identity/`
— see those directories for their role.

## SDK modules involved

| Module | Role |
|---|---|
| `blacksea.sdk.payload.envelope` | `build_encrypted_envelope` — packs the fixed binary core, seals it with a pure-stdlib HMAC-SHA256 AEAD, returns JSON envelope bytes |
| `blacksea.sdk.payload.http` | `send_https_encrypted` — builds + POSTs the HMAC-SHA256 AEAD envelope |
