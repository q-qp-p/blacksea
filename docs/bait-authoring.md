# Bait Authoring Guide

A **bait** is one deceptive lure. In Blacksea every bait is authored as **three separate components** plus a declarative manifest:

| Component | File | Runs… | Role |
|---|---|---|---|
| **Payload** | `payload.py` | on the *target* (attacker's box) | collects something and beacons it home |
| **Listener** | `listener.py` | in the *brain* (your trusted plane) | decodes the beacon and interprets it into intel |
| **Staging vessel** | `staging_vessel/setup.sh` | in the *control plane* at build time | wraps the bundled payload into its delivery artifact |

A fourth file — `manifest.yaml` — declares how they fit together. This guide is **self-contained**: read it top to bottom and you have everything needed to produce all three components, the manifest, and register the result. Every step past "write the files" — register, build, approve, forge — goes through the **`blacksea` console**, the single operator entry point (see §7 and [`docs/console.md`](./console.md) for its full command reference).

> **The one rule that shapes everything:** the payload (target side) and the listener (server side)
> are the *same bait split across two files*. They must agree byte-for-byte on how a body is
> serialised. There is no structural enforcement of this across two files — keeping them in sync is
> the author's job. The golden tests exist to catch drift.

---

## Contents

1. [The SDK, the three-component model, and the build pipeline](#1-the-sdk-the-three-component-model-and-the-build-pipeline)
2. [Directory layout of one bait](#2-directory-layout-of-one-bait)
3. [Authoring `payload.py`](#3-authoring-payloadpy)
4. [Authoring `listener.py`](#4-authoring-listenerpy)
5. [Authoring `staging_vessel/setup.sh`](#5-authoring-staging_vesselsetupsh)
6. [`manifest.yaml` — the declarative manifest](#6-manifestyaml--the-declarative-manifest)
7. [Registering, building, and deploying with the `blacksea` console](#7-registering-building-and-deploying-with-the-blacksea-console)
8. [Multiple vessels for the same payload + listener](#8-multiple-vessels-for-the-same-payload--listener)
9. [Quick-start: a new bait from scratch](#9-quick-start-a-new-bait-from-scratch)

---

## 1. The SDK, the three-component model, and the build pipeline

`blacksea.sdk` is the **only** package a bait author ever imports — never `blacksea.brain`, `blacksea.control_plane`, `blacksea.correlation`, or `blacksea.console`. It is deliberately small, entirely standard library, and split into two halves along the trust boundary a bait crosses:

| Half | Import surface | Runs where | What it gives you |
|---|---|---|---|
| **target-side** (payload) | `blacksea.sdk.payload.*` | on the attacker's machine, inside the bundled self-contained file | comms primitives — `send_dns`, `send_dns_multiturn`, `send_http`, `send_https_encrypted`, `build_encrypted_envelope` (§3 below) |
| **server-side** (listener) | `blacksea.sdk.listener` — **one import, nothing else** | in the brain's analyzer pool | the `Listener` ABC, every frozen type you touch (`Envelope`, `AnalyzerOutput`, `Signals`, `GoldenCase`, `ObservedSource`), `BodyDecodeError`, and the golden-test harness (§4 below) |

Both halves are **pure standard library** — no third-party runtime dependency anywhere in `blacksea.sdk`, at any tier. That isn't incidental: it's what lets the bundler ship a payload that runs on stock Python 3 with nothing to `pip install` on the target.

**Why the import surface is split this way.** The package root (`blacksea.sdk`) never re-exports `Listener` or the SDK types — importing them from the root doesn't work, and that's deliberate. The bundler flattens a payload by vendoring every package it imports; if the root re-exported the listener ABC and its types, **every** payload bundle would drag in the golden-test runner and code a beacon never uses. So keep the halves apart: a payload imports only `blacksea.sdk.payload.*`, a listener imports only `blacksea.sdk.listener`, and neither reaches into the other's territory.

Everything downstream of the SDK — flattening your payload into one file, injecting per-instance secrets, driving the staging vessel, managing the catalog, running your listener in the brain — is orchestrated for you by the **`blacksea` console** (§7). As a bait author, you write against the SDK directly; you drive the console to move what you wrote from source to a live instance.

```
                                  CONTROL PLANE (build time)
   payload.py  ──inject constants──►  bundled payload  ──staging vessel──►  artifact
  (target code)   (_ZONE, _TOKEN,     (one self-contained       (setup.sh)       (deployed
                   _KEY, … prepended)   .py, stdlib-only)                          to target)
        │
        │ the bundled payload already contains the instance token + AES key as literals
        ▼
   staging_vessel NEVER sees the token/key as separate values (§5 below)
```

What `blacksea forge` / `blacksea instances build` (§7) drive at `build` time, in order:

1. **Generate secrets** for this instance: a random `instance_token` (8 B) and a per-instance master key `_KEY` (32 B, HMAC-SHA256 AEAD). `_KEY` is written straight to the brain's key directory (`brain_keydir.json`) and **never** to the registry.
2. **Resolve `build_vars`** — the names your manifest declares (e.g. `_ZONE`, `_TOKEN`) — to concrete values from the instance config (see the standard-var table below).
3. **Inject** those constants as module-level literals prepended to `payload.py`.
4. **Bundle**: inline every `blacksea.sdk.payload.*` import your payload uses, producing **one self-contained `.py` that runs on stock Python 3** with no `blacksea` package present.
5. **Stage**: hand the bundled file to `staging_vessel/setup.sh`, which produces the final delivery artifact(s) and declares them in an `artifact.json` manifest.
6. **Record** the artifact descriptor + `key_ref` in the registry instance record.

Because the token and key are embedded as literal Python constants in step 3/4, the bundled payload already carries them — the staging vessel in step 5 **never receives them as separate inputs**. This is the "no secret material in context" rule (§5 below) and it is why vessels can't accidentally leak secrets.

### Standard build variables the factory resolves for you

The factory auto-resolves these well-known names from the instance config. Any *other* name your manifest declares must be supplied at build time via `--set NAME=VALUE` (an unresolved name fails the build — never a silent pass):

| Name | Resolved from | Type |
|---|---|---|
| `_TOKEN` | `instance_token` | hex string (16 chars) |
| `_KEY` | per-instance master key (HMAC-SHA256 AEAD) | hex string (64 chars / 32 B) |
| `_ZONE` | `callback_addresses["dns"]` | DNS zone, e.g. `cb.example.com` (only if the bait has a `dns` channel) |
| `_SERVER_URL` | `callback_addresses["https"]` | HTTPS endpoint, e.g. `https://cb.example.com:8443` (only if the bait has an `https` channel) |

> **`campaign_id` is not injectable.** The payload never receives it and it never travels on the
> wire. The brain derives `campaign_id` from the key directory keyed by `instance_token` and
> records it there — so campaign scope stays entirely backend-side. Don't declare `_CAMPAIGN` in
> `build_vars` (it would fail the build as an unresolved name).

Reference your injected constants in the payload as **globals** (they're prepended above your code). Because they're injected at build time, a linter can't see them — annotate with `# noqa: F821`:

```python
send_dns(_TOKEN, _ZONE, _socket.gethostname().encode())  # noqa: F821  (injected at build)
```

### Testing your payload's bundle locally, before registering

The bundler that flattens `payload.py` at `build` time is also installed as its own console-script, `bs-bundle` (same `make install` as `blacksea`), so you can see exactly what your payload will look like once flattened — no registration, no control plane, no infra:

```bash
bs-bundle ../lure_material/payloads/<name>/payload.py \
    --root src \
    --var _ZONE='"cb.example.com"' --var _TOKEN='"deadbeef01234567"'
```

It walks your payload's **static import graph** (an AST walk over `import`/`from ... import` statements), starting at the entry-point script and vendoring every module reachable **under `--root`** — this is the mechanism by which `from blacksea.sdk.payload.dns import send_dns` becomes inlined source in the bundled output instead of an import statement. Anything *outside* `--root` (stdlib, third-party) is left as an ordinary import — exactly why every `blacksea.sdk.payload.*` primitive must stay stdlib-only: a third-party import inside a vendored module would survive bundling as a dependency the target doesn't have. `--var NAME=VALUE` mimics the constant-injection step the factory performs for you at real build time; `--include-module` force-vendors anything invisible to static analysis (a dynamic import); `--minify`/`--strip-comments` shrink the output. This is a debugging aid for bait authors — `blacksea forge` / `instances build` (§7) run the same bundler internally, with the real per-instance token and key.

---

## 2. Directory layout of one bait

A bait is declared by a **single file**, `manifest.yaml` — the payload, listener, and staging vessel are never written or copied next to it. They live in the repo-root catalog, `lure_material/payloads/<name>/` (payload + listener pair) and `lure_material/staging_vessels/<name>/` (delivery mechanism) — sibling of `services/`, see `lure_material/README.md` — and the manifest references them by a `../`-relative path:

```
<bait_dir>/
└── manifest.yaml         # the ONLY file — references payload/listener/vessel by path (see §6)
```

```yaml
# <bait_dir>/manifest.yaml   (the ../ count depends on <bait_dir>'s depth — see below)
listener_class: ../../../lure_material/payloads/<name>/listener.<ClassName>
payload_file:   ../../../lure_material/payloads/<name>/payload.py
staging_vessel: ../../../lure_material/staging_vessels/<vessel-name>
```

**A manifest can live anywhere** — there is no dedicated `baits/` directory. The factory, ingestion, and brain pool resolve `payload_file` / `listener_class` / `staging_vessel` via plain `os.path.join(bait_dir, ...)` + `importlib`, so a manifest works from wherever it sits as long as its relative paths reach `lure_material/`. In this repo the concrete homes are the automated end-to-end baits under `e2e_tests/<name>/` (three `../` to the repo root: `<name>` → `e2e_tests` → `services` → root) and the unit-test reference bait at `test_fixtures/baits/hostname_probe/` (four: `hostname_probe` → `baits` → `test_fixtures` → `services` → root). **Path depth matters** — don't copy a path string between two bait dirs at different depths without adjusting the `../` count.

**Reuse vs. new design.** The common case is *reusing* an existing catalog entry — just write a new `manifest.yaml` referencing the `lure_material/payloads/<name>/` + `staging_vessels/<vessel>/` you want (this is also how you get **multiple staging vessels for one payload/listener design**: two manifests, same payload entry, different vessel — no copy or symlink). Authoring a *genuinely new* payload/listener/vessel design means writing it in `lure_material/` **first** (§3–§5), then declaring a manifest that references it. Then `blacksea baits register <bait_dir>/` runs the ingestion gate (including the golden tests, §7) — no registration succeeds with a failing golden case.

`lure_material/` (implementations) + a manifest (declaration) are the **only** things a bait author writes. Never import from (or edit) `sdk/`, `brain/`, `control_plane/`, `correlation/`, `edge/`, or `console/`. The single permitted import surface for payload/listener code is `blacksea.sdk` (specifically `blacksea.sdk.payload.*` from payloads and `blacksea.sdk.listener` from listeners).
---

## 3. Authoring `payload.py`

The payload is a standalone Python script that runs on the target. Two hard rules:

- **Never crash on a failed callback.** Every comms primitive swallows its own errors; respect that contract — wrap your own logic so a dead network never raises.
- **Reference injected constants as globals** (`_ZONE`, `_TOKEN`, `_KEY`, …), annotated `# noqa: F821`.

### Communication primitives (`blacksea.sdk.payload.*`)

These are stdlib-only functions the bundler inlines into your payload, so the bundled output needs no `blacksea` package and no third-party libraries at all, at any tier.

| Import | Signature | Channel / tier | Notes |
|---|---|---|---|
| `payload.dns.send_dns` | `send_dns(token, zone, body=b"", server="")` | DNS · **tier 0** (signal only) | packs the 19B header (`ev\|flags`, `instance_token`, random `session_id`, `seq_no`) ahead of `body`, base32-encodes, splits across ≤63-char labels (modes 1-2), sends `<labels>.<zone>` as an A-query — via the OS resolver, or (if `server="host:port"` given) a hand-rolled raw UDP query direct to that address, bypassing the resolver (local/test only — omit for real deployments, which rely on DNS delegation). **No signature/`enc`** — DNS is unsigned by channel definition; `body` still rides the free per-query byte budget (~20-110 B) if you want to carry a short observed-tier fact alongside the signal. |
| `payload.dns_multiturn.send_dns_multiturn` | `send_dns_multiturn(data, zone, delay)` | DNS · tier 0 | base32-chunks arbitrary bytes across sequential queries (set `dns.max_chunks` in the manifest; warns above 50). |
| `payload.http.send_http` | `send_http(url, data, headers=None)` | HTTPS · raw POST | low-level; prefer `send_https_encrypted`. |
| `payload.http.send_https_encrypted` | `send_https_encrypted(url, body, key_hex, instance_token_hex, *, session_id=None, seq_no=0)` | HTTPS · **tier 2** | builds the encrypted `{ev, tok, enc}` envelope (HMAC-SHA256 AEAD, pure stdlib) and POSTs it. |
| `payload.envelope.build_encrypted_envelope` | `build_encrypted_envelope(body, key_hex, instance_token_hex, *, session_id=None, seq_no=0)` | — | raw envelope builder (returns bytes) if you need to ship the envelope over your own transport. |

**Tier ↔ channel pairing** (enforced/warned at registration, see §6 below): DNS is tier-0 only (no signed body); tier ≥ 1 requires a "fat" channel (HTTPS) to carry the encrypted body.

### Example: tier-0 DNS beacon (the `hostname_probe` payload)

```python
#!/usr/bin/env python3
# hostname-probe payload.
# Bundled at factory time: _ZONE and _TOKEN are injected as module-level constants
# before this file is fed to the bundler; blacksea.sdk.payload is inlined so the
# output runs on stock Python 3.
from blacksea.sdk.payload.dns import send_dns
import socket as _socket
import json as _json

_body = _json.dumps({"hostname": _socket.gethostname()}).encode()
send_dns(_TOKEN, _ZONE, _body)  # noqa: F821  (_TOKEN/_ZONE injected at build)
```

For local testing, where the DNS zone usually isn't really delegated to your dev edge, declare `_DNS_SERVER` in `build_vars` and pass it as a fourth positional arg — see `e2e_tests/hostname_grab_dns/` for a complete worked example (manifest + payload + listener).

### Example: tier-2 HTTPS payload (encrypted body)

```python
#!/usr/bin/env python3
# Collect a fact, beacon it home over the encrypted HTTPS channel.
import json as _json
import socket as _socket
from blacksea.sdk.payload.http import send_https_encrypted

body = _json.dumps({"hostname": _socket.gethostname()}).encode()
# _SERVER_URL, _TOKEN, _KEY are injected at build time:
send_https_encrypted(_SERVER_URL, body, _KEY, _TOKEN)  # noqa: F821
```

For a complete, real tier-2 payload built exactly this way — collecting a richer body than one field and driving actual inference server-side — see `../lure_material/payloads/agent_fp/payload.py`, Blacksea's flagship payload (§2 above).

---

## 4. Authoring `listener.py`

The listener is the server-side half: it decodes the beacon `body` and classifies the hit. Import everything from **one** place:

```python
from blacksea.sdk.listener import (
    Listener, AnalyzerOutput, BodyDecodeError, Envelope, GoldenCase,
    Signals, test_envelope, ANY,
)
```

It is a **pure function with no ambient authority**: no I/O, no `eval`, no external modules, bounded time + memory, and it must **never raise**. The brain's analyzer pool calls `interpret()` once per inbound hit under a timeout.

You author your listener by subclassing `Listener`. It has **no `build()` method** — the build side is entirely the console/factory's job, driven from your separate `payload.py` and `staging_vessel/setup.sh`.

### The `Listener` ABC — methods to implement

| Method | Required | Contract |
|---|---|---|
| `encode_body(self, data: dict) -> bytes` | yes | canonical serialisation of a body dict → bytes. Must be **deterministic**. This is the reference serialiser your payload must match byte-for-byte. |
| `decode_body(self, body: bytes) -> dict` | yes | inverse of `encode_body`. **Must not raise** on truncated/partial input — return best-effort. Raise `BodyDecodeError` **only** on completely unrecoverable input (wrong magic, bad version). Never raise any other type. |
| `interpret(self, envelope: Envelope, body: bytes) -> AnalyzerOutput` | yes | classify one hit. **Must handle `body == b""`** (tier-0 signal-only). **Must not raise** — catch everything and surface it in `details` under a `_`-prefixed key. Internally calls `decode_body` and catches `BodyDecodeError`. |
| `golden_cases(self) -> list[GoldenCase]` | yes | offline `interpret()` fixtures; run at registration (any failure blocks it). Must include **at least one `body=b""`** case. |
| `on_register` / `on_deploy(instance_token)` / `on_burn(reason)` / `on_retire` | no | lifecycle hooks, default no-op. Same no-ambient-authority rules as `interpret`. |

### The types you return

```python
@dataclass
class Envelope:                 # brain-verified, handed to interpret(); body is passed separately
    ev: int                     # envelope version
    bait_id: str
    bait_version: str
    instance_token: bytes       # 8 B
    campaign_id: str
    assurance_tier: int         # 0 | 1 | 2
    session_id: bytes           # 8 B
    seq_no: int                 # uint16; 0 = single-shot tripwire
    sensor_time: int            # ms, claimed-tier
    channel: str                # "dns" | "https" | ...
    edge_recv_time: int         # ms, observed-tier (trusted)
    observed_source: ObservedSource   # ip, ja3, source_type
    edge_id: str
    sig_valid: bool             # brain's authoritative re-verify result

@dataclass
class AnalyzerOutput:           # what interpret() returns; framework merges it into the Record
    event_type: str             # from the event_type enum; must be non-empty
    signals: Signals | None = None
    details: dict | None = None # opaque, pair-specific intel; size-capped by the framework

@dataclass
class Signals:                  # optional promoted fields Tier-2 reads (it never reads details)
    fingerprint_hash: str | None = None
    caution_level: str | None = None        # "none"|"low"|"medium"|"high"
    explicit_session_end: bool | None = None
```

You **cannot** set framework fields (`sig_valid`, `instance_token`, `session_id`, …) from `interpret()` — the framework assembles the full Record and your output is merged in. Only fill `event_type`, `signals`, `details`. Omit any `Signals` field you can't honestly compute (a faked `caution_level` poisons burn detection).

### Keeping `encode_body` ↔ the payload in sync

`encode_body` is the canonical serialiser; the payload's own serialisation must produce **equivalent bytes** for the same logical data. They live in separate files and there's no structural check — the golden tests are your safety net. Pin the serialiser down hard: pick one format, make it sorted and deterministic, and use the identical call in both places.

### Golden tests

Build fixtures with `test_envelope(...)` (a fixture *builder*, not a pytest test — despite the `test_` prefix, `blacksea.sdk.testing` marks it `__test__ = False` so pytest never tries to collect it itself):

```python
test_envelope(tier=2, bait_id="hostname-probe")                 # tier-2 HTTPS defaults
test_envelope(tier=0, bait_id="hostname-probe", channel="dns")  # tier-0 signal-only (sig_valid=False)
```

`test_envelope()` fills in every `Envelope` field with a stable, recognisable default (fixed `instance_token`/`session_id`, a fixed `sensor_time`) so you only override what your case cares about; `channel` defaults to `https` for `tier >= 1` and `dns` for `tier == 0`, and `sig_valid` defaults to `tier >= 1` (tier-0 is unsigned by definition — §1).

**How a case is scored** (`run_golden_case` in `blacksea.sdk.testing`): it calls your `interpret(case.envelope, case.body)` inside a `try`/`except Exception` — if it raises at all, the case fails with "`interpret() must never raise`" rather than propagating, mirroring exactly what the brain's analyzer pool does with a real hit. `event_type` must match `expected.event_type` **exactly**. Matching is deliberately **loose** everywhere else, so a golden `expected` can assert only what matters:

- omit `signals` / `details` entirely on `expected` → that part isn't checked at all;
- set `expected.signals` but leave one of its fields `None` → that individual field isn't checked (the others still are);
- `expected.details` is matched as a **subset**: every key in `expected.details` must be present in the actual output (missing → fail), but the actual output may carry **extra** keys your case doesn't mention;
- use the `ANY` sentinel as a `details` value (or a `Signals` field) → the key/field must be **present**, but its value isn't asserted — useful for a hostname, a timestamp, or an error message you don't want to pin exactly.

Run them locally with `assert_golden(MyListener())` — it raises `AssertionError` listing every failing case's label + reason, handy from `pytest` or a REPL. `blacksea baits register` (§7) runs the same cases via `run_golden_cases()` at registration and blocks on any failure, reported one result per case — plus two registration-only gates that fire even before your cases are scored: `golden_cases()` returning an empty list, and no case in the list using `body == b""` (every listener **must** cover the signal-only / tier-0 shape).

### Full example (the `hostname_probe` listener)

```python
from __future__ import annotations
import json

from blacksea.sdk.listener import (
    AnalyzerOutput, BodyDecodeError, Envelope, GoldenCase, Listener, test_envelope,
)


class HostnameProbeListener(Listener):
    """Collects the attacker host's name reported via a DNS beacon."""

    def encode_body(self, data: dict) -> bytes:
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()

    def decode_body(self, body: bytes) -> dict:
        try:
            return json.loads(body.decode())
        except Exception as exc:
            raise BodyDecodeError(str(exc))

    def interpret(self, envelope: Envelope, body: bytes) -> AnalyzerOutput:
        if not body:
            return AnalyzerOutput(event_type="signal_only")
        try:
            data = self.decode_body(body)
        except BodyDecodeError as exc:
            return AnalyzerOutput(
                event_type="signal_only", details={"_decode_error": str(exc)}
            )
        return AnalyzerOutput(
            event_type="payload_exec_collect",
            details={"hostname": data.get("hostname")},
        )

    def golden_cases(self) -> list[GoldenCase]:
        return [
            GoldenCase(
                label="normal hit — hostname reported",
                body=self.encode_body({"hostname": "victim-box"}),
                envelope=test_envelope(tier=2, bait_id="hostname-probe"),
                expected=AnalyzerOutput(
                    event_type="payload_exec_collect",
                    details={"hostname": "victim-box"},
                ),
            ),
            GoldenCase(
                label="signal-only (zero body, tier 0)",
                body=b"",
                envelope=test_envelope(tier=0, bait_id="hostname-probe", channel="dns"),
                expected=AnalyzerOutput(event_type="signal_only"),
            ),
        ]
```

---

## 5. Authoring `staging_vessel/setup.sh`

The staging vessel is the **final build step** that transforms the bundled payload into its delivery artifact(s). Every bait declares one in `staging_vessel/setup.sh`. The vessel receives structured input via a JSON context file, must emit an `artifact.json` manifest declaring its outputs, and is validated by the factory before the artifact is recorded.

### Invocation

```bash
bash <staging_vessel_dir>/setup.sh <context.json>
```

**Single argument:** absolute path to a JSON context file. The factory creates this file, invokes the vessel, then deletes it.

### Input: `context.json`

```json
{
  "bundled_payload_path": "/tmp/xxxx_bundled.py",
  "bundling_outputs_dir": "/abs/path/to/root/bundling_outputs",
  "output_dir": "/abs/path/to/root/to_stage",
  "output_dir_root": "/abs/path/to/root",
  "bait_id": "hostname-beacon",
  "bait_version": "1.0.0",
  "campaign_id": "campaign-abc",
  "target_arch": ["x86_64-linux"],
  "toolchain": "python3.11",
  "callback_addresses": { "https": "https://cb.example.com:8443", "dns": "cb.example.com" },
  "seed": "3f9c1a7b2e6d..."
}
```

| Field | Meaning |
|---|---|
| `bundled_payload_path` | absolute path to the self-contained bundled payload. Read-only; cleaned up by the factory after the vessel finishes. |
| `bundling_outputs_dir` | absolute path to bundler transformation artifacts (bundled.py, .gz, .b64, ready_for_vessel.txt, bundle_manifest.json). Vessels **read** from here but do NOT write to it. |
| `output_dir` | absolute path to the `to_stage/` directory for **deployment artifacts only**. Pre-created, empty when the vessel starts. This is what gets deployed. |
| `output_dir_root` | absolute path to the root directory (parent of `bundling_outputs/` and `to_stage/`). Vessels write `artifact.json` here, not in `output_dir`. |
| `bait_id` / `bait_version` | from the manifest. |
| `campaign_id` | campaign ID for this build instance. |
| `target_arch` | from `manifest.build.target_arch` (e.g. `["x86_64-linux"]`). |
| `toolchain` | from `manifest.build.toolchain` (e.g. `"python3.11"`, `"gcc"`); `"unspecified"` if omitted. |
| `callback_addresses` | per-channel callback addresses resolved from instance config. |
| `seed` | fresh 32-char hex, unique per build. **Seed any RNG from this** (layout randomisation, padding) — do **not** call `os.urandom()` directly. |

**Secrets are deliberately absent.** `instance_token` and `_KEY` are **not** in `context.json` — they are already embedded as literals in the bundled payload before staging. The vessel never sees them as separate values — the key is never exposed beyond the artifact it's embedded in.

### Output: `artifact.json` (required before exit 0)

The vessel **must** write `<output_dir_root>/artifact.json` (**not** inside `output_dir`):

```json
{
  "primary": "bait_binary",
  "files": {
    "bait_binary": { "role": "binary" },
    "README.md":   { "role": "doc" },
    "bait_binary.sig": { "role": "signature" }
  }
}
```

**Location:** `artifact.json` goes in the **root directory** (`output_dir_root`), not inside `to_stage/` (`output_dir`). This separates build metadata from deployment artifacts.

| Field | Meaning |
|---|---|
| `primary` | name of the primary artifact (the one to execute/deploy). Must be a key in `files` and exist on disk in `output_dir` (the `to_stage/` directory). |
| `files` | map of filename → metadata. **Every** file physically present in `output_dir` must be listed — any unlisted file is a `BuildError`. Files in `bundling_outputs_dir` are NOT declared (factory-managed). |
| `files[name].role` | semantic role: `"binary"`, `"script"`, `"doc"`, `"config"`, `"signature"`, … Recorded for auditing; not validated by the factory. |

The factory then computes the `Artifact` descriptor: `filename` = `primary`, `sha256` of the primary on disk, and a per-file `sha256` map. **Hashes are never trusted from the vessel** — the factory always reads and hashes from disk.

### Output: `how_to_stage.md` (recommended, operator-only)

Alongside `artifact.json`, a vessel **should** also write `<output_dir_root>/how_to_stage.md` — a short operator-facing note explaining how to deploy *this build's* artifact and the exact command that fires it. It exists so an operator staging the artifact weeks later doesn't have to re-derive the trigger command from the vessel's source.

**Location:** `output_dir_root`, the same directory as `artifact.json` — **never** inside `output_dir` (`to_stage/`). `to_stage/` is what gets deployed to the honeypot; a file that tells an attacker how the bait works has no business shipping with it. A vessel that declares `how_to_stage.md` in `artifact.json`'s `files` map (i.e. stages it into `to_stage/`) gets a `BuildError` — this is enforced, not just documented.

**Content — three short sections, no fixed schema:**
1. What this artifact is (one or two sentences — the delivery mechanism's cover story/shape).
2. How to place it on the target (permissions, companion files, working directory).
3. The exact command to trigger it — built from *this build's* actual output (primary filename, any per-build config filenames), not a generic template.

Generate it the same way you generate any other per-build content (e.g. the staged, attacker-facing `README.md`): a heredoc or small Python snippet in `setup.sh`, using `context.json`'s fields and whatever the vessel just staged. See `../lure_material/staging_vessels/pwcrypt/setup.sh` for a worked example (the primary binary name varies per build with `target_arch`).

**Enforcement:** advisory, not required for `exit 0`. If `<output_dir_root>/how_to_stage.md` is missing, the factory records a warning (surfaced to the operator via `blacksea forge`/`instances build`'s normal warnings output) and continues — existing vessels can adopt this gradually. The `to_stage/`-placement rule above is the one part that *is* hard-enforced (a security boundary, not an authoring convenience).

### Exit conditions

- **Exit 0** → success; the factory validates `artifact.json` and the declared files.
- **Non-zero** → failure; the factory captures `stderr`, raises `BuildError`, stops the build.
- The factory enforces a **300-second timeout**; a vessel that doesn't exit is killed → `BuildError`.

### Rules

1. **Opacity of payload.** The bundled payload is opaque bytes — the vessel wraps/delivers it, never parses or mutates its logic. It may append envelope framing (e.g. a shell heredoc wrapper) but must not decrypt, decompress, or modify the payload's executable content.
2. **No secret material in output.** Artifact files (other than optionally a signature over the payload) must not contain the bundled payload directly — that would leak it. A NOP vessel that just copies the bundled file is allowed for prototyping, but a real vessel embeds the payload inside a native binary, notebook kernel, container image, etc.
3. **Determinism.** Two invocations with identical `context.json` (same bundled file, same seed, same output_dir path) must produce byte-identical outputs **or** document which inputs are intentionally non-deterministic and why (comment in `setup.sh`). Audit-grade reproducibility isn't required yet, but design for it.
4. **Use `seed` for randomness.** Seed your RNG from `seed` for any non-deterministic content; never call `urandom()`/`getrandom()` directly.
5. **No network access by default.** Don't depend on git clones, package downloads, or remote compilation servers unless explicitly designed for and documented (supply-chain + audit risk).
6. **All output must be declared.** Any file left in `output_dir` that isn't in `files` → `BuildError` (catches leftover `.o` files, compiler temp dirs, partial outputs).
7. **Exit on timeout.** See above.

### Reference: minimal NOP vessel

```bash
#!/usr/bin/env bash
# Minimal reference staging vessel: reads context.json, copies payload, declares output.
set -euo pipefail

CONTEXT_JSON="${1:?usage: setup.sh <context.json>}"

# Parse context.json (Python one-liner to avoid a jq dependency).
BUNDLED=$(python3 -c "import json; print(json.load(open('$CONTEXT_JSON'))['bundled_payload_path'])")
OUTPUT=$(python3 -c "import json; print(json.load(open('$CONTEXT_JSON'))['output_dir'])")
OUTPUT_ROOT=$(python3 -c "import json; print(json.load(open('$CONTEXT_JSON'))['output_dir_root'])")

cp "$BUNDLED" "$OUTPUT/probe.py"
chmod +x "$OUTPUT/probe.py"

# artifact.json goes in root, not in to_stage/
cat > "$OUTPUT_ROOT/artifact.json" <<'EOF'
{ "primary": "probe.py", "files": { "probe.py": { "role": "script" } } }
EOF

echo "staged: $OUTPUT/probe.py"
```

### Reference: C-binary vessel with cross-compilation

Illustrates a vessel that compiles a C wrapper embedding the bundled payload with full cross-compilation support:

```bash
#!/usr/bin/env bash
set -euo pipefail

CONTEXT_JSON="${1:?usage: setup.sh <context.json>}"

# Parse context.json.
BUNDLED=$(python3 -c "import json; c=json.load(open('$CONTEXT_JSON')); print(c['bundled_payload_path'])")
BUNDLING_OUTPUTS=$(python3 -c "import json; c=json.load(open('$CONTEXT_JSON')); print(c['bundling_outputs_dir'])")
OUTPUT=$(python3 -c "import json; c=json.load(open('$CONTEXT_JSON')); print(c['output_dir'])")
OUTPUT_ROOT=$(python3 -c "import json; c=json.load(open('$CONTEXT_JSON')); print(c['output_dir_root'])")
TARGET_ARCH=$(python3 -c "import json; c=json.load(open('$CONTEXT_JSON')); print(c.get('target_arch', [''])[0] if c.get('target_arch') else '')")

# Map target_arch to compiler (cross-compilation pattern, see §5 above).
if [[ -n "$TARGET_ARCH" ]]; then
    case "$TARGET_ARCH" in
        x86_64-linux)
            CC=gcc
            EXTRA_CFLAGS="-m64"
            ;;
        aarch64-linux)
            CC=aarch64-linux-gnu-gcc
            EXTRA_CFLAGS=""
            ;;
        x86_64-darwin)
            CC=clang
            EXTRA_CFLAGS="-arch x86_64"
            ;;
        arm64-darwin)
            CC=clang
            EXTRA_CFLAGS="-arch arm64"
            ;;
        *)
            echo "error: unsupported target_arch '$TARGET_ARCH'" >&2
            exit 1
            ;;
    esac
    echo "cross-compiling for $TARGET_ARCH (CC=$CC)..." >&2
else
    CC=cc
    EXTRA_CFLAGS=""
    echo "building for host platform..." >&2
fi

# Use the bundler's ready-to-execute command string.
PAYLOAD_CMD=$(cat "$BUNDLING_OUTPUTS/ready_for_vessel.txt")

# Generate C wrapper embedding the payload command.
cat > "$OUTPUT/wrapper.c" <<EOF
#include <stdlib.h>
const char payload_cmd[] = "$PAYLOAD_CMD";
int main() {
    return system(payload_cmd) == 0 ? 0 : 1;
}
EOF

# Compile.
$CC $EXTRA_CFLAGS -O2 -Wall -o "$OUTPUT/bait_binary" "$OUTPUT/wrapper.c" 2>&1 || {
    echo "error: compilation failed" >&2
    exit 1
}

rm "$OUTPUT/wrapper.c"

# Declare the output — artifact.json goes in root, not in to_stage/
cat > "$OUTPUT_ROOT/artifact.json" <<'EOF'
{
  "primary": "bait_binary",
  "files": {
    "bait_binary": {"role": "binary"}
  }
}
EOF

echo "staged: $OUTPUT/bait_binary" >&2
```

For more complex examples (Makefile-based builds, multi-file artifacts, RCE delivery mechanisms), see:
- `../lure_material/staging_vessels/pwcrypt/` — cross-compiling C binary with RCE delivery
- `../lure_material/staging_vessels/identity/` — minimal NOP vessel (copies payload as-is)

### Bundler Artifacts in `bundling_outputs_dir`

Before invoking the vessel, the factory writes these transformation artifacts to `bundling_outputs_dir`:

| File | Purpose |
|------|---------|
| `ready_for_vessel.txt` | **USE THIS** — complete shell command to decompress and execute the payload |
| `bundled.py` | Flattened Python source (for debugging) |
| `bundled.gz` | gzip-compressed payload |
| `bundled.b64` | base64-encoded payload |
| `bundle_manifest.json` | Transformation metadata |

**Vessels MUST use `ready_for_vessel.txt` for payload transformation.** This file contains a complete, ready-to-execute system command string that decompresses and runs the bundled payload. Do NOT re-implement gzip+base64 encoding or other transformation logic — the bundler handles this.

**Example usage:**

```bash
# Parse bundling_outputs_dir from context.json
BUNDLING_OUTPUTS=$(python3 -c "import json; c=json.load(open('$CONTEXT_JSON')); print(c['bundling_outputs_dir'])")

# Correct way (use bundler's pre-generated string):
PAYLOAD_CMD=$(cat "$BUNDLING_OUTPUTS/ready_for_vessel.txt")

# WRONG - do NOT manually encode (violates the contract):
# PAYLOAD_B64=$(gzip -c < "$BUNDLED" | base64 | tr -d '\n')
# PAYLOAD_CMD="python3 -c \"import gzip,base64;exec(...)\""
```

These artifacts are in a **separate directory** from `output_dir` (the `to_stage/` deployment directory). Vessels **read** from `bundling_outputs_dir` but MUST NOT write to it. These files are NOT declared in `artifact.json` and are NOT part of the deployment artifact.

### Cross-Compilation Support (Native Binary Vessels)

Vessels that compile native binaries (C, Rust, Go, etc.) MUST support cross-compilation based on the `target_arch` field from `context.json`. This allows the same vessel to build artifacts for different target platforms from a single control-plane host.

#### Standard target_arch Values (Locked)

| `target_arch` | Platform | Typical Toolchain |
|---------------|----------|-------------------|
| `x86_64-linux` | 64-bit Intel/AMD Linux | `gcc -m64` |
| `aarch64-linux` | 64-bit ARM Linux | `aarch64-linux-gnu-gcc` |
| `x86_64-darwin` | 64-bit Intel macOS | `clang -arch x86_64` |
| `arm64-darwin` | ARM macOS (Apple Silicon) | `clang -arch arm64` |

Whatever toolchain you pick has to be present on the **build host** — the machine where you run `blacksea instances build` / `blacksea forge` — never on the target, which only ever receives the finished artifact. The compilers above are the plain-`cc` baseline; the shipped vessels reach for whatever produces a genuinely portable binary for their language, and each names its requirement in [the bait catalog](../lure_material/README.md): `pwcrypt`, for one, builds its Linux binaries inside Docker containers to get static musl output. Pick the same way: whatever gives you a static, dependency-free binary for the target you're aiming at. The pure-script `identity` vessel skips all of this — it needs nothing beyond `python3`.

#### Implementation Pattern

**1. Parse `target_arch` from `context.json`:**

```bash
TARGET_ARCH=$(python3 -c "import json; c=json.load(open('$CONTEXT_JSON')); print(c.get('target_arch', [''])[0] if c.get('target_arch') else '')")
```

**2. Map to compiler and flags:**

```bash
if [[ -n "$TARGET_ARCH" ]]; then
    case "$TARGET_ARCH" in
        x86_64-linux)
            CC=gcc
            EXTRA_CFLAGS="-m64"
            ;;
        aarch64-linux)
            CC=aarch64-linux-gnu-gcc
            EXTRA_CFLAGS=""
            ;;
        x86_64-darwin)
            CC=clang
            EXTRA_CFLAGS="-arch x86_64"
            ;;
        arm64-darwin)
            CC=clang
            EXTRA_CFLAGS="-arch arm64"
            ;;
        *)
            echo "error: unsupported target_arch '$TARGET_ARCH'" >&2
            exit 1
            ;;
    esac
    echo "cross-compiling for $TARGET_ARCH (CC=$CC)..." >&2
else
    # No target_arch — build for host (backward compatibility).
    CC=cc
    EXTRA_CFLAGS=""
    echo "building for host platform..." >&2
fi
```

**3. Pass to build system:**

```bash
make TARGET_ARCH="$TARGET_ARCH" CC="$CC" CFLAGS="$EXTRA_CFLAGS" >&2
```

**4. Makefile support for `TARGET_ARCH`:**

```makefile
# Cross-compilation support: TARGET_ARCH set by setup.sh from context.json.
# If empty, auto-detect from host platform (uname) for local builds.
TARGET_ARCH ?=

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11

# Determine target platform.
ifeq ($(TARGET_ARCH),)
# Auto-detect mode: use host platform.
UNAME_S := $(shell uname -s)
TARGET_OS := $(UNAME_S)
else
# Cross-compile mode: parse TARGET_ARCH.
# Format: <arch>-<os>, e.g. "x86_64-linux".
TARGET_OS := $(lastword $(subst -, ,$(TARGET_ARCH)))
endif

# Platform-specific flags.
ifeq ($(TARGET_OS),Linux)
LDFLAGS += -no-pie
else ifeq ($(TARGET_OS),Darwin)
# macOS-specific flags...
endif
```

#### Backward Compatibility

If `target_arch` is missing or empty in `context.json`, vessels SHOULD fall back to building for the host platform (auto-detect via `uname`). This preserves compatibility with manual/local builds and older bait manifests.

#### Validation Requirements

1. **Fail fast on unsupported targets:** Exit non-zero with a clear error message naming the unsupported target and listing what IS supported.

2. **Document supported targets:** In the vessel's own README or header comment, list which `target_arch` values are supported and any external dependencies (e.g., "requires `aarch64-linux-gnu-gcc` for ARM Linux cross-compilation").

3. **Test matrix:** Vessels SHOULD be tested against all claimed `target_arch` values.

#### Reference Implementation

**Reference:** `../lure_material/staging_vessels/pwcrypt/setup.sh` and `pwcrypt/src/Makefile` — full cross-compiling C binary vessel with RCE delivery.

### Checklist for vessel authors

- [ ] Parse `context.json` from the first argument.
- [ ] Read `bundled_payload_path`; write all files to `output_dir`.
- [ ] **Use `ready_for_vessel.txt`** — read the bundler's pre-generated command string instead of manually encoding the payload.
- [ ] **Support cross-compilation** — parse `target_arch` and map to appropriate compiler/flags (native binaries only; interpreted-language vessels can skip this).
- [ ] Write `artifact.json` declaring every output file and a `primary` field.
- [ ] Exit 0 on success; non-zero + stderr on failure.
- [ ] Treat the bundled payload as opaque bytes (don't parse/modify its logic).
- [ ] Use `seed` for any randomness (never `urandom()` directly).
- [ ] Declare **all** output files in `artifact.json`, including docs and sidecars (bundler artifacts are auto-excluded).
- [ ] Avoid external network calls unless explicitly designed for.
- [ ] Generate `how_to_stage.md` in `output_dir_root` (recommended, advisory) — what this artifact is, how to place it, and the exact trigger command; never declare it in `artifact.json` or write it into `output_dir`.

---

## 6. `manifest.yaml` — the declarative manifest

The manifest ties the three components together and is validated by the control plane's ingestion rules at `register` time. **Required top-level fields:** `bait_id`, `version`, `description`, `assurance_tier`, `deploy_class`, `channels`, `envelope_version`, `provenance`, `build`, `listener_class`, `payload_file`, `staging_vessel`. (`isolation_class` defaults to `in_process`.)

| Field | Value |
|---|---|
| `bait_id` | unique routing key / queue subject `bait.<bait_id>`. |
| `version` | bait version string. |
| `assurance_tier` | `0` (signal only) \| `1` \| `2` (encrypted body). |
| `deploy_class` | `portable_artifact` \| `host_resident` \| `interactive_service`. |
| `isolation_class` | `in_process` (default) \| `subprocess` \| `sandboxed` (the latter needs an `isolation:` block). |
| `channels` | map of channel → config. Known receivers today: `dns`, `https`. DNS/ICMP are tier-0-only. |
| `envelope_version` | must be `1`. |
| `listener_class` | `<module>.<ClassName>` (e.g. `listener.HostnameProbeListener`). |
| `payload_file` | filename of the payload (e.g. `payload.py`). |
| `staging_vessel` | directory containing `setup.sh` (e.g. `staging_vessel/`). |
| `listener_data_files` | *(optional)* list of filenames, relative to `listener_class`'s own directory, that the listener reads as sibling data at construction (e.g. a YAML knowledge base loaded via `Path(__file__).parent / "..."`). Frozen alongside the module at `register` and covered by the same `listener_hash` — omit this and a listener that reads any file beyond its own source will import fine at `register` (source tree has the sibling) but fail on the brain's *frozen* copy (`src/blacksea/control_plane/listeners.py`'s closure-scope contract). |
| `build_vars` | list of constant names the factory must resolve before bundling (e.g. `_ZONE`, `_TOKEN`). Standard names auto-resolve; others need `--set`. |
| `provenance` | **all sub-fields required and non-empty**: `behavior`, `source`, `observed_date`. Cite the attacker behavior — no generic baits. |
| `build` | `toolchain` (e.g. `python3.11`, `gcc`) + `target_arch` list. |
| `retention_days` | *(optional)* int; telemetry retention window for this bait. |
| `deploy` | *(optional)* deploy-time parameters so `forge` (§7) needs no CLI flags: `campaign`, `callbacks` (one address per declared channel), optional `build_vars` (== `--set`), optional `approve` (default `true`). See below. |
| `test` | *(optional, default `false`)* marks a test/example/reference bait — not real intel. Propagated to every record the bait produces (`records.test`) and shown as a `TEST` badge in the observer UI. Set this on any bait you author purely to exercise the pipeline (as every `e2e_tests/` entry and `hostname_probe` do). |

**The `deploy:` block (optional — consumed by `forge`, not by `register`).** It carries the deploy-time parameters that otherwise go on the `build` command line, making the manifest self-sufficient for a single-call `forge`:

```yaml
deploy:
  campaign: field-2026q3            # required for forge (or pass --campaign)
  callbacks:
    https: http://cb.example.com:8443   # one per declared channel (or pass --callback CH=ADDR)
  build_vars:                       # optional — overrides for author-chosen names (== --set)
    _FOO: bar
  comment: "field-2026q3 default"   # optional — free-text operator note stored on the instance
  approve: true                     # optional; false == forge --no-approve (stop at pending)
```

`forge`'s CLI flags (`--campaign` / `--callback` / `--set` / `--comment` / `--no-approve`) override the block per field, so a manifest can declare production defaults while a local test repoints the callback. `comment` is purely descriptive metadata (why this instance was built) — it's shown wherever the bait is visualized (`blacksea baits show` / `instances show` / `instances ls` / `--json`) and never affects the build, routing, or attribution. If a manifest omits `deploy.comment` and you don't pass `--comment`, the console prompts you for one interactively (empty is fine).

Validation rules worth knowing (each is either a hard error `✗` or a warning `⚠` at registration):

- Unknown channel → **error**.
- `assurance_tier 0` with a fat channel, or tier ≥ 1 with only DNS → **warning**.
- `dns.max_chunks > 50` → **warning** (detection + canary-zone DoS risk).
- `deploy_class: interactive_service` → **warning + requires explicit operator acknowledgement** (segmentation).
- `envelope_version` not `1` → **error**.
- Empty/missing required field or provenance sub-field → **error**.
- Listener not a `Listener` subclass, or any golden case failing (incl. missing zero-body case) → **error**.

### Complete example (the `hostname_probe` manifest)

```yaml
bait_id: hostname-probe
version: "1.0.0"
description: >
  Reference/test bait demonstrating the manifest-only authoring model: the payload,
  listener, and staging vessel are cataloged in lure_material/ and referenced here
  by path — this directory holds only the manifest.

assurance_tier: 0            # tier-0: DNS signal only (no signed body)
deploy_class: portable_artifact
isolation_class: in_process
test: true                   # reference/test bait — not real intel

channels:
  dns: {}

envelope_version: 1

# payload/listener/vessel are cataloged in lure_material/ (repo root, sibling of services/),
# not copied locally — see lure_material/README.md and §2 above.
listener_class: ../../../../lure_material/payloads/hostname_grab_dns/listener.HostnameGrabDNSListener
payload_file: ../../../../lure_material/payloads/hostname_grab_dns/payload.py
staging_vessel: ../../../../lure_material/staging_vessels/identity

# Constants the factory injects into payload.py before bundling.
build_vars:
  - _ZONE          # DNS callback zone, e.g. "cb.example.com"
  - _TOKEN         # hex-encoded instance_token
  - _DNS_SERVER    # "host:port" for local/test raw-UDP delivery; empty for a real deployment

provenance:
  behavior: >
    Reference bait only — exercises the manifest-only authoring model and the
    register/build/stage/interpret loop. Not grounded in an observed attacker
    behavior and not intended for live deployment.
  source: services/test_fixtures/baits/hostname_probe/
  observed_date: "2026-06-08"

retention_days: 7

build:
  toolchain: python3.11
  target_arch:
    - x86_64-linux
```

---

## 7. Registering, building, and deploying with the `blacksea` console

Everything past "write the files" is a `blacksea` command. The console is the single operator entry point over the control plane's catalog + factory — see [`docs/console.md`](./console.md) for the full command reference; this section covers only what a bait author needs to take a manifest from source to a live instance. Two equivalent ways to invoke it, used interchangeably below:

| Form | When |
|---|---|
| `blacksea …` | interactive use — on PATH after `make install`, no venv activation needed (or run `.venv/bin/blacksea …` directly) |
| `python -m blacksea.console …` | module form, any environment where `blacksea` is importable |

### Register: the ingestion gate

`blacksea baits register` parses + validates the manifest, loads `listener_class`, checks it implements the `Listener` ABC, and runs `golden_cases()` offline (§4) — **no registration succeeds with a failing golden case**; a failure is reported structured, one result per case.

```bash
# From services/ — <bait_dir> is wherever you put the manifest (e.g. e2e_tests/<name>/):
blacksea baits register <bait_dir>

# Reload an already-registered bait's manifest from disk (picks up a manifest edit):
blacksea baits register <bait_dir> --refresh
```

You can run the same golden cases yourself first, offline, no infra needed (§4 covers the matching semantics in full):

```python
from listener import MyListener
from blacksea.sdk.testing import assert_golden
assert_golden(MyListener())
```

### Build → approve: the manual hot-deploy loop

Once registered, `build` generates the per-instance secrets and produces a deployable artifact (`pending`); `approve` is the explicit human gate that makes it live:

```bash
# Build: generate the per-instance master key `_KEY` + token, resolve build_vars, bundle
# payload.py, run the staging vessel. Result: a `pending` instance + a deployable artifact.
# Omit --comment and, in an interactive shell, you're prompted for a note (empty is fine).
blacksea instances build <bait_id> --campaign C-2026Q2-alpha --callback dns=cb.example.com \
    --comment "target: honeypot-7, field-2026q3"

# Approve: pending → active, and publish the instance key to the brain's key directory.
# The brain picks this up on its next key-directory poll — no restart.
blacksea instances approve <instance_token>
```

Inspect the catalog at any point:

```bash
blacksea baits ls
blacksea baits show <bait_id>                 # manifest + every instance, with comment + artifact path
blacksea instances ls --bait <bait_id>        # filters: --bait / --campaign / --status
blacksea instances show <instance_token>
blacksea instances artifact <instance_token>  # locate the deployable to_stage/ dir + primary file
```

### `forge`: register → build → approve in one call

If the manifest carries a `deploy:` block (§6 — campaign + per-channel callbacks), `forge` collapses the whole chain into a single command, no per-bait script:

```bash
blacksea forge <bait_dir>/manifest.yaml

# Override the manifest's deploy defaults for a local test, or stop before approving:
blacksea forge <bait_dir>/manifest.yaml \
    --campaign test --callback https=http://127.0.0.1:8443 --no-approve

# Attach a note recording *why* this instance was built (or omit --comment to be prompted):
blacksea forge <bait_dir>/manifest.yaml --comment "campaign alpha, host bravo"
```

`forge` prints the instance token + the deployable artifact path; add `--json` for a machine-readable result (the field is `artifact_path` — what the e2e test harness parses).

### Watching it fire, and standing an instance down

```bash
blacksea status                        # is the infra (Postgres/brain/NATS/edge) up?
blacksea events tail --bait <bait_id>  # follow new hits live, Ctrl-C to stop
blacksea events show <record_id>       # full record incl. signals + details
```

`burn` / `retire` / `revoke` are operator-confirmed, never automatic; each refreshes the brain's key directory, and the brain picks up the change on its next poll — no restart:

```bash
blacksea instances burn   --instance <instance_token> --reason "token seen in the wild"
blacksea instances retire --design   <bait_id>
blacksea instances revoke <instance_token>   # key weaponized
```

---

## 8. Multiple vessels for the same payload + listener

One `(payload, listener)` pair can ship under several `bait_id`s when only the *delivery format* differs. The design-level source of truth for such a pair is `../lure_material/payloads/<name>/` (see §2 above) — under the manifest-only model this needs **no copying or symlinking of any file**. Just write one manifest per vessel, each pointing at the same payload/listener catalog entry but a different `staging_vessels/<name>/`. `agent_fp` (§2's flagship payload) actually ships this way today — the same `payload.py`/`listener.py` behind two independent manifests:

```
services/e2e_tests/agent_fp/manifest.yaml              # bait_id: agent-fp      — staging_vessel: identity
docs/examples/agent_fp_pwcrypt_demo/manifest.yaml       # bait_id: agent-fp-demo — staging_vessel: pwcrypt
```

```yaml
# services/e2e_tests/agent_fp/manifest.yaml  (../ count matches this dir's depth — see §2)
listener_class: ../../../lure_material/payloads/agent_fp/listener.AgentFingerprintListener
payload_file:   ../../../lure_material/payloads/agent_fp/payload.py
staging_vessel: ../../../lure_material/staging_vessels/identity
```

```yaml
# docs/examples/agent_fp_pwcrypt_demo/manifest.yaml  (same depth, different vessel)
listener_class: ../../../lure_material/payloads/agent_fp/listener.AgentFingerprintListener
payload_file:   ../../../lure_material/payloads/agent_fp/payload.py
staging_vessel: ../../../lure_material/staging_vessels/pwcrypt
```

Each gets its own key (separate instance token + master key) and routes on its own `bait.<bait_id>` subject, but shares the same decode + interpret logic — because both manifests point at the identical `payload.py`/`listener.py` files, there is no drift risk to manage.

---

## 9. Quick-start: a new bait from scratch

**Reusing an existing catalog design** (skip to step 4):

1. Browse `lure_material/README.md` for an existing `payloads/<name>/` + `staging_vessels/<name>/` pair that fits.
2. *(nothing to write — reuse the catalog entries as-is)*
3. *(nothing to write)*
4. `mkdir -p <bait_dir>/` (e.g. under `e2e_tests/<name>/`) and write `manifest.yaml` (§6) referencing the chosen catalog entries (see §2's path template), with a non-empty `provenance` block, and (to enable a one-call forge) a `deploy:` block with `campaign` + a `callbacks` address per channel.
5. `blacksea forge <bait_dir>/manifest.yaml` — registers (green golden cases or it doesn't register), builds a fresh instance, and approves it in one step. Prefer piecewise `blacksea baits register` / `instances build` / `instances approve` (§7) if you want to inspect between steps.

**Authoring a genuinely new design** (all steps):

1. `mkdir -p ../lure_material/payloads/<name>/`. Write `payload.py` — import comms from `blacksea.sdk.payload.*`; reference injected constants as globals (`# noqa: F821`); never crash.
2. In the same directory, write `listener.py` — subclass `Listener`; implement `encode_body`/`decode_body`/`interpret`/`golden_cases`. Pure, total, handles `body == b""`.
3. If no existing staging vessel fits, `mkdir -p ../lure_material/staging_vessels/<vessel-name>/` and write `setup.sh` (executable) against the §5 contract: read `context.json`, write outputs to `output_dir`, emit `artifact.json`. Otherwise reuse an existing vessel (e.g. `lure_material/staging_vessels/identity/` for a plain script drop).
4. `mkdir -p <bait_dir>/` (e.g. under `e2e_tests/<name>/`) and write `manifest.yaml` (§6) referencing the new catalog entries, with a non-empty `provenance` block and a `deploy:` block.
5. `blacksea forge <bait_dir>/manifest.yaml` (or piecewise `baits register`/`instances build`/ `instances approve`, §7).

---

## Where to read more

- §1–§2 above — the SDK's import split (`blacksea.sdk.payload.*` vs. `blacksea.sdk.listener`), the manifest-only model, directory layout, and the "reuse vs. new design" checklist.
- [`docs/setup_a_bait.md`](./setup_a_bait.md) — deploying a bait you've authored: placing the artifact on a target and watching the first hit land.
- [`docs/console.md`](./console.md) — the full `blacksea` console command reference (§7 above covers only what a bait author needs).
- [`lure_material/README.md`](../lure_material/README.md) — the catalog of ready-made payloads, listeners, and staging vessels to reuse or learn from.
- [`test_fixtures/baits/hostname_probe/`](../services/test_fixtures/baits/hostname_probe/) — a worked manifest-only bait example (the reference test bait).
- [`../lure_material/payloads/hostname_grab_dns/`](../lure_material/payloads/hostname_grab_dns/) — the payload + listener that example references, end to end.
- [`../lure_material/payloads/agent_fp/`](../lure_material/payloads/agent_fp/) — the flagship payload: LLM-driven agent-harness attribution, end to end (see `services/e2e_tests/agent_fp/` and `docs/examples/agent_fp_pwcrypt_demo/` for its two shipped pairings).
- [`../lure_material/staging_vessels/`](../lure_material/staging_vessels/) — reusable staging vessels (pwcrypt RCE delivery, identity NOP vessel).
