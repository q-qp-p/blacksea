# sdk/ — blacksea.sdk Python package

**Status:** **implemented.** `python -m pytest tests/sdk` collects 82 tests
(39 in `tests/sdk/*.py` for this module + 43 in `tests/sdk/bundler/` for the payload bundler —
see `src/blacksea/bundler/context.md`); the "26 tests passing" figure from the original
landing predates the HMAC-envelope migration, the `hostname_probe` golden-case tests, and the
bundler test suite.  
**Language:** Python 3.11+  
**Contracts:** this file is self-sufficient. The bait-authoring surface (the `Listener` ABC,
its lifecycle hooks, and the frozen SDK types a `listener.py` imports) and the `TypedEvent`
projection consumed by `blacksea/correlation/` are both defined and locked below — no
external design doc is required to understand or modify this module.

**Layout:** The importable code lives at `src/blacksea/sdk/`, part of the single
`blacksea` distribution (root `services/pyproject.toml`). Run the suite with
`python -m pytest tests/sdk` after `make install` (`pip install -e .`, which makes
every `blacksea.*` package importable — no `PYTHONPATH`, no per-module install).

## Scope

Everything a bait author needs to write a bait's server-side `listener.py` — and nothing
else. A bait is authored as three separate files (the payload script, the `Listener`
subclass, and the staging vessel — see "Authoring model" below); this package is the only
import the `listener.py` half ever uses. It contains:

- The **`Listener` ABC** — the primary, interpret-only authoring surface (see "Authoring
  model" below). `BoobyBait` is kept as a deprecated alias (`BoobyBait = Listener`) for code
  written against the old single-class build+interpret model; new authors subclass `Listener`
  directly. There is no `Buildable` protocol any more — only `Interpretable`.
- The **`Interpretable` protocol view** — the interpret-side surface handed to the analyzer
  pool (`encode_body`/`decode_body`/`interpret`/lifecycle hooks/`golden_cases`); documents the
  no-ambient-authority contract (inv 11).
- Frozen dataclass SDK types a `listener.py` actually touches: `Envelope`, `AnalyzerOutput`,
  `Signals`, `GoldenCase`, `ObservedSource`. `types.py` also still defines `Artifact`,
  `BuildContext`, `RunResult` — these are the build-orchestration contract now owned by
  `control_plane/factory.py` (its `LocalBuildContext` implements `BuildContext`); they are not
  part of what a bait author writes, since `Listener` has no `build()` method — the factory
  drives the build out-of-band from a separate `payload.py` script + `staging_vessel/setup.sh`.
- Exceptions (`BodyDecodeError`, `BuildError`) — `BodyDecodeError` is raised by
  `decode_body()`/caught by `interpret()`; `BuildError` is raised by `BuildContext.run()` in
  the factory's build sandbox, unrelated to anything a `Listener` subclass does itself.
- **Communication primitives** (`payload/`): `send_dns`, `send_http`, `send_dns_multiturn` — stdlib-only Python functions that run on the attacker's machine. Callable two ways: inlined at build time via `get_comms_source()` (reads the same `payload/` source files), or imported directly by a payload (`from blacksea.sdk.payload.dns import send_dns`) for the bundler to inline.
- **`get_comms_source(channels)`**: returns the source of the requested primitive(s) as a single inlineable Python block, reading from `payload/`, for authors building a payload as a template string rather than a real `.py` file. **Not called by the factory today** — `control_plane/factory.py`'s `bundle_payload()` runs the bundler directly against `payload.py` (which imports comms via `from blacksea.sdk.payload.* import ...`, the direct-import style used by the reference bait and `docs/bait-authoring.md`); `get_comms_source()` remains as an alternative template-inlining path a `Listener` subclass never calls itself.
- **Tier≥1 envelope construction** (`payload/`): `payload/envelope.py` (`build_encrypted_envelope`
  — a pure-stdlib HMAC-SHA256 AEAD over a fixed binary core: `ev(1) ‖ session_id(8) ‖ seq_no(4) ‖
  sensor_time(8) ‖ body`, no CBOR, no length prefix since `body` is last; HMAC-SHA256 doubles as
  a CTR-mode keystream for confidentiality and as the MAC, encrypt-then-MAC with
  domain-separated `ke`/`ka` subkeys derived from the 32-byte `_KEY`; outer wire shape
  `{ev, tok, enc}`, wire version `ev: 2`), `payload/http.py` (`send_http`/`send_https_encrypted`
  senders). Payloads import these directly
  (`from blacksea.sdk.payload.http import send_https_encrypted`); the bundler inlines them.
  No third-party imports anywhere on this path — `envelope.py` uses only
  `base64`/`hmac`/`hashlib`/`json`/`os`/`time` at module level (no deferred-import trick needed;
  see *Bundler minimality* below).
- Dev/test helpers (`test_envelope()`)
- The golden-test runner (used both at registration and locally by bait authors)

The `framework/` subdirectory contains types the framework uses internally (`TypedEvent` — see
*Invariants* below). Bait authors never import from `framework/` directly — it is not part of
the public API.

### Authoring model — three files, `Listener` is interpret-only

A bait is authored as three separate files:

1. `payload.py` — a standalone Python script; imports comms primitives from
   `blacksea.sdk.payload.*` directly. Fed through the bundler at factory time, which inlines
   the comms source and prepends injected constants (instance token, callback address, …) to
   produce a self-contained artifact.
2. `listener.py` — a `Listener` subclass. Owns the server-side half only: body
   encoding/decoding, telemetry interpretation, and golden-case fixtures. A single `Listener`
   class can be registered under multiple `bait_id`s when the same interpret logic applies to
   different staging vessels.
3. `staging_vessel/setup.sh` — takes the bundled payload file and produces the final bait
   artifact (a shell script, notebook embed, fake binary, …).

`Listener` (`src/blacksea/sdk/abc.py`) declares no `build()` method — there is no build-side ABC
method at all. The build side (what used to be a `BoobyBait.build()` method) is entirely
handled by `control_plane/factory.py`, which orchestrates `payload.py` + the staging vessel out
of band; a `Listener` subclass is never asked to build anything. `Listener`'s contract:

- `encode_body(data: dict) -> bytes` — canonical serialisation, used for golden-case generation
  and round-trip testing; the deployed payload's own code must produce byte-for-byte equivalent
  output for the same logical payload (structural enforcement across the two files is
  impossible — this is the author's responsibility).
- `decode_body(body: bytes) -> dict` — inverse of `encode_body`; MUST NOT raise on truncated /
  partially-corrupt input (best-effort dict); raises `BodyDecodeError` only on completely
  unrecoverable input (wrong magic, incompatible version).
- `interpret(envelope: Envelope, body: bytes) -> AnalyzerOutput` — pure function, called once
  per inbound hit; MUST handle `body == b""` (signal-only / tier-0); MUST NOT raise (catches all
  exceptions internally, expresses them via `_`-prefixed meta-keys in `details`); MUST complete
  within the framework's time + memory limits.
- Lifecycle hooks `on_register()`, `on_deploy(instance_token)`, `on_burn(reason)`,
  `on_retire()` — optional, default no-op, same ambient-authority restrictions as `interpret()`.
- `golden_cases() -> list[GoldenCase]` — required; the registration gate. Must include at least
  a normal hit and a zero-body (signal-only) hit; the framework runs these at registration and
  any failure blocks staging.

## Scope boundary (what this module is NOT)

- Not the pool that runs analyzers (that is `brain/pool.py`)
- Not the build orchestrator (that is `control_plane/factory.py` — it implements the
  `BuildContext` ABC defined in `types.py` and drives payload bundling + the staging vessel; no
  `Listener` subclass has a `build()` method to run)
- Not the registration validator (that is `control_plane/ingestion.py`)

## Plan

Build order:

1. `exceptions.py` — needed by everything else
2. `types.py` — all frozen dataclasses; ground truth for the locked SDK types
3. `abc.py` — `Listener` (interpret-only) ABC + `Interpretable` protocol view, `BoobyBait` kept
   as a deprecated alias; depends on types.py
4. `testing.py` — test_envelope() helper + golden-test runner; depends on types.py + abc.py
5. `framework/types.py` — TypedEvent; kept separate so bait authors cannot accidentally import it
6. `listener.py` — the single server-side authoring surface: re-exports the `Listener` ABC (and
   `BoobyBait` alias), types, exceptions, `get_comms_source`, and the golden-test harness
7. `__init__.py` — package root, deliberately **import-free** (see the bundler-minimality
   invariant below)

Exit criterion: `from blacksea.sdk.listener import Listener, Envelope, AnalyzerOutput`
works and the golden-test runner passes. The runner + loose matcher are proven against a
stdlib-JSON fixture bait in `tests/sdk/test_sdk.py` (normal / zero-body / malformed cases,
the zero-body registration gate, and the structural `TypedEvent` exclusions).

## Dependencies

- No dependencies on other modules in this codebase.
- Everything, including `payload/` (all channels, all tiers), is standard library only — no
  third-party runtime dependency anywhere in this package.

## Invariants enforced here

- **Bundler minimality — the package root `__init__.py` MUST NOT import its submodules.**
  A payload imports only `blacksea.sdk.payload.*`. The bundler
  (`src/blacksea/bundler/discovery.py`) vendors a payload's **entire parent-package chain**, so
  `src/blacksea/sdk/__init__.py` is always vendored and scanned — and discovery walks *all* AST
  nodes, including imports nested inside functions or `if TYPE_CHECKING:` blocks. Any
  `from .abc import Listener` (or other re-export) there is therefore dragged into **every**
  payload bundle, shipping the Listener ABC, the golden-test runner, and the SDK types that a
  beacon payload never uses. Keep `__init__.py` import-free; bait authors import the server-side
  surface from `blacksea.sdk.listener`, never from the package root. Locked by
  `tests/sdk/test_payload_import_is_minimal.py` (both a real-discovery leak check and an AST check
  that the `__init__` imports no `blacksea.*` submodule).
- inv 11: `Interpretable` protocol documents the no-ambient-authority contract; the sandbox in
  `brain/` enforces it at runtime, but the type boundary starts here.
- The `TypedEvent` struct in `framework/types.py` structurally excludes `details` and
  `sensor_time` — the correlation engine (see `src/blacksea/correlation/context.md`) cannot
  access them (inv 12, inv 17) because the fields don't exist on the type at all — a missing
  field is a compile-time/structural constraint, not a runtime check:

  ```python
  @dataclass(frozen=True)
  class TypedEvent:
      record_id: str; bait_id: str; instance_token: bytes; campaign_id: str
      deploy_class: str; assurance_tier: int
      session_id: bytes; seq_no: int; event_type: str
      edge_recv_time: int
      source_ip: str; source_ja3: str | None; source_type: str
      fingerprint_hash: str | None; caution_level: str | None; explicit_session_end: bool
      sig_valid: bool; orphan: bool; instance_status: str
  ```

  The framework constructs a `TypedEvent` from every verified Record and hands it to
  `blacksea/correlation/`; it is the only type that module imports from the framework —
  correlation never touches the full Record.

## File list

| File | Description |
|---|---|
| `src/blacksea/sdk/__init__.py` | Package root. **Import-free by invariant** (only `__version__`) — must never import submodules, or they leak into every payload bundle (see *Bundler minimality* above) |
| `src/blacksea/sdk/listener.py` | Server-side authoring surface — the single import for bait authors: re-exports the ABC, all SDK types, exceptions, `get_comms_source`, and the golden-test harness. **`TypedEvent` deliberately NOT re-exported** |
| `src/blacksea/sdk/types.py` | Frozen dataclasses: `ObservedSource`, `Envelope`, `Signals`, `AnalyzerOutput`, `GoldenCase` (the bait-authoring types) plus `Artifact`, `RunResult`, and the abstract `BuildContext` (the build-orchestration contract consumed by `control_plane/factory.py`'s `LocalBuildContext`, not by `Listener`) |
| `src/blacksea/sdk/abc.py` | `Listener` ABC — interpret-only (`encode_body`/`decode_body`/`interpret`/lifecycle hooks/`golden_cases`; no `build()`); `Interpretable` Protocol view; `BoobyBait = Listener` kept as a deprecated back-compat alias |
| `src/blacksea/sdk/exceptions.py` | `BodyDecodeError`, `BuildError` |
| `src/blacksea/sdk/inject.py` | `get_comms_source(channels) -> str`: reads primitive source files from `payload/` and returns a self-contained inlineable Python block |
| `src/blacksea/sdk/payload/__init__.py` | Package marker (empty) |
| `src/blacksea/sdk/payload/dns.py` | `send_dns(token, zone, body=b"", server="")`: packs the mandatory 19B wire header (`ev\|flags`(1B), `instance_token`(8B), `session_id`(8B), `seq_no`(2B)) + body, base32-encodes across ≤63-char labels (modes 1-2, chunked at a base32-group boundary so a label split never corrupts a byte), sends via the OS resolver or (if `server` given) a hand-rolled raw UDP query direct to `host:port` — stdlib only, no third-party DNS library; swallows all errors |
| `src/blacksea/sdk/payload/dns_multiturn.py` | `send_dns_multiturn(data, zone, delay)`: base32-chunk arbitrary bytes across sequential DNS queries |
| `src/blacksea/sdk/payload/envelope.py` | `build_encrypted_envelope(body, key_hex, instance_token_hex, ...)`: packs the fixed binary encrypted-core (`ev(1) ‖ session_id(8) ‖ seq_no(4) ‖ sensor_time(8) ‖ body`), seals it with a pure-stdlib HMAC-SHA256 AEAD (`tok` bound into the tag), returns the `{ev, tok, enc}` JSON bytes. Module-level stdlib imports only (`base64`/`hmac`/`hashlib`/`json`/`os`/`time`) |
| `src/blacksea/sdk/payload/http.py` | `send_http` (raw POST, stdlib `urllib.request`), `send_https_encrypted` (builds + POSTs the HMAC-SHA256 AEAD envelope) |
| `src/blacksea/sdk/testing.py` | `test_envelope()` fixture builder; `ANY` matcher sentinel; `run_golden_case()`/`run_golden_cases()`/`assert_golden()` runner (used offline + at registration) |
| `src/blacksea/sdk/framework/__init__.py` | Marks framework as a sub-package; documents the no-import rule for bait authors |
| `src/blacksea/sdk/framework/types.py` | `TypedEvent` projection struct (framework-internal; bait authors must not import this) |
| `tests/sdk/test_sdk.py` | SDK contract tests: imports, golden runner + matcher (against a `_JsonListener` fixture), registration gates, frozen-immutability, structural `TypedEvent` exclusions, comms injection, the `Listener` ABC-completeness check, and the `hostname_probe` bait's catalog-referenced `HostnameGrabDNSListener` (loaded from `lure_material/payloads/hostname_grab_dns/listener.py`; the bait manifest fixture is `test_fixtures/baits/hostname_probe/` — see `docs/bait-authoring.md`) golden cases + payload-structure checks |
| `tests/sdk/test_payload_import_is_minimal.py` | Locks the *Bundler minimality* invariant: a payload-comms import pulls in no server-side modules and no third-party module at all (the entire tier≥1 path is pure stdlib post-HMAC-migration), and `__init__.py` imports no `blacksea.*` submodule |
| `tests/sdk/test_envelope.py` | Locks the HMAC-SHA256 AEAD envelope construction (`payload/envelope.py`): HMAC primitive KAT, round-trip shape/length checks, nonce randomness, and a golden wire vector so the format can't silently drift |

`src/blacksea/bundler/` (the payload bundler that vendors and flattens `payload/` imports into a
self-contained artifact, including `vessel_wrappers.py`'s vessel-ready command generation) is a
sibling package, not part of this file list — see `src/blacksea/bundler/context.md`.
