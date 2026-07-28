# context.md — blacksea/config/

## Scope

`blacksea.config` is the single source of truth for **operational configuration**: every
deployment/runtime value that used to be a scattered `os.environ.get(...)` default. Before this
module those defaults were triplicated across the Makefile, inline Python, and the Go edge — which
is how two drifts crept in (`BS_KEYDIR` meaning different files in the brain vs. the CLI;
`NATS_STREAM` being `BAITS` in the brain but `BAIT` in the edge). One documented, env-overridable
definition per value now prevents that.

It also owns loading the ONE unified config file `config/blacksea.env` (written by
`make init` — the hidden `blacksea init` under the hood) into `os.environ` before any setting
resolves, so every Python entry
point — a bare `blacksea`, `python -m blacksea.brain.pool`, `pytest` — reads the same file with no
wrapper exporting it. `envload.py` does the finding/parsing/loading (env always wins over the file);
`settings.py` calls it once at import (`BS_CONFIG_PATH = envload.load_into_environ()`).

**Package-anchored path resolution — the CLI works from any directory.** Blacksea is
always an *editable* install, so a module's `__file__` resolves into the real source tree.
`envload.PROJECT_ROOT` uses that (`Path(__file__).resolve().parents[3]` → the `services/` root,
validated by a `pyproject.toml` there; `None` for a relocated/non-editable install; overridable via
`$BS_PROJECT_ROOT`). This is a **CWD-independent anchor**, and it fixes the "works inside `./`, fails
elsewhere" bug: an installed `blacksea` (on PATH at `~/.local/bin`) previously found
`config/blacksea.env` only by walking *up from the CWD*, so running it from outside the checkout
yielded "no Postgres DSN" even with the DB up.
- **Config discovery** (`find_config_file`), highest precedence first: `--config` → `$BS_CONFIG` →
  CWD-upward walk for `config/blacksea.env` then legacy `secrets/env` (a checkout you're hacking in
  wins) → **`<PROJECT_ROOT>/config/blacksea.env`** then `<PROJECT_ROOT>/secrets/env` (the anchor).
- **Operational paths** — `settings.py` re-exports the root as `BS_PROJECT_ROOT` and, via
  `_root_path(name, *rel)`, defaults `BS_REGISTRY` / `BS_ARTIFACTS_ROOT` / `BRAIN_KEYDIR` /
  `BS_DEV_DIR` / `EDGE_DIR` / `EDGE_BIN` / `BS_COMPOSE_FILE` *under* the root (each still
  env-overridable). In-tree (`root == cwd`) these are byte-identical to the old relative defaults, so
  behavior is unchanged from the repo root; out-of-tree they're correct instead of broken — so
  `up`/`forge`/`reset` are location-independent too (the supervisor passes `docker compose -f
  <BS_COMPOSE_FILE>`). Locked by `tests/config/test_envload.py` (the anchor + precedence cases).

**Scope boundary — what this module is NOT:**
- **Not protocol/wire constants.** Crypto domain-separation labels, envelope version `ev`,
  nonce/tag/header sizes, DNS header layout, record-id format are *contracts* that must match
  byte-for-byte across payload/brain/edge. They stay as named constants next to the code that uses
  them, guarded by the golden wire-vector tests — never here.
- **Not the payload's config.** The deployed payload is stdlib-only and minimal (locked invariant);
  it receives its parameters injected at build time by the bundler, and must never import this
  package.
- **Not the Go edge's config.** Go cannot import a Python module. The edge mirrors the values it
  shares (NATS, ports, timeouts) in `edge/config.go`; the two must be kept in sync by
  hand — the `NATS_STREAM` default in particular, and the `NATS_MAX_BYTES`/`NATS_MAX_AGE_S`
  BAITS-stream disk caps, which both sides provision.

## Plan

Pure standard library (`os`, `pathlib`), no third-party dependencies. It ships inside the single
`blacksea` distribution (root `services/pyproject.toml`, installed editable via `make install`) —
no `PYTHONPATH` export and no per-module packaging. Values are grouped by concern; each reads its
env var through a small typed helper (`_str`/`_opt`/`_int`/`_float`/`_bool`) so "unset" and "set but
empty" behave identically.

## File list

- `src/blacksea/config/__init__.py` — re-exports the `settings` submodule.
- `src/blacksea/config/settings.py` — all operational settings, grouped and documented.
- `src/blacksea/config/envload.py` — locates/parses `config/blacksea.env` (falling back to the
  legacy `secrets/env`), assembles a Postgres DSN from coordinates, and loads it into `os.environ`
  with env-wins precedence. Also computes `PROJECT_ROOT` (the package-derived, CWD-independent
  anchor) and adds `<PROJECT_ROOT>/config/blacksea.env` as the final config-discovery fallback. A
  leaf: imports nothing from `blacksea` (not even `settings`, which imports it), so there is no
  import cycle.

## Dependencies

None (standard library only). **Consumed by:** `blacksea.brain` (`pool.py`, `assembly.py`),
`blacksea.control_plane` (`cli.py`, `factory.py`), `blacksea.observer`
(`__main__.py`, `api.py`, `service.py`), `blacksea.correlation` (`queries.py`, `reader.py`),
and `blacksea.otel_export` (the `BS_OTEL_*` block: emitter endpoint/protocol/headers/TLS,
`BS_OTEL_ENABLED`, `BS_OTEL_EMIT_DETAILS`, poll cadence, cursor seed).

## Invariants

- **The deployed payload never imports this package** (upholds the SDK import-minimality invariant).
- **Protocol/wire constants are never defined here** (they are contracts, not knobs).
- **The Go edge's `config.go` mirror must agree with the shared defaults here** — notably
  `NATS_STREAM` (or the two sides create overlapping JetStream streams) and
  `NATS_MAX_BYTES`/`NATS_MAX_AGE_S` (the BAITS-stream disk caps — a mismatch lets whichever side
  provisions the stream last silently re-widen it back toward unbounded).
- **Config + operational paths resolve independent of the CWD.** The installed `blacksea` must
  behave the same from any working directory (config discovered via the package anchor; operational
  paths anchored under `BS_PROJECT_ROOT`). Locked by `tests/config/test_envload.py`; regressing it
  reintroduces the "no Postgres DSN outside the checkout" failure.
