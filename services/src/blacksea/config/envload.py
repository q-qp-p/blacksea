"""blacksea.config.envload — locate and load the ONE Blacksea config file into ``os.environ``.

``make init`` (the hidden ``blacksea init`` under the hood) writes a single flat ``KEY=VALUE`` file,
``config/blacksea.env``, carrying the infra **mode** (``BS_INFRA``) plus the backing-service
coordinates and credentials. That one file is what every consumer reads:

* the **Python apps** — via this loader, imported by :mod:`blacksea.config.settings`, so a bare
  ``blacksea`` / ``python -m blacksea.brain.pool`` / ``pytest`` picks it up with no wrapper exporting it;
* **docker-compose** — ``--env-file config/blacksea.env``;
* the **Makefile** — ``-include config/blacksea.env``;
* the **console supervisor** (``blacksea up`` — ``console/supervisor.py``), which reads this file to
  hand the Go edge its NATS creds when it launches the edge + brain daemons (design step 3).

This retires an earlier state where the DSN/URL were re-derived in four places
(``settings.py`` / ``Makefile`` / ``dev-up.sh`` / ``edge/config.go``) with ``localhost`` hardcoded
into the DSN — the "config assembled in four places" pain.

PRECEDENCE — a variable already present in the environment ALWAYS wins over the file, so
``--postgres``, an explicit ``POSTGRES_DSN=…``, and the per-process env the console supervisor
passes to the daemons all override it (:func:`load_into_environ` uses ``os.environ.setdefault``). A
missing file is a silent no-op (a fresh checkout before ``make init``).

MIGRATION — when no ``config/blacksea.env`` exists yet, the loader falls back to the legacy
``secrets/env`` (which held only ``POSTGRES_PASSWORD``/``NATS_PASS``); combined with the coordinate
defaults below that still yields the correct dev DSN, so an un-migrated checkout keeps working until
the first ``make init`` / ``blacksea up`` writes the unified file.

This module is a leaf: **pure standard library, imports nothing from blacksea** (in particular not
``settings``, which imports *it*) so there is no import cycle.

PORTABILITY — the package **is** the anchor. Blacksea is always an *editable* install
(``pip install -e .``, driven by ``make install``), so this file's ``__file__`` resolves into the
real source tree — ``<root>/src/blacksea/config/envload.py`` → :data:`PROJECT_ROOT` is ``<root>`` (the
``services/`` dir), computed once at import and **independent of the CWD**. That is what lets an
installed ``blacksea`` (on ``PATH`` at ``~/.local/bin/blacksea``) resolve its config from *any*
working directory, not only from inside the checkout: :func:`find_config_file` falls back to
``<PROJECT_ROOT>/config/blacksea.env`` after the CWD-upward walk. :mod:`blacksea.config.settings`
re-exports :data:`PROJECT_ROOT` as ``BS_PROJECT_ROOT`` and anchors its operational path defaults to
it, so ``up`` / ``forge`` / ``reset`` are location-independent too.
"""

from __future__ import annotations

import os
from pathlib import Path

# The unified config file, relative to a project root; and the legacy creds-only file it supersedes.
CONFIG_RELPATH = os.path.join("config", "blacksea.env")
LEGACY_SECRETS_RELPATH = os.path.join("secrets", "env")


def _package_project_root() -> str | None:
    """The absolute project root, inferred from THIS installed package's location.

    Resolution: ``$BS_PROJECT_ROOT`` if set (explicit override — for a relocated/non-editable
    install), else the package-derived root ``Path(__file__).resolve().parents[3]`` (this file is
    ``<root>/src/blacksea/config/envload.py``), **validated** by the presence of ``pyproject.toml``
    at that root — so a stray install where ``__file__`` sits in ``site-packages`` yields ``None``
    (a bogus path is never returned). ``None`` disables the package anchor; callers then fall back to
    the CWD-relative behavior. CWD-independent by construction."""
    override = os.environ.get("BS_PROJECT_ROOT")
    if override:
        return override
    try:
        root = str(Path(__file__).resolve().parents[3])
    except (OSError, IndexError):
        return None
    return root if os.path.exists(os.path.join(root, "pyproject.toml")) else None


# Computed once at import — the CWD-independent anchor. Monkeypatchable in tests that exercise the
# pure CWD-walk discovery in isolation (set it to ``None`` to suppress the package fallback).
PROJECT_ROOT = _package_project_root()


def anchored(relpath: str) -> str:
    """``<PROJECT_ROOT>/relpath`` when the package anchor is known, else ``relpath`` (CWD-relative
    fallback). This is the **write-side mirror** of the read-side fallback in
    :func:`find_config_file`: ``blacksea init`` writes ``config/blacksea.env`` *here*, i.e. exactly
    where the loader will later look for it — so init is correct from any CWD, and the overwrite
    guard sees the real existing file instead of silently minting a stray config with fresh
    credentials that mismatch a running Postgres volume."""
    return os.path.join(PROJECT_ROOT, relpath) if PROJECT_ROOT else relpath

# The canonical dev/docker coordinate defaults for the Python side — ``console/envfile.py`` delegates
# to :func:`dsn_from_coords` rather than keeping its own copy. The ``Makefile`` necessarily mirrors
# these (Make cannot import this module — see its ``POSTGRES_HOST ?= localhost`` block) and must stay
# in sync by hand. ``localhost`` is a *default coordinate* here, not a DSN baked to assume host-local
# Postgres: in external mode ``config/blacksea.env`` supplies an opaque ``POSTGRES_DSN`` that wins
# outright, so nothing assembles ``host=localhost`` for a remote DB.
DEV_HOST = "localhost"
DEV_PORT = "5432"
DEV_DB = "blacksea"
DEV_USER = "blacksea"


def parse_env_file(path: str) -> dict[str, str]:
    """Parse a dotenv-style file (``KEY=value``, ``#`` comments, optional ``export``, optional
    quotes) into a dict. A missing/unreadable file is an empty dict, never an error."""
    out: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                if line.startswith("export "):
                    line = line[len("export "):]
                key, _, value = line.partition("=")
                out[key.strip()] = value.strip().strip('"').strip("'")
    except OSError:
        return {}
    return out


def dsn_from_coords(env: dict[str, str] | None = None) -> str | None:
    """Assemble a libpq DSN from ``POSTGRES_HOST``/``PORT``/``DB``/``USER``/``PASSWORD`` in ``env``
    (default ``os.environ``), using the dev coordinate defaults for anything unset. Returns ``None``
    when no password is present — there is no safe literal password default, and a passwordless DSN
    would silently mean "no auth". Does **not** consider ``POSTGRES_DSN`` (an opaque DSN is the
    caller's precedence concern)."""
    e = os.environ if env is None else env
    password = e.get("POSTGRES_PASSWORD")
    if not password:
        return None
    host = e.get("POSTGRES_HOST", DEV_HOST)
    port = e.get("POSTGRES_PORT", DEV_PORT)
    dbname = e.get("POSTGRES_DB", DEV_DB)
    user = e.get("POSTGRES_USER", DEV_USER)
    return f"host={host} port={port} dbname={dbname} user={user} password={password}"


def find_config_file(explicit: str | None = None, start: str | None = None) -> str | None:
    """Locate the config file. Order, highest precedence first:

    1. ``explicit`` arg (``--config``);
    2. ``$BS_CONFIG``;
    3. ``config/blacksea.env`` then the legacy ``secrets/env``, from ``start`` (default CWD) upward a
       few levels — so a checkout you are actively hacking in wins (``git config --local``-style);
    4. the **package anchor** ``<PROJECT_ROOT>/config/blacksea.env`` then ``<PROJECT_ROOT>/secrets/env``
       — CWD-independent, so an installed ``blacksea`` resolves its config from *any* directory, not
       only from inside the checkout (this is the fix for "works inside ./, fails elsewhere").

    Returns the first existing path, or ``None``."""
    if explicit:
        return explicit if os.path.exists(explicit) else None
    env_override = os.environ.get("BS_CONFIG")
    if env_override:
        return env_override if os.path.exists(env_override) else None
    directory = os.path.abspath(start or os.getcwd())
    for _ in range(5):  # CWD + up to 4 parents
        for relpath in (CONFIG_RELPATH, LEGACY_SECRETS_RELPATH):
            candidate = os.path.join(directory, relpath)
            if os.path.exists(candidate):
                return candidate
        parent = os.path.dirname(directory)
        if parent == directory:
            break
        directory = parent
    # Package anchor (step 4): the installed package knows where the source tree is, regardless of
    # CWD. ``PROJECT_ROOT`` is ``None`` for a non-editable/relocated install → skipped.
    if PROJECT_ROOT:
        for relpath in (CONFIG_RELPATH, LEGACY_SECRETS_RELPATH):
            candidate = os.path.join(PROJECT_ROOT, relpath)
            if os.path.exists(candidate):
                return candidate
    return None


def load_into_environ(explicit: str | None = None, start: str | None = None) -> str | None:
    """Find the config file and populate ``os.environ`` from it for any key **not already set**
    (env always wins). Returns the path loaded, or ``None`` if none was found. Called once, at
    :mod:`blacksea.config.settings` import time, so the whole system reads one file."""
    path = find_config_file(explicit, start)
    if not path:
        return None
    for key, value in parse_env_file(path).items():
        os.environ.setdefault(key, value)
    return path
