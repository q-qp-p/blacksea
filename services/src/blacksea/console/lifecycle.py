"""lifecycle.py — `blacksea init` logic. **No click/rich** (facade purity).

`blacksea init` picks the infra **mode** once and writes the ONE unified config file
``config/blacksea.env`` that every consumer reads (see :mod:`blacksea.config.envload`):

* **docker** — Blacksea will run Postgres + NATS in containers. Generates random credentials (or
  reuses ones already present, so an existing Postgres data volume keeps working) and writes
  ``BS_INFRA=docker`` + the localhost coordinates.
* **external** — the operator runs their own Postgres + NATS. Takes an opaque ``POSTGRES_DSN`` +
  ``NATS_URL``/creds (+ optional TLS), **validates connectivity before saving**, and writes
  ``BS_INFRA=external``. Blacksea never generates or overwrites those credentials.

This module is pure (imports no click/rich); the interactive prompting lives in
``commands/init.py``, which resolves values and hands them here. The credential *file* is written
``0600`` (it can carry a DB password / NATS creds), mirroring the ``otel_ctl`` config writer.
"""

from __future__ import annotations

import os
import re
import secrets
import socket
import subprocess
from collections.abc import Callable
from urllib.parse import urlsplit

import psycopg

from blacksea.config import envload

from .models import InitResult


class InitError(Exception):
    """A failed ``blacksea init`` — refusing to overwrite without ``--force``, external infra
    unreachable, or a missing required value. Operational failure, exit code 1."""

    exit_code = 1


def _gen_secret() -> str:
    """A fresh 24-byte hex credential — no spaces or shell/Make/compose-special characters, so the
    same ``KEY=value`` file is safely consumed by ``docker compose --env-file``, Make's ``-include``,
    and the console supervisor's env-passing."""
    return secrets.token_hex(24)


def _expected_pg_volume() -> str:
    """The Postgres data-volume name **this** Blacksea stack's ``docker compose`` mounts —
    ``<project>_pg_data``, where ``project`` is docker-compose's project name: ``$COMPOSE_PROJECT_NAME``
    if set, else the sanitized basename of the compose file's directory (lowercased, characters outside
    ``[a-z0-9_-]`` dropped — compose's own normalization). Anchoring the drift probe to this exact name,
    rather than any ``*pg_data`` volume, keeps it from warning about an unrelated compose stack's volume
    that happens to share the ``pg_data`` suffix."""
    from blacksea.config import settings  # lazy: keep the settings import off the pure init path
    project = os.environ.get("COMPOSE_PROJECT_NAME") or os.path.basename(
        os.path.dirname(os.path.abspath(settings.BS_COMPOSE_FILE)))
    return f"{re.sub(r'[^a-z0-9_-]', '', project.lower())}_pg_data"


def _docker_pg_volume_present() -> bool:
    """Best-effort: is **this stack's** Postgres data volume (:func:`_expected_pg_volume`) already
    present on this host? Used to warn when a docker-mode ``init`` is about to mint a FRESH password
    while that volume — with a different password baked into its role at *its* first init — is still
    around. Postgres never re-applies ``POSTGRES_PASSWORD`` to an existing data dir, so that
    combination is exactly the drift that makes the host connection fail with ``password
    authentication failed`` even though the config file and the container env agree. Any failure (no
    docker binary, daemon down, timeout) → ``False``: we warn only on a positive sighting, never on a
    guess, so a normal fresh init stays quiet."""
    try:
        out = subprocess.run(
            ["docker", "volume", "ls", "--format", "{{.Name}}"],
            capture_output=True, text=True, timeout=5, check=True).stdout
    except (OSError, subprocess.SubprocessError):
        return False
    return _expected_pg_volume() in {name.strip() for name in out.splitlines() if name.strip()}


def _write_env_file(path: str, lines: list[str]) -> None:
    """Write the config file ``0600`` (it carries credentials), creating the parent dir. A dir we
    create is set ``0700`` so the credential file isn't left in a world-traversable directory
    (matching the old ``secrets/`` posture); a pre-existing dir is left untouched so a custom
    ``--config`` path never retightens something like the repo root."""
    parent = os.path.dirname(os.path.abspath(path)) or "."
    created = not os.path.isdir(parent)
    os.makedirs(parent, exist_ok=True)
    if created:
        os.chmod(parent, 0o700)
    content = "\n".join(lines) + "\n"
    # `os.open`'s `mode` only applies when the file is newly created — it does NOT retighten an
    # already-existing file's permissions (e.g. a `--force` overwrite of a file someone had
    # loosened by hand). chmod unconditionally after writing so "written 0600" holds regardless.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(path, 0o600)


def _gitignore_safe(path: str) -> bool:
    """True when ``path`` sits at ``config/<name>.env`` — the location the repo ``.gitignore`` covers
    (``config/blacksea.env`` + ``config/*.env``). A path anywhere else (e.g. ``--config infra.env`` at
    the repo root) is NOT ignored, so writing the credential file there risks committing secrets."""
    parts = os.path.normpath(path).split(os.sep)
    return len(parts) >= 2 and parts[-2] == "config" and parts[-1].endswith(".env")


def _redact_dsn(dsn: str) -> str:
    """A non-secret one-line shape of a libpq DSN for display — password stripped."""
    return " ".join(tok for tok in dsn.split() if not tok.startswith("password=")).strip() or dsn


class Initializer:
    """Writes ``config/blacksea.env``. The default target is the **package-anchored**
    ``<PROJECT_ROOT>/config/blacksea.env`` (:func:`envload.anchored`) — the same location the loader
    reads from — so ``blacksea init`` writes to the right place and the overwrite guard sees any
    existing config regardless of the CWD (pass ``--config`` to override). ``legacy_path`` is the
    pre-unification creds-only ``secrets/env`` it migrates from, anchored the same way."""

    def __init__(
        self, config_path: str | None = None, legacy_path: str | None = None,
        volume_probe: Callable[[], bool] | None = None,
    ) -> None:
        self.config_path = config_path or envload.anchored(envload.CONFIG_RELPATH)
        self.legacy_path = legacy_path or envload.anchored(envload.LEGACY_SECRETS_RELPATH)
        # Best-effort "does a pg_data volume already exist?" probe — injectable so tests can drive both
        # branches without a docker daemon. Defaults to the real `docker volume ls` probe.
        self._volume_probe = volume_probe or _docker_pg_volume_present

    # ── credential carry-forward ────────────────────────────────────────────────

    def existing_creds(self) -> tuple[str | None, str | None]:
        """The ``(POSTGRES_PASSWORD, NATS_PASS)`` already on disk — from ``config/blacksea.env`` if
        present, else the legacy ``secrets/env`` — so re-running/​migrating keeps the credentials a
        running Postgres volume was created with. ``(None, None)`` if neither exists."""
        for path in (self.config_path, self.legacy_path):
            if os.path.exists(path):
                env = envload.parse_env_file(path)
                if env.get("POSTGRES_PASSWORD") or env.get("NATS_PASS"):
                    return env.get("POSTGRES_PASSWORD"), env.get("NATS_PASS")
        return None, None

    def _guard_overwrite(self, force: bool) -> None:
        if os.path.exists(self.config_path) and not force:
            raise InitError(
                f"{self.config_path} already exists — pass --force to overwrite. "
                f"(To rotate credentials, delete it and re-run init, then re-sync Postgres — which "
                f"otherwise keeps the OLD password baked into its data dir. EITHER keep your data and "
                f"align the running role to the new password: `ALTER ROLE <POSTGRES_USER> PASSWORD "
                f"'<new>'` (a non-destructive re-sync); OR recreate the volume so Postgres re-inits "
                f"with it: `docker compose --env-file {self.config_path} down -v && blacksea up` — "
                f"this DESTROYS existing data.)")

    def _safety_notes(self) -> list[str]:
        """Warn if the credential file is being written somewhere ``.gitignore`` does not cover."""
        if _gitignore_safe(self.config_path):
            return []
        return [f"⚠ {self.config_path} holds credentials and is NOT covered by .gitignore "
                f"(only config/*.env is) — do not commit it"]

    def _drop_legacy_after_migration(self, config_existed: bool, notes: list[str]) -> None:
        """Once the credentials live in ``config/blacksea.env``, the legacy ``secrets/env`` must not
        linger: this writer carries its old password forward, so a lingering copy would silently
        shadow a later rotation (delete config + re-init would just re-migrate the same password).
        Remove it after a *migrating* write (config did not previously exist)."""
        if (not config_existed and self.legacy_path != self.config_path
                and os.path.exists(self.legacy_path)):
            os.remove(self.legacy_path)
            notes.append(
                f"removed the legacy {self.legacy_path} (its creds now live in the config file)")

    # ── docker mode ─────────────────────────────────────────────────────────────

    def init_docker(self, *, force: bool = False) -> InitResult:
        """Write a ``BS_INFRA=docker`` config: reuse any credentials already on disk (keeps an
        existing Postgres volume working), else generate fresh ones."""
        self._guard_overwrite(force)
        config_existed = os.path.exists(self.config_path)
        pg_pass, nats_pass = self.existing_creds()
        notes: list[str] = []
        if pg_pass or nats_pass:
            notes.append("kept existing credentials (an existing Postgres volume stays valid)")
        # Drift guard: minting a FRESH password (no creds carried forward) while a `pg_data` volume is
        # still around means Postgres keeps the volume's OLD password and the host connection will fail
        # `password authentication failed`. Warn — the file is written either way (init is pure file
        # I/O), but the operator needs to re-sync Postgres. Mirrors the overwrite-guard rotate note.
        elif self._volume_probe():
            notes.append(
                "⚠ a Postgres data volume already exists but no credentials were carried forward — "
                "the fresh password below will NOT match it (Postgres keeps the volume's original "
                "password), so connections will fail `password authentication failed` until you "
                "re-sync: `ALTER ROLE <POSTGRES_USER> PASSWORD '<new>'` to keep your data, or "
                f"`docker compose --env-file {self.config_path} down -v && blacksea up` to recreate "
                "the volume (destroys existing data)")
        pg_pass = pg_pass or _gen_secret()
        nats_pass = nats_pass or _gen_secret()
        lines = [
            "# Blacksea runtime config — infra mode + backing-service coordinates + credentials.",
            "# Written by `blacksea init`. Read by the Python apps (blacksea.config.envload),",
            "# docker-compose (--env-file), the Makefile (-include, for `make test`), and the console",
            "# supervisor (blacksea up). Credentials live here — DO NOT COMMIT (gitignored).",
            "BS_INFRA=docker",
            f"POSTGRES_HOST={envload.DEV_HOST}",
            f"POSTGRES_PORT={envload.DEV_PORT}",
            f"POSTGRES_DB={envload.DEV_DB}",
            f"POSTGRES_USER={envload.DEV_USER}",
            f"POSTGRES_PASSWORD={pg_pass}",
            "NATS_URL=nats://localhost:4222",
            "NATS_USER=blacksea",
            f"NATS_PASS={nats_pass}",
        ]
        _write_env_file(self.config_path, lines)
        self._drop_legacy_after_migration(config_existed, notes)
        notes.append("next: `blacksea up` to start Postgres + NATS + the edge + brain")
        notes.extend(self._safety_notes())
        return InitResult(
            mode="docker",
            config_path=self.config_path,
            created=True,
            postgres_summary=f"{envload.DEV_HOST}:{envload.DEV_PORT}/{envload.DEV_DB}",
            nats_summary="nats://localhost:4222",
            validated=False,
            notes=notes,
        )

    # ── external mode ───────────────────────────────────────────────────────────

    def init_external(
        self, *, postgres_dsn: str, nats_url: str, nats_user: str | None = None,
        nats_pass: str | None = None, tls_ca: str | None = None, tls_cert: str | None = None,
        tls_key: str | None = None, force: bool = False, validate: bool = True,
    ) -> InitResult:
        """Write a ``BS_INFRA=external`` config from operator-supplied connection info. Validates
        Postgres + NATS reachability first (unless ``validate=False``) and writes **nothing** if a
        check fails — so a broken deployment never silently persists bad coordinates."""
        if not postgres_dsn or not nats_url:
            raise InitError("external mode requires both a Postgres DSN and a NATS URL")
        self._guard_overwrite(force)
        validated = False
        if validate:
            self._validate_external(postgres_dsn, nats_url)
            validated = True
        lines = [
            "# Blacksea runtime config — EXTERNAL infra (operator-managed Postgres + NATS).",
            "# Blacksea connects to these and never provisions or overwrites them. DO NOT COMMIT.",
            "BS_INFRA=external",
            f"POSTGRES_DSN={postgres_dsn}",
            f"NATS_URL={nats_url}",
        ]
        if nats_user:
            lines.append(f"NATS_USER={nats_user}")
        if nats_pass:
            lines.append(f"NATS_PASS={nats_pass}")
        # Optional TLS for the edge↔NATS hop (consumed when the edge runs on a separate network).
        # Written commented when unset so the knob is discoverable.
        for key, val in (("NATS_CA", tls_ca), ("NATS_TLS_CERT", tls_cert), ("NATS_TLS_KEY", tls_key)):
            lines.append(f"{key}={val}" if val else f"# {key}=")
        _write_env_file(self.config_path, lines)
        notes = ["Blacksea will not manage these services — start your own Postgres + NATS"]
        if not validate:
            notes.insert(0, "connectivity was NOT validated (--no-validate)")
        notes.extend(self._safety_notes())
        return InitResult(
            mode="external",
            config_path=self.config_path,
            created=True,
            postgres_summary=_redact_dsn(postgres_dsn),
            nats_summary=nats_url,
            validated=validated,
            notes=notes,
        )

    def _validate_external(self, postgres_dsn: str, nats_url: str, timeout: float = 3.0) -> None:
        """Fail fast + specifically if either backing service is unreachable — before saving."""
        try:
            with psycopg.connect(postgres_dsn, connect_timeout=int(timeout)):
                pass
        except psycopg.Error as exc:
            raise InitError(f"Postgres unreachable — {exc}. Nothing was written.") from exc
        host, port = _nats_hostport(nats_url)
        try:
            with socket.create_connection((host, port), timeout=timeout):
                pass
        except OSError as exc:
            raise InitError(
                f"NATS {host}:{port} unreachable — {exc.__class__.__name__}. Nothing was written."
            ) from exc


def _nats_hostport(url: str, default_port: int = 4222) -> tuple[str, int]:
    """Extract ``(host, port)`` from a ``nats://host:port`` (or bare ``host:port``) URL."""
    parts = urlsplit(url if "://" in url else f"//{url}")
    return (parts.hostname or "127.0.0.1", parts.port or default_port)
