"""otel_ctl.py — OTel emitter control. **No click/rich** (facade purity).

The console does not background-supervise the emitter. It:

* **owns the config** — a dedicated env file ``secrets/otel.env`` (separate from ``secrets/env``),
  holding validated ``BS_OTEL_*`` keys; ``otel config show``/``set`` read/write it;
* **runs it in the foreground** — ``otel run`` loads ``secrets/otel.env`` into a freshly-spawned
  ``python -m blacksea.otel_export`` and streams its logs (Ctrl-C stops — the runner flushes on
  SIGINT/SIGTERM);
* **emits an OS unit** — ``otel install-unit`` writes a systemd unit (or a compose snippet) with
  ``EnvironmentFile=secrets/otel.env`` for durable always-on running.

Config plumbing: ``settings.py`` resolves every ``BS_OTEL_*`` from
``os.environ`` **at import time** and the emitter reads them **once at startup** — it never
re-reads. So ``otel config set`` applies only to the **next** ``run``/unit start, never a running
emitter; the CLI prints "restart the emitter to apply." The seam that makes the env file take
effect is that ``otel run`` spawns a *fresh subprocess* whose ``settings.py`` resolves from the
injected env.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass

from .models import ComponentStatus, OtelStatus

# The keys `otel config set` is allowed to manage — exactly the BS_OTEL_* block in
# blacksea.config.settings. Setting anything else is a usage error (typo protection).
OTEL_KEYS: tuple[str, ...] = (
    "BS_OTEL_ENABLED",
    "BS_OTEL_ENDPOINT",
    "BS_OTEL_PROTOCOL",
    "BS_OTEL_HEADERS",
    "BS_OTEL_TLS_CA",
    "BS_OTEL_TLS_CERT",
    "BS_OTEL_TLS_KEY",
    "BS_OTEL_DEPLOYMENT_ID",
    "BS_OTEL_EMIT_DETAILS",
    "BS_OTEL_POLL_INTERVAL",
    "BS_OTEL_START_TIME",
    "BS_OTEL_BATCH_LIMIT",
)


class OtelConfigError(Exception):
    """A bad ``otel config set`` — unknown key, or a malformed ``KEY=VALUE`` — exit code 2."""

    exit_code = 2


@dataclass
class OtelControl:
    """Manages the ``secrets/otel.env`` file and the emitter subprocess. Constructed by the
    facade with the resolved env-file path and the DSN the emitter needs (from the console's own
    config, never re-read from click)."""

    env_path: str
    postgres_dsn: str
    unit_path: str                # where install-unit writes (e.g. secrets/blacksea-otel.service)

    # ── env-file management ─────────────────────────────────────────────────────

    def read_env(self) -> dict[str, str]:
        """Parse ``secrets/otel.env`` into a dict. A missing file is an empty config (not an
        error) — ``otel config set`` creates it on first write. Systemd-``EnvironmentFile``
        syntax: ``KEY=VALUE`` lines, ``#`` comments, blanks ignored, no ``export``."""
        out: dict[str, str] = {}
        if not os.path.exists(self.env_path):
            return out
        with open(self.env_path, encoding="utf-8") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                out[key.strip()] = value.strip()
        return out

    def set_values(self, updates: dict[str, str]) -> dict[str, str]:
        """Validate + merge ``updates`` into the env file, write it back 0600, and return the
        merged config. Raises :class:`OtelConfigError` on an unknown key."""
        unknown = [k for k in updates if k not in OTEL_KEYS]
        if unknown:
            raise OtelConfigError(
                f"unknown otel config key(s) {sorted(unknown)} — valid keys: {', '.join(OTEL_KEYS)}")
        merged = {**self.read_env(), **updates}
        self._write_env(merged)
        return merged

    def _write_env(self, config: dict[str, str]) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.env_path)) or ".", exist_ok=True)
        lines = [
            "# blacksea otel emitter config — managed by `blacksea otel config set`.",
            "# EnvironmentFile-compatible (KEY=VALUE, no export). Changes apply on the NEXT",
            "# `blacksea otel run` / unit (start); a running emitter reads BS_OTEL_* once at",
            "# startup and never re-reads.",
        ]
        # Emit in the canonical BS_OTEL_* order for a stable, diff-friendly file.
        for key in OTEL_KEYS:
            if key in config:
                lines.append(f"{key}={config[key]}")
        # Preserve any stray extra keys the operator hand-added, rather than dropping them.
        for key, value in config.items():
            if key not in OTEL_KEYS:
                lines.append(f"{key}={value}")
        content = "\n".join(lines) + "\n"
        # 0600 — it can carry auth headers / TLS material. `os.open`'s `mode` only applies when
        # the file is newly created, so an existing looser-permission file needs an explicit
        # chmod too (mirrors lifecycle.py's `_write_env_file`).
        fd = os.open(self.env_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.chmod(self.env_path, 0o600)

    def status(self) -> OtelStatus:
        return OtelStatus(
            env_path=self.env_path,
            exists=os.path.exists(self.env_path),
            config=self.read_env(),
            unit_installed=os.path.exists(self.unit_path),
            unit_detail=(f"installed at {self.unit_path}"
                         if os.path.exists(self.unit_path) else "no unit written"),
        )

    def status_component(self) -> ComponentStatus:
        """The otel row for `blacksea status`: the console holds no otel process
        state, so it probes indirectly — the systemd unit's own status if a unit was installed
        and ``systemctl`` is available, else an honest ``unmanaged/unknown``."""
        if not os.path.exists(self.unit_path):
            return ComponentStatus(
                "otel", "unknown", "inferred",
                "no unit installed — run in the foreground with `blacksea otel run`, or "
                "`blacksea otel install-unit` for always-on")
        unit_name = os.path.basename(self.unit_path)
        systemctl = shutil.which("systemctl")
        if not systemctl:
            return ComponentStatus(
                "otel", "unknown", "unit",
                f"unit written ({self.unit_path}); no systemctl to query its status here")
        try:
            proc = subprocess.run(
                [systemctl, "is-active", unit_name],
                capture_output=True, text=True, timeout=3)
            state = (proc.stdout or proc.stderr).strip() or "unknown"
        except Exception as exc:  # noqa: BLE001
            return ComponentStatus("otel", "unknown", "unit", f"systemctl query failed: {exc}")
        up = state == "active"
        return ComponentStatus(
            "otel", "up" if up else ("unknown" if state == "unknown" else "down"),
            "unit", f"systemd unit {unit_name}: {state}")

    # ── foreground run ──────────────────────────────────────────────────────────

    def child_env(self) -> dict[str, str]:
        """The environment the spawned emitter runs with: the current env, plus the managed
        ``secrets/otel.env`` values layered on top, plus the console's ``POSTGRES_DSN`` (the
        emitter tails the durable records table) and ``BS_OTEL_ENABLED=1`` defaulted on (the
        operator explicitly asked to run it)."""
        env = dict(os.environ)
        if self.postgres_dsn:
            env["POSTGRES_DSN"] = self.postgres_dsn
        env.update(self.read_env())
        env.setdefault("BS_OTEL_ENABLED", "1")
        return env

    def run_foreground(self) -> int:
        """Spawn ``python -m blacksea.otel_export`` with the loaded env and stream its logs.
        Blocks until the child exits; returns the child's exit code. Ctrl-C (SIGINT) reaches
        the child in the same process group, and its runner flushes + shuts down cleanly."""
        cmd = [sys.executable, "-m", "blacksea.otel_export"]
        try:
            completed = subprocess.run(cmd, env=self.child_env())
        except KeyboardInterrupt:
            # The child got the same SIGINT and is flushing; treat as a clean stop.
            return 0
        return completed.returncode

    # ── OS unit emission ────────────────────────────────────────────────────────

    def render_systemd_unit(self) -> str:
        """A systemd service unit for durable always-on running. ``EnvironmentFile`` points at
        the managed otel.env; ``POSTGRES_DSN`` is embedded as an ``Environment=`` line from the
        console's current config (the emitter needs it and it is not a BS_OTEL_* key). WorkingDir
        is the repo so relative paths (e.g. ``secrets/otel.env``) resolve; the emitter module is
        found via the installed ``blacksea`` package."""
        workdir = os.getcwd()
        env_abspath = os.path.abspath(self.env_path)
        dsn_line = f'Environment="POSTGRES_DSN={self.postgres_dsn}"\n' if self.postgres_dsn else ""
        return (
            "[Unit]\n"
            "Description=Blacksea OTLP telemetry emitter (blacksea.otel_export)\n"
            "After=network-online.target\n"
            "Wants=network-online.target\n"
            "\n"
            "[Service]\n"
            "Type=simple\n"
            f"WorkingDirectory={workdir}\n"
            f"EnvironmentFile={env_abspath}\n"
            f"{dsn_line}"
            f"ExecStart={sys.executable} -m blacksea.otel_export\n"
            "Restart=on-failure\n"
            "RestartSec=5\n"
            "\n"
            "[Install]\n"
            "WantedBy=multi-user.target\n"
        )

    def render_compose_snippet(self) -> str:
        """A docker-compose service snippet (the non-systemd host alternative)."""
        env_abspath = os.path.abspath(self.env_path)
        return (
            "  otel-emitter:\n"
            "    image: blacksea/otel-export:latest   # build/point at your image\n"
            "    command: [\"python\", \"-m\", \"blacksea.otel_export\"]\n"
            "    env_file:\n"
            f"      - {env_abspath}\n"
            "    environment:\n"
            f"      POSTGRES_DSN: \"{self.postgres_dsn}\"\n"
            "    restart: on-failure\n"
        )

    def install_unit(self, *, flavor: str = "systemd") -> str:
        """Write the unit to ``unit_path`` and return the path. ``flavor`` is ``systemd``
        (default) or ``compose``. Written ``0600`` — like the unit's own `EnvironmentFile`, it
        embeds ``POSTGRES_DSN`` (with password) directly, so it's credential-bearing too."""
        content = (self.render_compose_snippet() if flavor == "compose"
                   else self.render_systemd_unit())
        os.makedirs(os.path.dirname(os.path.abspath(self.unit_path)) or ".", exist_ok=True)
        fd = os.open(self.unit_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.chmod(self.unit_path, 0o600)
        return self.unit_path
