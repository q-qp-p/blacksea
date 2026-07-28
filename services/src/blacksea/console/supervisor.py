"""supervisor.py — the local lifecycle supervisor behind ``blacksea up/down/logs/reset``.
**No click/rich** (facade purity — imported by ``service.py``).

This is the Python port of the retired ``scripts/dev-up.sh`` + ``dev-down.sh`` + ``dev-status.sh`` +
``reset-state.sh`` shell supervisor: one front door replaces the hand-rolled nohup/PID scaffolding.
A ``blacksea`` invocation is a client that **exits**, so ``up`` starts the app daemons *detached*
(``start_new_session=True`` — its own session/process-group, surviving the CLI exit) under
``BS_DEV_DIR`` (``.dev/``) with a ``<name>.pid`` / ``<name>.log`` / ``<name>.cmd`` triple, exactly
like ``dev-up.sh``. Re-running is idempotent: a daemon already alive with the *same* launch
fingerprint (argv + env) is left alone; one alive with a *different* fingerprint (e.g. a changed
``BS_BRAIN_KEYDIR_POLL_S``) is stopped and replaced.

**Two infra modes** (the ``BS_INFRA`` switch):

* **docker** — ``up`` drives ``docker compose`` for Postgres + NATS (waiting until Postgres is
  ready), then starts the native daemons. ``down --infra`` takes the containers back down.
* **external** — Blacksea never touches the operator's Postgres/NATS: ``up`` *verifies* reachability
  and, if either is down, starts **nothing** and fails specifically; ``down`` never runs compose.

**Edge on a separate network (the advanced shape).** The edge is a self-contained dead-drop that
needs only NATS reachability — it can live on a different network from the brain. The
supervisor manages a *host-specific* subset of daemons, never a fixed ``[edge, brain]`` pair:

* **co-located** (dev default) — one host runs ``edge`` + ``brain`` (+ infra).
* **brain host, ``--edge-separate``** — ``up`` manages ``brain`` only (+ infra); the edge lives
  elsewhere, so it is neither built, started, nor probed here.
* **edge host, ``up --edge-only``** — ``up`` builds + starts only the ``edge``, pointed at the
  (remote) ``NATS_URL``, with the ``NATS_CA``/``NATS_TLS_*`` knobs passed through for the TLS hop;
  no infra, no Postgres, no brain.

``down`` / ``status`` / ``logs`` / ``reset`` restrict themselves to the daemons ``_managed_daemons``
says this host owns (co-located → both; ``edge_co_located=False``, i.e. a brain host configured
with ``--edge-separate`` → ``brain`` only) intersected with whichever of those actually have a
``.dev/<name>`` triple on disk — so a stale ``.dev/brain.*`` left over from an earlier co-located
run can't make a repurposed edge-only host manage a daemon it no longer owns. There is no
persistent equivalent of ``up --edge-only`` (a per-invocation bring-up choice, not a host identity),
so that one shape is only enforced by ``up`` itself.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import signal
import socket
import subprocess
import time
from urllib.parse import urlsplit

import psycopg
from psycopg import sql

from blacksea.config import envload
from blacksea.control_plane.schema import validate_schema

from .models import DaemonStatus, DownResult, ResetResult, UpResult

# The daemons the supervisor knows how to manage. ``up`` starts a host-specific subset; the other
# verbs act on whichever of these this host is configured to own (see `_managed_daemons`).
EDGE, BRAIN = "edge", "brain"
KNOWN_DAEMONS = (EDGE, BRAIN)

_START_SETTLE_S = 0.3      # grace after spawn to catch an immediately-dying daemon (matches dev-up.sh)
_STOP_GRACE_S = 4.0        # SIGTERM → wait this long → SIGKILL
_PG_READY_TIMEOUT_S = 40   # how long `up` waits for docker-mode Postgres to accept connections


class SupervisorError(Exception):
    """A failed lifecycle action (a daemon died on launch, external infra unreachable, missing
    creds, docker not available). Operational failure, exit code 1."""

    exit_code = 1


class Supervisor:
    """Local process + infra lifecycle. Construct with the resolved paths/coordinates (the facade
    builds it from :class:`ConsoleConfig`), then call :meth:`up` / :meth:`down` / :meth:`status` /
    :meth:`reset`. Paths default to absolute locations anchored under the project root (see
    ``settings.BS_PROJECT_ROOT``), so the lifecycle verbs operate on the repo's ``.dev/`` / ``edge/``
    / compose file / material store from **any** working directory — not only from inside the
    checkout — while an explicit override (env var / flag) still wins."""

    def __init__(
        self, *,
        dev_dir: str,
        edge_dir: str,
        edge_bin: str,
        python_exe: str,
        infra_mode: str,
        daemons_mode: str,
        config_path: str | None,
        compose_env_file: str,
        compose_file: str,
        registry_root: str,
        artifacts_root: str,
        schema: str,
        brain_keydir: str,
        default_brain_keydir: str,
        nats_url: str,
        nats_user: str | None,
        nats_pass: str | None,
        nats_stream: str,
        edge_id: str,
        edge_dns_addr: str,
        edge_dns_zones: str,
        edge_https_addr: str,
        edge_co_located: bool = True,
    ) -> None:
        self.dev_dir = dev_dir
        self.edge_dir = edge_dir
        self.edge_bin = edge_bin
        self.python_exe = python_exe
        self.infra_mode = infra_mode
        self.daemons_mode = daemons_mode
        self.config_path = config_path
        self.compose_env_file = compose_env_file
        self.compose_file = compose_file
        self.registry_root = registry_root
        self.artifacts_root = artifacts_root
        self.schema = schema
        self.brain_keydir = brain_keydir
        # The configured DEFAULT keydir (``settings.BRAIN_KEYDIR``), passed in so `reset` can tell
        # whether `brain_keydir` is the default location it owns (safe to rmtree wholesale) or a
        # custom `--brain-keydir` the operator pointed elsewhere (only the file is removed). Passed
        # rather than read from settings so tests can sandbox it.
        self.default_brain_keydir = default_brain_keydir
        self.nats_url = nats_url
        self.nats_user = nats_user
        self.nats_pass = nats_pass
        self.nats_stream = nats_stream
        self.edge_id = edge_id
        self.edge_dns_addr = edge_dns_addr
        self.edge_dns_zones = edge_dns_zones
        self.edge_https_addr = edge_https_addr
        self.edge_co_located = edge_co_located

    def _managed_daemons(self) -> tuple[str, ...]:
        """The daemon set this host is *configured* to own, independent of what happens to sit
        on disk under ``.dev/`` — mirrors ``ConsoleService._up_targets``'s co-located/edge-separate
        split so ``down``/``status``/``reset`` never act on a daemon this host was never meant to
        run (e.g. a stale ``.dev/brain.*`` left over from an earlier co-located run, once the host
        is reconfigured with ``--edge-separate``). There is no persistent equivalent of `up
        --edge-only` today (it's a per-invocation bring-up choice, not a host identity), so an
        edge-only host still reports/manages a `brain` entry if one happens to exist on disk."""
        if not self.edge_co_located:
            return (BRAIN,)
        return KNOWN_DAEMONS

    # ── public verbs ────────────────────────────────────────────────────────────

    def up(self, *, targets: tuple[str, ...], infra: bool, rebuild_edge: bool,
           infra_only: bool = False) -> UpResult:
        """Bring up the requested ``targets`` (a subset of ``KNOWN_DAEMONS``). In docker mode this
        first drives ``docker compose`` for the infra it manages; in external mode it verifies the
        operator's Postgres/NATS are reachable and starts nothing if they are not. ``infra_only``
        brings up (docker) / verifies (external) Postgres + NATS and starts no daemons — the
        lightweight path for the unit suites, which only need a reachable database."""
        infra_notes: list[str] = []
        env = self._resolve_config_env(
            want_postgres=infra_only or BRAIN in targets, notes=infra_notes)

        # Infra: relevant when we run a Postgres-backed daemon (the brain) on this host, or when the
        # caller asked for infra only (bring up the DB with no daemons).
        needs_infra = infra and (infra_only or BRAIN in targets)
        if needs_infra:
            if self.infra_mode == "external":
                infra_notes.extend(self._verify_external(env))
            else:
                infra_notes.extend(self._compose_up(env))
        elif infra and EDGE in targets and BRAIN not in targets:
            infra_notes.append("edge-only: no infra managed here (the edge needs only NATS)")

        if infra_only:
            # infra_notes already reports what happened per mode (compose brought it up, or
            # external verified reachability); this note only states that no daemons were started.
            return UpResult(
                mode=self.infra_mode, infra=infra_notes, daemons=[],
                notes=["infra-only: no daemons started "
                       "(run `blacksea up` to also start the edge + brain)"])

        # Supervised: systemd/containers own the daemons — `up` is a health signal, starts nothing.
        if self.daemons_mode == "supervised":
            return UpResult(
                mode=self.infra_mode, infra=infra_notes, daemons=[],
                notes=["BS_DAEMONS=supervised — Blacksea started no app processes "
                       "(systemd/containers own them); run `blacksea status` to check health"])

        daemons: list[DaemonStatus] = []
        if EDGE in targets:
            self._ensure_edge_binary(rebuild_edge, infra_notes)
            daemons.append(self._start(EDGE, [self.edge_bin], self._edge_env(env)))
        if BRAIN in targets:
            daemons.append(self._start(
                BRAIN, [self.python_exe, "-m", "blacksea.brain.pool"], self._brain_env(env)))

        return UpResult(
            mode=self.infra_mode, infra=infra_notes, daemons=daemons,
            notes=self._up_notes(targets))

    def down(self, *, infra: bool) -> DownResult:
        """Stop every daemon this host started (any ``.dev/<name>`` present). ``infra`` additionally
        runs ``docker compose down`` in docker mode (a no-op in external mode)."""
        results = [self._stop(name) for name in self._managed_daemons() if self._has_state(name)]
        actually_stopped = [d for d in results if d.action == "stopped"]
        infra_stopped = False
        notes: list[str] = []
        if not actually_stopped:
            notes.append(f"no dev daemons were running (nothing under {self.dev_dir}/)")
        if infra:
            if self.infra_mode == "external":
                notes.append("BS_INFRA=external — Blacksea does not manage your Postgres/NATS "
                             "(nothing to stop)")
            else:
                self._compose_down()
                infra_stopped = True
                notes.append("stopped Postgres + NATS containers (data volume preserved)")
        elif self.infra_mode != "external":
            notes.append("infra containers left running — `blacksea down --infra` also stops them")
        return DownResult(daemons=results, infra_stopped=infra_stopped, notes=notes)

    def status(self) -> list[DaemonStatus]:
        """The daemon-level view (``edge``/``brain`` PIDs) — complements ``blacksea status``'s
        infra-health pane. Reports only daemons this host owns and has state for."""
        out: list[DaemonStatus] = []
        for name in self._managed_daemons():
            if not self._has_state(name):
                continue
            running, pid = self._is_running(name)
            out.append(DaemonStatus(
                name=name, running=running, pid=pid, log_path=self._logfile(name),
                action="", detail="running" if running else "not running (stale pidfile)"))
        return out

    def log_files(self) -> list[str]:
        """Existing ``.dev/*.log`` files (newest daemons first) for ``blacksea logs`` to tail."""
        return [self._logfile(n) for n in self._managed_daemons() if os.path.exists(self._logfile(n))]

    def reset(self, conn: "psycopg.Connection | None", *, purge_nats: bool = True) -> ResetResult:
        """Wipe all test-generated state (records, brain_health, the control-plane catalog, the
        material store, the brain key directory, the NATS backlog) WITHOUT touching creds or the
        infra containers — the port of ``scripts/reset-state.sh``. Stops the dev daemons first so
        nothing re-creates state mid-wipe. ``conn`` is the facade's Postgres connection (``None``
        → skip the DB steps)."""
        cleared: list[str] = []
        skipped: list[str] = []

        stopped_names = [
            name for name in self._managed_daemons()
            if self._has_state(name) and self._stop(name).action == "stopped"
        ]
        if stopped_names:
            cleared.append(f"stopped dev daemons ({', '.join(stopped_names)})")
        else:
            skipped.append("no dev daemons were running")

        # Two independent statements, each reported on its own outcome: a TRUNCATE that
        # succeeds is never hidden behind a later DROP SCHEMA failure (or vice versa) — the
        # connection is autocommit, so a successful TRUNCATE is already permanent regardless
        # of what happens next.
        if conn is not None:
            try:
                with conn.cursor() as cur:
                    cur.execute("TRUNCATE records, brain_health")
                cleared.append("truncated records + brain_health")
            except psycopg.Error as exc:
                skipped.append(f"TRUNCATE records/brain_health failed ({exc.__class__.__name__}) — skipped")
            try:
                schema_ident = sql.Identifier(validate_schema(self.schema))
                with conn.cursor() as cur:
                    cur.execute(sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(schema_ident))
                cleared.append(f"dropped the {self.schema!r} catalog schema")
            except (psycopg.Error, ValueError) as exc:
                skipped.append(
                    f"dropping the {self.schema!r} catalog schema failed "
                    f"({exc.__class__.__name__}) — skipped")
        else:
            skipped.append("Postgres unreachable — records/brain_health/catalog not wiped")

        if purge_nats:
            note = self._purge_nats()
            (cleared if note.startswith("purged") else skipped).append(note)

        # Material store + brain key directory (per-instance test state). Keep the write-once creds
        # in config/blacksea.env. Remove the keydir file, and rmtree its parent ONLY when `brain_keydir`
        # is the configured DEFAULT (`self.default_brain_keydir`) — the location `reset` owns and may
        # clear wholesale. A custom `--brain-keydir` the operator pointed elsewhere (even at a dir that
        # happens to be named `secrets/keys`) has only its own file removed; its sibling files are never
        # bulk-deleted. Compared via `abspath` so equal paths written differently still match.
        removed = self._rmtree(self.registry_root)
        if os.path.exists(self.brain_keydir):
            os.remove(self.brain_keydir)
            removed = True
        keydir_parent = os.path.dirname(self.brain_keydir)
        is_default_keydir = os.path.abspath(self.brain_keydir) == os.path.abspath(self.default_brain_keydir)
        if keydir_parent and is_default_keydir:
            removed = self._rmtree(keydir_parent) or removed
        for stale in ("brain_keydir.json", "keydir.json", "brain_keydir.json.seq",
                      "snapshot.json", "snapshot.json.seq"):
            if os.path.exists(stale):
                os.remove(stale)
        cleared.append(f"wiped the material store ({self.registry_root}/) + the brain key directory"
                       if removed else "material store / key directory already clean")

        return ResetResult(
            cleared=cleared, skipped=skipped,
            notes=["creds (config/blacksea.env) + infra containers untouched — "
                   "`blacksea up` again for a clean stack"])

    # ── config resolution ────────────────────────────────────────────────────────

    def _resolve_config_env(
        self, *, want_postgres: bool, notes: list[str] | None = None
    ) -> dict[str, str]:
        """Return the backing-service coordinates the child daemons need, resolved from the ONE
        config file. In docker mode a *missing* config is auto-generated (preserving the old
        ``blacksea up`` zero-friction bootstrap); in external mode a missing config is an error — its
        creds can only come from the operator (``blacksea init --external``). Neither applies when
        no Postgres-backed daemon is being brought up on this host (``want_postgres=False``, e.g.
        ``up --edge-only``): the edge needs only NATS coordinates, which can come from the ambient
        env / ``--nats`` alone, so a missing config file is not fatal and nothing is generated for
        it — a fresh edge-only host in external mode is not forced through a Postgres-credential
        ``blacksea init --external`` flow it will never use."""
        # config_path is None on a fresh checkout (no file existed at settings-import time) — resolve
        # it to the default so an auto-generated docker config is actually read back below.
        config_path = self.config_path or envload.anchored(envload.CONFIG_RELPATH)
        if not os.path.exists(config_path):
            if not want_postgres:
                return {k: v for k, v in os.environ.items() if k in _PASSTHROUGH}
            if self.infra_mode == "external":
                raise SupervisorError(
                    "no config/blacksea.env — external infra needs one you provide. "
                    "Run `blacksea init --external` first.")
            self._bootstrap_docker_config(config_path, notes)
        # Re-read the file directly (it may have just been generated), then layer the backing-service
        # keys from os.environ on top so an ambient override (an explicit POSTGRES_DSN=… etc.) wins.
        env = envload.parse_env_file(config_path)
        env.update({k: v for k, v in os.environ.items() if k in _PASSTHROUGH})
        dsn = os.environ.get("POSTGRES_DSN") or env.get("POSTGRES_DSN") or envload.dsn_from_coords(env)
        if dsn:
            env["POSTGRES_DSN"] = dsn
        elif want_postgres:
            raise SupervisorError(
                "no Postgres DSN resolvable from config/blacksea.env — run `make init`")
        return env

    def _bootstrap_docker_config(self, path: str, notes: list[str] | None = None) -> None:
        """Generate a docker-mode config at ``path`` when none exists (the old ``blacksea up``
        behavior). Imported lazily so a missing config never pulls the init writer into a plain
        ``down``/``status``. Surfaces the init writer's warnings (⚠) into ``notes`` so the
        credential-drift warning — a fresh password minted here while an old ``pg_data`` volume with a
        different password lingers — actually reaches the operator instead of being swallowed."""
        from .lifecycle import Initializer  # local import: keep init writer off the common path
        result = Initializer(path).init_docker()
        if notes is not None:
            notes.append(f"generated {path} (docker mode)")
            notes.extend(n for n in result.notes if n.startswith("⚠"))

    # ── infra: docker mode ────────────────────────────────────────────────────────

    def _compose(self, *args: str) -> list[str]:
        # `-f` makes the compose file resolve from any CWD (anchored under the project root), rather
        # than relying on `docker compose`'s own walk-up-from-CWD lookup — the reason `up` used to
        # only work from inside the checkout.
        return ["docker", "compose", "-f", self.compose_file,
                "--env-file", self.compose_env_file, *args]

    def _compose_up(self, env: dict[str, str]) -> list[str]:
        """``docker compose up -d`` for Postgres + NATS, then block until Postgres accepts
        connections (so the brain doesn't race a not-yet-ready DB)."""
        try:
            subprocess.run(self._compose("up", "-d"), check=True)  # noqa: S603 — fixed argv
        except FileNotFoundError as exc:
            raise SupervisorError("`docker` not found — install Docker or use BS_INFRA=external") from exc
        except subprocess.CalledProcessError as exc:
            raise SupervisorError(f"`docker compose up` failed (exit {exc.returncode})") from exc
        user = env.get("POSTGRES_USER", envload.DEV_USER)
        db = env.get("POSTGRES_DB", envload.DEV_DB)
        self._wait_postgres(user, db)
        return [f"postgres {user}@{db} … ready", "nats … up   (docker compose)"]

    def _wait_postgres(self, user: str, db: str) -> None:
        deadline = time.monotonic() + _PG_READY_TIMEOUT_S
        probe = self._compose("exec", "-T", "postgres", "pg_isready", "-U", user, "-d", db, "-q")
        while time.monotonic() < deadline:
            if subprocess.run(probe, capture_output=True).returncode == 0:  # noqa: S603
                return
            time.sleep(1)
        raise SupervisorError(
            f"Postgres did not become ready within {_PG_READY_TIMEOUT_S}s — check `docker compose logs postgres`")

    def _compose_down(self) -> None:
        try:
            subprocess.run(self._compose("down"), check=True)  # noqa: S603
        except FileNotFoundError as exc:
            raise SupervisorError("`docker` not found — cannot stop infra containers") from exc
        except subprocess.CalledProcessError as exc:
            raise SupervisorError(f"`docker compose down` failed (exit {exc.returncode})") from exc

    # ── infra: external mode ──────────────────────────────────────────────────────

    def _verify_external(self, env: dict[str, str]) -> list[str]:
        """Fail fast + specifically if the operator's Postgres or NATS is unreachable — before
        starting any daemon (the design's 'starts nothing' guarantee)."""
        dsn = env.get("POSTGRES_DSN", "")
        try:
            with psycopg.connect(dsn, connect_timeout=3):
                pass
        except psycopg.Error as exc:
            raise SupervisorError(
                f"Postgres unreachable — {exc.__class__.__name__}. Blacksea started no daemons. "
                f"Fix connectivity or re-run `blacksea init`.") from exc
        host, port = _nats_hostport(env.get("NATS_URL", self.nats_url))
        try:
            with socket.create_connection((host, port), timeout=3):
                pass
        except OSError as exc:
            raise SupervisorError(
                f"NATS {host}:{port} unreachable — {exc.__class__.__name__}. "
                f"Blacksea started no daemons.") from exc
        return ["postgres … reachable", f"nats {host}:{port} … reachable"]

    # ── daemon process management (the dev-up.sh port) ────────────────────────────

    def _start(self, name: str, argv: list[str], env: dict[str, str]) -> DaemonStatus:
        """Idempotently start ``name`` detached under ``.dev/``. Leaves an already-running daemon
        with the identical launch fingerprint alone; restarts one whose fingerprint changed."""
        os.makedirs(self.dev_dir, exist_ok=True)
        fingerprint = _fingerprint(argv, env)
        running, pid = self._is_running(name)
        # `_pid_matches_argv` mitigates PID reuse (a crashed daemon's pidfile survives, and the
        # OS later hands that exact PID to an unrelated process before our next check) — best
        # effort (Linux /proc only; `None` on platforms without it, e.g. macOS dev hosts, in
        # which case we fall back to trusting the fingerprint match alone, as before).
        if running and pid is not None and _pid_matches_argv(pid, argv[-1]) is False:
            running = False
        if running:
            if self._read_cmd(name) == fingerprint:
                return DaemonStatus(name, True, pid, self._logfile(name), "unchanged",
                                    "already running, same config")
            self._stop(name)
            action = "restarted"
        else:
            action = "started"
            self._clear_pid(name)

        child_env = dict(os.environ)
        child_env.update(env)
        logfile = self._logfile(name)
        # "wb" (not "ab"): every fresh spawn gets a clean log, matching the old
        # `nohup … >"$logfile" 2>&1 &` (dev-up.sh), which truncated on every launch — an
        # append-mode log would grow unbounded across restarts and could show a crash
        # diagnostic (`_tail_file` below) stale lines from a previous incarnation.
        with open(logfile, "wb") as log:
            # start_new_session detaches the child into its own session/pgroup so it outlives this
            # (exiting) CLI — the nohup+setsid the old shell supervisor got from `nohup … &`.
            proc = subprocess.Popen(  # noqa: S603 — fixed argv (edge binary / `python -m …`), no shell
                argv, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                start_new_session=True, env=child_env)
        self._write_pid(name, proc.pid)
        self._write_cmd(name, fingerprint)

        # Catch a daemon that dies on launch. Poll the Popen handle (not os.kill): a just-exited
        # child of THIS process is an un-reaped zombie that os.kill(pid, 0) still reports as alive —
        # proc.poll() both detects the exit and reaps it. (Once `up` exits, the surviving daemons
        # reparent to init, which reaps them, so later `down`/`status` os.kill checks are correct.)
        time.sleep(_START_SETTLE_S)
        if proc.poll() is not None:
            self._clear_pid(name)
            tail = _tail_file(logfile, 20)
            raise SupervisorError(
                f"{name} exited immediately (code {proc.returncode}) — last lines of {logfile}:\n{tail}")
        return DaemonStatus(name, True, proc.pid, logfile, action,
                            f"{action} (pid {proc.pid})")

    def _stop(self, name: str) -> DaemonStatus:
        running, pid = self._is_running(name)
        logfile = self._logfile(name)
        if not running or pid is None:
            self._clear_pid(name)
            return DaemonStatus(name, False, None, logfile, "not-running", "not running")
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            self._clear_pid(name)
            return DaemonStatus(name, False, None, logfile, "not-running", "already gone")
        except PermissionError:
            # A stale pidfile reused by a process we don't own — leave the pidfile in place
            # (it may still be legitimately alive, just not ours to kill) and report rather
            # than crash the rest of down()/reset()'s later steps (the old shell scripts
            # wrapped every kill in `|| true` for exactly this reason).
            return DaemonStatus(name, True, pid, logfile, "not-stopped",
                                f"cannot stop pid {pid} (permission denied)")
        if not _wait_dead(pid, time.monotonic() + _STOP_GRACE_S):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(pid, signal.SIGKILL)
            _wait_dead(pid, time.monotonic() + 1.0)
        self._clear_pid(name)
        return DaemonStatus(name, False, None, logfile, "stopped", f"stopped (pid {pid})")

    # ── edge build ────────────────────────────────────────────────────────────────

    def _ensure_edge_binary(self, rebuild: bool, notes: list[str]) -> None:
        """Ensure a runnable edge binary exists. Mirrors ``blacksea up``'s ``build-edge`` prereq:
        rebuild via ``go build`` (fast — Go caches) so a bare ``blacksea up`` also picks up edge
        source changes. Falls back to an existing binary if ``go`` is missing / the build fails;
        errors only when there is nothing runnable at all."""
        have = os.path.exists(self.edge_bin)
        if not rebuild and have:
            return
        try:
            subprocess.run(  # noqa: S603 — fixed argv
                ["go", "build", "-o", os.path.join("bin", "edge"), "."],
                cwd=self.edge_dir, check=True)
            notes.append("built the edge binary (go build)")
            return
        except FileNotFoundError:
            if have:
                notes.append("`go` not found — using the existing edge binary (not rebuilt)")
                return
            raise SupervisorError(
                f"no edge binary at {self.edge_bin} and `go` is not installed — "
                f"run `make build-edge` on a host with Go, or install Go") from None
        except subprocess.CalledProcessError as exc:
            if have:
                notes.append(f"edge rebuild failed (exit {exc.returncode}) — using the existing binary")
                return
            raise SupervisorError(f"`go build` of the edge failed (exit {exc.returncode})") from exc

    # ── child environments (what dev-up.sh handed each process) ───────────────────

    def _edge_env(self, env: dict[str, str]) -> dict[str, str]:
        """The Go edge's launch env. It holds no key material and reaches only NATS, so it carries
        just its id, the NATS coordinates (+ optional TLS knobs for a cross-network hop), and its
        listen addresses."""
        out = {
            "EDGE_ID": self.edge_id,
            "NATS_URL": env.get("NATS_URL", self.nats_url),
            "NATS_STREAM": env.get("NATS_STREAM", self.nats_stream),
            "DNS_ADDR": self.edge_dns_addr,
            "DNS_ZONES": self.edge_dns_zones,
            "HTTPS_ADDR": self.edge_https_addr,
        }
        _copy_if(out, env, "NATS_USER", self.nats_user)
        _copy_if(out, env, "NATS_PASS", self.nats_pass)
        # TLS for the edge↔NATS hop when the edge runs on a separate/untrusted network — passed
        # through when present (the edge honors a tls:// URL against these; see edge/context.md).
        for key in ("NATS_CA", "NATS_TLS_CERT", "NATS_TLS_KEY"):
            _copy_if(out, env, key, env.get(key))
        return out

    def _brain_env(self, env: dict[str, str]) -> dict[str, str]:
        """The brain's launch env: the DSN + NATS coordinates + the key-directory / material paths.
        ``BS_BRAIN_KEYDIR_POLL_S`` is passed through from the ambient env (so ``blacksea up`` with
        BS_BRAIN_KEYDIR_POLL_S=1 in the env still tightens the hot-swap poll for the e2e harness)."""
        out = {
            "POSTGRES_DSN": env["POSTGRES_DSN"],
            "NATS_URL": env.get("NATS_URL", self.nats_url),
            "NATS_STREAM": env.get("NATS_STREAM", self.nats_stream),
            "BS_BRAIN_KEYDIR": self.brain_keydir,
            "BS_ARTIFACTS_ROOT": self.artifacts_root,
            "BS_CP_SCHEMA": self.schema,
        }
        _copy_if(out, env, "NATS_USER", self.nats_user)
        _copy_if(out, env, "NATS_PASS", self.nats_pass)
        _copy_if(out, env, "BS_BRAIN_KEYDIR_POLL_S", os.environ.get("BS_BRAIN_KEYDIR_POLL_S"))
        return out

    # ── NATS backlog purge (reset) ────────────────────────────────────────────────

    def _purge_nats(self) -> str:
        """Best-effort purge of the ``BAITS`` JetStream backlog (reset). Imported lazily and never
        fatal — a missing broker just skips, matching ``reset-state.sh``."""
        if not self.nats_pass:
            return "NATS creds absent — stream backlog not purged"
        try:
            import asyncio

            import nats
        except ImportError:
            return "nats client unavailable — stream backlog not purged"

        async def _run() -> None:
            nc = await nats.connect(
                self.nats_url, user=self.nats_user or "", password=self.nats_pass or "",
                connect_timeout=3)
            try:
                await nc.jetstream().purge_stream(self.nats_stream)
            finally:
                await nc.drain()

        try:
            asyncio.run(_run())
            return f"purged the NATS {self.nats_stream} stream backlog"
        except Exception as exc:  # noqa: BLE001 — best-effort, like the shell version
            return f"NATS purge skipped ({exc.__class__.__name__})"

    # ── .dev/ state files ─────────────────────────────────────────────────────────

    def _pidfile(self, name: str) -> str:
        return os.path.join(self.dev_dir, f"{name}.pid")

    def _logfile(self, name: str) -> str:
        return os.path.join(self.dev_dir, f"{name}.log")

    def _cmdfile(self, name: str) -> str:
        return os.path.join(self.dev_dir, f"{name}.cmd")

    def _has_state(self, name: str) -> bool:
        return os.path.exists(self._pidfile(name)) or os.path.exists(self._logfile(name))

    def _is_running(self, name: str) -> tuple[bool, int | None]:
        pid = _read_int(self._pidfile(name))
        if pid is None:
            return False, None
        return (_pid_alive(pid), pid)

    def _write_pid(self, name: str, pid: int) -> None:
        with open(self._pidfile(name), "w", encoding="utf-8") as fh:
            fh.write(str(pid))

    def _clear_pid(self, name: str) -> None:
        with contextlib.suppress(FileNotFoundError):
            os.remove(self._pidfile(name))

    def _write_cmd(self, name: str, fingerprint: str) -> None:
        with open(self._cmdfile(name), "w", encoding="utf-8") as fh:
            fh.write(fingerprint)

    def _read_cmd(self, name: str) -> str | None:
        try:
            with open(self._cmdfile(name), encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError:
            return None

    # ── misc helpers ──────────────────────────────────────────────────────────────

    def _up_notes(self, targets: tuple[str, ...]) -> list[str]:
        notes: list[str] = []
        if EDGE in targets:
            notes.append(f"edge     DNS {self.edge_dns_addr}   HTTPS {self.edge_https_addr}")
        if EDGE not in targets and BRAIN in targets:
            notes.append("edge runs on a separate network — deploy it there (it needs only NATS); "
                         "not managed on this host")
        notes.append("observer  run on demand with `blacksea web-ui` (http://localhost:8000)")
        notes.append("next      `blacksea status` to verify health · `blacksea forge <manifest>`")
        return notes

    @staticmethod
    def _rmtree(path: str) -> bool:
        if path and os.path.isdir(path):
            shutil.rmtree(path, ignore_errors=True)
            return True
        return False


# ── module-level helpers (pure) ──────────────────────────────────────────────────

# Backing-service keys we forward from the ambient env onto the file-resolved coordinates (an
# explicit override — e.g. POSTGRES_DSN=… — still wins). The daemons also inherit the full os.environ
# (see _start), so BS_* knobs like BS_BRAIN_KEYDIR_POLL_S reach the child without being listed here.
_PASSTHROUGH = frozenset({
    "POSTGRES_DSN", "POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_DB", "POSTGRES_USER",
    "POSTGRES_PASSWORD", "NATS_URL", "NATS_USER", "NATS_PASS", "NATS_STREAM",
    "NATS_CA", "NATS_TLS_CERT", "NATS_TLS_KEY",
})


def _fingerprint(argv: list[str], env: dict[str, str]) -> str:
    """A stable hash of the launch (argv + sorted env) — a changed poll interval, DSN, or binary
    path yields a new fingerprint so :meth:`Supervisor._start` restarts rather than leaving a
    stale-config daemon (the ``dev-up.sh`` ``.cmd`` fingerprint, which folded env into ``$@``)."""
    h = hashlib.sha1()  # noqa: S324 — not security; a collision just means "same config"
    for part in argv:
        h.update(b"\x00")
        h.update(part.encode())
    for key in sorted(env):
        h.update(f"\x01{key}={env[key]}".encode())
    return h.hexdigest()


def _copy_if(dst: dict[str, str], src: dict[str, str], key: str, fallback: str | None) -> None:
    """Set ``dst[key]`` from ``src[key]`` (else ``fallback``) only when a value is present — so an
    absent NATS user/pass stays absent (anonymous NATS) rather than becoming an empty string."""
    val = src.get(key, fallback)
    if val:
        dst[key] = val


def _read_int(path: str) -> int | None:
    try:
        with open(path, encoding="utf-8") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True   # exists but owned by another user
    return True


def _wait_dead(pid: int, deadline: float) -> bool:
    """Poll until ``pid`` is dead or ``deadline`` (a ``time.monotonic()`` value) passes.

    Reaps ``pid`` via ``os.waitpid(pid, os.WNOHANG)`` when it is a child of *this* process —
    required because ``os.kill(pid, 0)`` (``_pid_alive``) reports an un-reaped zombie as still
    alive, which would otherwise make this loop always burn the full grace period for any daemon
    stopped by the same process that started it (every daemon-restart path within one CLI
    invocation, the whole of ``tests/console/test_supervisor.py``, and a future long-lived
    in-process facade caller). Falls back to ``_pid_alive`` for a ``pid`` that is *not* our child
    — the ordinary cross-invocation CLI case, where an earlier ``blacksea up`` already exited and
    the daemon has reparented to init, which reaps it for us, so ``os.kill(pid, 0)`` promptly
    reports it gone once it actually dies."""
    while True:
        try:
            reaped_pid, _ = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            if not _pid_alive(pid):
                return True
        else:
            if reaped_pid == pid:
                return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.1)


def _pid_matches_argv(pid: int, needle: str) -> bool | None:
    """Best-effort mitigation for PID reuse: after a daemon dies without going through
    :meth:`Supervisor._stop` (leaving a stale ``.pid``/``.cmd`` pair), the OS can hand that exact
    PID to an unrelated process before the next check — a bare ``os.kill(pid, 0)`` liveness check
    can't tell the difference. Reads ``/proc/<pid>/cmdline`` (Linux only) and checks whether
    ``needle`` (the daemon's own argv tail — the edge binary path, or ``blacksea.brain.pool``)
    still appears in it. Returns ``None`` (inconclusive) where ``/proc`` isn't available (e.g.
    macOS dev hosts) or the process is already gone — callers should treat ``None`` as "can't
    tell, don't second-guess the fingerprint match", not as a positive match."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            cmdline = fh.read().decode("utf-8", "replace")
    except OSError:
        return None
    if not cmdline:
        return None
    return needle in cmdline


def _tail_file(path: str, n: int) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return "".join(fh.readlines()[-n:])
    except OSError:
        return "(log unavailable)"


def _nats_hostport(url: str, default_port: int = 4222) -> tuple[str, int]:
    parts = urlsplit(url if "://" in url else f"//{url}")
    return (parts.hostname or "127.0.0.1", parts.port or default_port)
