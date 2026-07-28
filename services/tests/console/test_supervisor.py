"""supervisor.py — the local lifecycle supervisor (blacksea up/down/logs/reset, step 3).

Exercises the process-management + reset + fingerprint logic against *real* short-lived child
processes in a tmp .dev/ (no Docker, no infra): the daemon start/stop/idempotency machinery that
replaced scripts/dev-up.sh. The docker/external `up` paths (compose, reachability) are covered by
the e2e suite (`make test-e2e`), which drives `blacksea up`.
"""

from __future__ import annotations

import os
import sys
import time

import psycopg
import pytest

from blacksea.config import envload
from blacksea.console.supervisor import (
    Supervisor,
    SupervisorError,
    _fingerprint,
    _pid_matches_argv,
)

# A harmless long-lived child and an immediately-dying one, used as stand-in daemons.
_SLEEP = [sys.executable, "-c", "import time; time.sleep(30)"]
_DIE = [sys.executable, "-c", "raise SystemExit(3)"]


def _sup(tmp_path, **over) -> Supervisor:
    kw = dict(
        dev_dir=str(tmp_path / ".dev"), edge_dir=str(tmp_path / "edge"),
        edge_bin=str(tmp_path / "edge" / "bin" / "edge"), python_exe=sys.executable,
        infra_mode="docker", daemons_mode="blacksea", config_path=str(tmp_path / "config.env"),
        compose_env_file=str(tmp_path / "config.env"),
        compose_file=str(tmp_path / "docker-compose.yml"),
        registry_root=str(tmp_path / "registry"), artifacts_root=str(tmp_path / "registry/artifacts"),
        schema="control_plane", brain_keydir=str(tmp_path / "secrets/keys/brain_keydir.json"),
        default_brain_keydir=str(tmp_path / "secrets/keys/brain_keydir.json"),  # default == brain_keydir unless overridden
        nats_url="nats://localhost:4222", nats_user="u", nats_pass="p", nats_stream="BAITS",
        edge_id="edge-test", edge_dns_addr=":15353", edge_dns_zones="cb.example.com",
        edge_https_addr=":8443")
    kw.update(over)
    return Supervisor(**kw)


# ── fingerprint ──────────────────────────────────────────────────────────────────


def test_fingerprint_is_stable_and_sensitive():
    a = _fingerprint(["x", "y"], {"K": "1"})
    assert a == _fingerprint(["x", "y"], {"K": "1"})       # deterministic
    assert a != _fingerprint(["x", "z"], {"K": "1"})       # argv change
    assert a != _fingerprint(["x", "y"], {"K": "2"})       # env change (e.g. poll interval)
    assert a != _fingerprint(["x", "y"], {})               # env removed


# ── daemon start / stop / status ──────────────────────────────────────────────────


def test_start_writes_state_and_runs(tmp_path):
    sup = _sup(tmp_path)
    st = sup._start("worker", _SLEEP, {})
    try:
        assert st.running and st.pid and st.action == "started"
        assert os.path.exists(sup._pidfile("worker"))
        assert os.path.exists(sup._logfile("worker"))
        assert sup._is_running("worker")[0]
    finally:
        sup._stop("worker")


def test_start_is_idempotent_same_config(tmp_path):
    sup = _sup(tmp_path)
    first = sup._start("worker", _SLEEP, {})
    try:
        again = sup._start("worker", _SLEEP, {})
        assert again.action == "unchanged"
        assert again.pid == first.pid            # same process, left alone
    finally:
        sup._stop("worker")


def test_start_restarts_on_config_change(tmp_path):
    sup = _sup(tmp_path)
    first = sup._start("worker", _SLEEP, {"POLL": "10"})
    try:
        changed = sup._start("worker", _SLEEP, {"POLL": "1"})
        assert changed.action == "restarted"
        assert changed.pid != first.pid          # replaced because the launch fingerprint changed
        assert not _alive(first.pid)             # the old one was stopped
    finally:
        sup._stop("worker")


def test_immediate_death_raises(tmp_path):
    sup = _sup(tmp_path)
    with pytest.raises(SupervisorError, match="exited immediately"):
        sup._start("crasher", _DIE, {})


def test_stop_clears_state(tmp_path):
    sup = _sup(tmp_path)
    sup._start("worker", _SLEEP, {})
    stopped = sup._stop("worker")
    assert not stopped.running and stopped.action == "stopped"
    assert not sup._is_running("worker")[0]
    assert not os.path.exists(sup._pidfile("worker"))   # pidfile cleared on stop


def test_status_reports_running_known_daemon(tmp_path):
    sup = _sup(tmp_path)
    sup._start("edge", _SLEEP, {})               # edge ∈ KNOWN_DAEMONS
    try:
        rows = {d.name: d for d in sup.status()}
        assert "edge" in rows and rows["edge"].running and rows["edge"].pid
    finally:
        sup._stop("edge")


def test_down_stops_known_daemons(tmp_path):
    sup = _sup(tmp_path)
    sup._start("brain", _SLEEP, {})              # a KNOWN_DAEMONS name so down/status see it
    res = sup.down(infra=False)
    names = [d.name for d in res.daemons]
    assert "brain" in names
    assert all(not d.running for d in res.daemons)
    assert not sup._is_running("brain")[0]


def test_log_files_lists_started_daemons(tmp_path):
    sup = _sup(tmp_path)
    sup._start("edge", _SLEEP, {})
    try:
        assert sup._logfile("edge") in sup.log_files()
    finally:
        sup._stop("edge")


def test_stop_reaps_same_process_child_promptly(tmp_path):
    # `_stop` on a daemon that is still a direct child of THIS process (exactly what every test
    # here does, and what an in-process restart within one CLI invocation would do) must not
    # burn the full SIGTERM grace period waiting on an unreaped zombie: os.kill(pid, 0) reports a
    # zombie as alive forever, so _wait_dead's os.waitpid(WNOHANG) reaping is load-bearing here.
    sup = _sup(tmp_path)
    sup._start("worker", _SLEEP, {})
    started = time.monotonic()
    sup._stop("worker")
    elapsed = time.monotonic() - started
    assert elapsed < 1.0, f"stop took {elapsed:.2f}s — same-process child was not reaped promptly"


def test_start_restarts_on_config_change_is_prompt(tmp_path):
    # A restart within `_start` calls `_stop` on a same-process child too — same zombie trap.
    sup = _sup(tmp_path)
    sup._start("worker", _SLEEP, {"POLL": "10"})
    try:
        started = time.monotonic()
        sup._start("worker", _SLEEP, {"POLL": "1"})
        elapsed = time.monotonic() - started
        assert elapsed < 1.0, f"restart took {elapsed:.2f}s — stale child was not reaped promptly"
    finally:
        sup._stop("worker")


def test_stop_permission_error_is_reported_not_raised(tmp_path, monkeypatch):
    # A stale pidfile whose PID has been reused by another user's process must not crash
    # down()/reset() — the old shell scripts wrapped every `kill` in `|| true` for this reason.
    import signal as signal_mod

    sup = _sup(tmp_path)
    os.makedirs(sup.dev_dir, exist_ok=True)
    with open(sup._pidfile("worker"), "w", encoding="utf-8") as fh:
        fh.write(str(os.getpid()))   # any real, alive pid stands in for "owned by someone else"

    def _raise_permission(pid, sig):
        if sig == signal_mod.SIGTERM:
            raise PermissionError("not yours")
        return None

    monkeypatch.setattr(os, "kill", _raise_permission)
    status = sup._stop("worker")
    assert status.action == "not-stopped"
    assert os.path.exists(sup._pidfile("worker"))   # left in place — still (maybe) alive


# ── PID-reuse mitigation ─────────────────────────────────────────────────────────


@pytest.mark.skipif(sys.platform != "linux", reason="/proc-based check, Linux only")
def test_pid_matches_argv_detects_mismatch_and_missing_pid():
    assert _pid_matches_argv(os.getpid(), "definitely-not-in-our-cmdline-xyz") is False
    assert _pid_matches_argv(999_999_999, "anything") is None   # no such pid → inconclusive


@pytest.mark.skipif(sys.platform == "linux", reason="only exercises the non-Linux fallback")
def test_pid_matches_argv_is_inconclusive_without_proc():
    assert _pid_matches_argv(os.getpid(), "anything") is None


# ── host-specific daemon scoping (edge_co_located) ─────────────────────────────────


def test_down_status_reset_ignore_daemons_this_host_does_not_own(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sup = _sup(tmp_path, edge_co_located=False)   # a brain host configured `--edge-separate`
    # A stale edge triple left over from an earlier co-located run on this same host.
    os.makedirs(sup.dev_dir, exist_ok=True)
    with open(sup._pidfile("edge"), "w", encoding="utf-8") as fh:
        fh.write("999999999")   # not a real pid
    open(sup._logfile("edge"), "w").close()

    assert {d.name for d in sup.status()} == set()   # edge isn't this host's to report as running

    sup._start("brain", _SLEEP, {})
    try:
        down_res = sup.down(infra=False)
        assert {d.name for d in down_res.daemons} == {"brain"}
        assert os.path.exists(sup._pidfile("edge"))   # untouched
    finally:
        sup._stop("brain")

    reset_res = sup.reset(None, purge_nats=False)
    assert any("brain" in c and "edge" not in c for c in reset_res.cleared if "stopped dev daemons" in c) \
        or any("no dev daemons were running" in s for s in reset_res.skipped)
    assert os.path.exists(sup._pidfile("edge"))   # reset() never touched the un-owned edge state


# ── reset (on-disk parts; conn=None skips the DB steps) ────────────────────────────


# ── config resolution ──────────────────────────────────────────────────────────


def test_docker_config_autobootstraps_on_fresh_checkout(tmp_path, monkeypatch):
    # config_path=None (no file existed at settings-import) + docker mode: `up` must auto-generate
    # config/blacksea.env and read it back with a usable DSN — else a fresh checkout can't start.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(envload, "PROJECT_ROOT", str(tmp_path))  # anchor the fallback to the sandbox
    sup = _sup(tmp_path, config_path=None)
    env = sup._resolve_config_env(want_postgres=True)
    assert os.path.exists("config/blacksea.env")         # auto-generated at the default location
    assert env["POSTGRES_DSN"].startswith("host=localhost")   # and read back (not an empty env)


def test_autobootstrap_surfaces_credential_drift_warning(tmp_path, monkeypatch):
    # On the `up` auto-generate path, a fresh password is minted; if a pg_data volume already exists
    # (different password baked in) the drift warning must reach the operator via `notes`, not be
    # swallowed inside _bootstrap_docker_config.
    from blacksea.console import lifecycle
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(envload, "PROJECT_ROOT", str(tmp_path))
    monkeypatch.setattr(lifecycle, "_docker_pg_volume_present", lambda: True)  # volume exists
    sup = _sup(tmp_path, config_path=None)
    notes: list[str] = []
    sup._resolve_config_env(want_postgres=True, notes=notes)
    assert any(n.startswith("⚠") and "password authentication failed" in n for n in notes), notes


def test_external_missing_config_errors(tmp_path):
    sup = _sup(tmp_path, infra_mode="external", config_path=str(tmp_path / "nope.env"))
    with pytest.raises(SupervisorError, match="external infra needs one"):
        sup._resolve_config_env(want_postgres=True)


# Postgres coordinate env vars the surrounding `make test` run may already export (for the
# sibling brain/control_plane suites) — cleared for the two tests below so "no Postgres was
# resolved" is asserted against a clean slate, not whatever happens to be ambient.
_POSTGRES_ENV_KEYS = (
    "POSTGRES_DSN", "POSTGRES_HOST", "POSTGRES_PORT", "POSTGRES_DB",
    "POSTGRES_USER", "POSTGRES_PASSWORD",
)


def test_no_postgres_needed_skips_missing_config_in_docker_mode(tmp_path, monkeypatch):
    # `up --edge-only`: no Postgres-backed daemon on this host, so a missing config file must
    # not trigger the docker-mode auto-bootstrap (which would write bogus localhost Postgres
    # creds nobody asked for on a dedicated edge host).
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(envload, "PROJECT_ROOT", str(tmp_path))  # anchor the fallback to the sandbox
    for key in _POSTGRES_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    sup = _sup(tmp_path, config_path=None)
    env = sup._resolve_config_env(want_postgres=False)
    assert not os.path.exists("config/blacksea.env")
    assert "POSTGRES_DSN" not in env


def test_no_postgres_needed_skips_missing_config_in_external_mode(tmp_path, monkeypatch):
    # `up --edge-only` on a dedicated external-mode edge host with no local config file at all
    # must NOT raise — the module's own contract promises edge-only needs "no Postgres".
    for key in _POSTGRES_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    sup = _sup(tmp_path, infra_mode="external", config_path=str(tmp_path / "nope.env"))
    env = sup._resolve_config_env(want_postgres=False)   # must not raise
    assert "POSTGRES_DSN" not in env


# ── reset ──────────────────────────────────────────────────────────────────────


def test_reset_wipes_material_and_default_keydir(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)                  # sandbox the CWD-relative stale-file cleanup
    sup = _sup(tmp_path)                          # default brain_keydir is under secrets/keys/
    os.makedirs(sup.registry_root, exist_ok=True)
    os.makedirs(os.path.dirname(sup.brain_keydir), exist_ok=True)
    open(sup.brain_keydir, "w").close()
    sibling = os.path.join(os.path.dirname(sup.brain_keydir), "other-key.json")
    open(sibling, "w").close()
    res = sup.reset(None, purge_nats=False)      # no DB, no NATS
    assert not os.path.exists(sup.registry_root)
    assert not os.path.exists(sup.brain_keydir)
    assert not os.path.exists(sibling)            # the default keys/ dir is rmtree'd wholesale
    assert any("material store" in c for c in res.cleared)
    assert any("Postgres unreachable" in s for s in res.skipped)   # conn=None recorded


def test_reset_does_not_rmtree_a_non_default_keys_directory(tmp_path, monkeypatch):
    # A `--brain-keydir` whose parent merely happens to be *named* "keys" (not the documented
    # default secrets/keys/) must have only its own file removed — the surrounding directory,
    # which may hold unrelated files, is never bulk-deleted.
    monkeypatch.chdir(tmp_path)
    custom_keydir = tmp_path / "myproject" / "keys" / "brain_keydir.json"
    os.makedirs(custom_keydir.parent, exist_ok=True)
    open(custom_keydir, "w").close()
    unrelated = custom_keydir.parent / "unrelated.pem"
    unrelated.write_text("do not touch")
    sup = _sup(tmp_path, brain_keydir=str(custom_keydir))
    sup.reset(None, purge_nats=False)
    assert not os.path.exists(custom_keydir)      # the keydir file itself is still removed
    assert os.path.exists(unrelated)               # the unrelated "keys" dir is left alone
    assert os.path.exists(custom_keydir.parent)


def test_reset_does_not_rmtree_a_custom_secrets_keys_directory(tmp_path, monkeypatch):
    # A custom `--brain-keydir` pointing at a DIFFERENT `.../secrets/keys/` dir (not the configured
    # default) must NOT be bulk-deleted — reset only owns the default location. Guards against the
    # old suffix-match guard, which rmtree'd any parent ending in `secrets/keys` and would have wiped
    # this dir's siblings. `default_brain_keydir` stays at the `_sup` helper's default (a different
    # path), so brain_keydir != default → only the file is removed.
    monkeypatch.chdir(tmp_path)                    # sandbox the CWD-relative stale-file cleanup
    custom_keydir = tmp_path / "elsewhere" / "secrets" / "keys" / "brain_keydir.json"
    os.makedirs(custom_keydir.parent, exist_ok=True)
    open(custom_keydir, "w").close()
    unrelated = custom_keydir.parent / "operator-owned.pem"
    unrelated.write_text("do not touch")
    sup = _sup(tmp_path, brain_keydir=str(custom_keydir))
    sup.reset(None, purge_nats=False)
    assert not os.path.exists(custom_keydir)      # the keydir file itself is still removed
    assert os.path.exists(unrelated)               # the custom secrets/keys/ dir is NOT bulk-deleted
    assert os.path.exists(custom_keydir.parent)


class _FakeCursor:
    def __init__(self, conn: "_FakeConn") -> None:
        self._conn = conn

    def __enter__(self) -> "_FakeCursor":
        return self

    def __exit__(self, *exc: object) -> bool:
        return False

    def execute(self, query: object, *args: object) -> None:
        text = str(query)
        self._conn.executed.append(text)
        for marker in self._conn.fail_on:
            if marker in text:
                raise psycopg.OperationalError(f"boom: {marker}")


class _FakeConn:
    """A minimal stand-in for a psycopg connection: records every statement text and can be
    told to fail whenever a given substring (e.g. "TRUNCATE" / "DROP SCHEMA") is executed."""

    def __init__(self, fail_on: tuple[str, ...] = ()) -> None:
        self.fail_on = fail_on
        self.executed: list[str] = []

    def cursor(self) -> _FakeCursor:
        return _FakeCursor(self)


def test_reset_db_wipe_truncates_records_and_brain_health_and_drops_schema(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sup = _sup(tmp_path)
    conn = _FakeConn()
    res = sup.reset(conn, purge_nats=False)
    assert any("truncated records + brain_health" in c for c in res.cleared)
    assert any(f"dropped the {sup.schema!r} catalog schema" in c for c in res.cleared)
    assert any("TRUNCATE records, brain_health" in q for q in conn.executed)
    assert any("DROP SCHEMA" in q for q in conn.executed)


def test_reset_truncate_success_is_not_hidden_by_a_later_schema_drop_failure(tmp_path, monkeypatch):
    # Regression: TRUNCATE and DROP SCHEMA used to share one try/except, so a DROP SCHEMA
    # failure (or `records` not existing yet) reported the *whole* DB step as "skipped" even
    # though TRUNCATE had already irreversibly committed (the connection is autocommit).
    monkeypatch.chdir(tmp_path)
    sup = _sup(tmp_path)
    conn = _FakeConn(fail_on=("DROP SCHEMA",))
    res = sup.reset(conn, purge_nats=False)
    assert any("truncated records + brain_health" in c for c in res.cleared)
    assert any("dropping the" in s and "failed" in s for s in res.skipped)


def test_reset_invalid_schema_name_is_reported_not_raised(tmp_path, monkeypatch):
    # The schema name now goes through psycopg.sql.Identifier(validate_schema(...)) instead of
    # a raw f-string — an invalid identifier must be a reported failure, not an unhandled
    # ValueError or malformed SQL sent to the server.
    monkeypatch.chdir(tmp_path)
    sup = _sup(tmp_path, schema="not a valid identifier; drop table records")
    conn = _FakeConn()
    res = sup.reset(conn, purge_nats=False)
    assert any("truncated records + brain_health" in c for c in res.cleared)
    assert any("dropping the" in s and "failed" in s for s in res.skipped)
    assert not any("DROP SCHEMA" in q for q in conn.executed)   # never reached the server


def test_reset_reports_stopped_daemons_by_name_and_never_claims_a_stop_that_did_not_happen(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    sup = _sup(tmp_path)
    # Nothing running: reset() must not unconditionally claim it stopped anything.
    res = sup.reset(None, purge_nats=False)
    assert not any("stopped dev daemons" in c for c in res.cleared)
    assert any("no dev daemons were running" in s for s in res.skipped)

    sup2 = _sup(tmp_path)
    sup2._start("brain", _SLEEP, {})
    res2 = sup2.reset(None, purge_nats=False)
    assert any(c == "stopped dev daemons (brain)" for c in res2.cleared)


# ── helpers ────────────────────────────────────────────────────────────────────────


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    return True
