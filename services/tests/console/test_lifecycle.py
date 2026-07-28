"""lifecycle.py — `blacksea init` file-writing + credential carry-forward + external validation.
No DB (external validation is exercised via an unreachable target that fails fast)."""

from __future__ import annotations

import os
import stat

import pytest

from blacksea.config import envload
from blacksea.console import lifecycle
from blacksea.console.lifecycle import InitError, Initializer, _redact_dsn


def _init(tmp_path, legacy=None, volume_probe=lambda: False):
    # Default `volume_probe` to "no volume" so the suite never shells out to a real docker daemon
    # (whose actual `*pg_data` volumes would otherwise inject the drift warning). Tests that exercise
    # the warning pass their own probe.
    return Initializer(
        config_path=str(tmp_path / "config" / "blacksea.env"),
        legacy_path=legacy or str(tmp_path / "secrets" / "env"),
        volume_probe=volume_probe)


def _parse(path):
    return envload.parse_env_file(path)


# ── docker mode ─────────────────────────────────────────────────────────────────


def test_docker_generates_and_writes(tmp_path):
    res = _init(tmp_path).init_docker()
    assert res.mode == "docker" and res.created and not res.validated
    env = _parse(res.config_path)
    assert env["BS_INFRA"] == "docker"
    assert env["POSTGRES_HOST"] == "localhost" and env["POSTGRES_DB"] == "blacksea"
    assert len(env["POSTGRES_PASSWORD"]) >= 32 and len(env["NATS_PASS"]) >= 32
    assert env["POSTGRES_PASSWORD"] != env["NATS_PASS"]


def test_docker_file_is_0600(tmp_path):
    res = _init(tmp_path).init_docker()
    mode = stat.S_IMODE(os.stat(res.config_path).st_mode)
    assert mode == 0o600


def test_docker_migrates_legacy_creds(tmp_path):
    legacy = tmp_path / "secrets" / "env"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("POSTGRES_PASSWORD=legacypw\nNATS_PASS=legacynats\n", encoding="utf-8")
    res = _init(tmp_path, legacy=str(legacy)).init_docker()
    env = _parse(res.config_path)
    assert env["POSTGRES_PASSWORD"] == "legacypw" and env["NATS_PASS"] == "legacynats"
    assert any("kept existing credentials" in n for n in res.notes)
    # The legacy file is removed after migration so it can't shadow a later rotation.
    assert not legacy.exists()
    assert any("removed the legacy" in n for n in res.notes)


def test_rotation_after_migration_generates_fresh_creds(tmp_path):
    # Migrate from a legacy secrets/env, then simulate the documented rotate flow
    # (delete config + re-init): with the legacy file gone, fresh creds are generated.
    legacy = tmp_path / "secrets" / "env"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("POSTGRES_PASSWORD=legacypw\nNATS_PASS=legacynats\n", encoding="utf-8")
    mgr = _init(tmp_path, legacy=str(legacy))
    migrated = _parse(mgr.init_docker().config_path)["POSTGRES_PASSWORD"]
    assert migrated == "legacypw"
    os.remove(mgr.config_path)                       # `rm -f config/blacksea.env`
    rotated = _parse(mgr.init_docker().config_path)["POSTGRES_PASSWORD"]
    assert rotated != "legacypw"                     # rotation actually rotated


def test_docker_warns_on_fresh_creds_with_existing_volume(tmp_path):
    # No creds carried forward (fresh config) BUT a pg_data volume already exists → the minted
    # password won't match the volume's baked-in one. init still writes the file, but must warn.
    res = _init(tmp_path, volume_probe=lambda: True).init_docker()
    assert res.created
    warn = [n for n in res.notes if n.startswith("⚠") and "password authentication failed" in n]
    assert warn, res.notes


def test_docker_no_volume_warning_when_no_volume(tmp_path):
    res = _init(tmp_path, volume_probe=lambda: False).init_docker()
    assert not any("password authentication failed" in n for n in res.notes)


def test_expected_pg_volume_is_scoped_to_the_compose_project(tmp_path, monkeypatch):
    # The drift probe must target THIS stack's `<project>_pg_data`, not any `*pg_data` volume — else it
    # false-warns about an unrelated compose stack. Project = the compose file's directory basename.
    from blacksea.config import settings
    monkeypatch.delenv("COMPOSE_PROJECT_NAME", raising=False)
    monkeypatch.setattr(settings, "BS_COMPOSE_FILE", str(tmp_path / "MyProj" / "docker-compose.yml"))
    assert lifecycle._expected_pg_volume() == "myproj_pg_data"   # lowercased, dir-scoped
    monkeypatch.setenv("COMPOSE_PROJECT_NAME", "Custom Name!")
    assert lifecycle._expected_pg_volume() == "customname_pg_data"   # env override, sanitized


def test_docker_no_volume_warning_when_creds_carried_forward(tmp_path):
    # Carrying creds forward is the *safe* path (the volume expects them) — no drift warning even if a
    # volume exists.
    legacy = tmp_path / "secrets" / "env"
    legacy.parent.mkdir(parents=True)
    legacy.write_text("POSTGRES_PASSWORD=legacypw\nNATS_PASS=legacynats\n", encoding="utf-8")
    res = _init(tmp_path, legacy=str(legacy), volume_probe=lambda: True).init_docker()
    assert not any("password authentication failed" in n for n in res.notes)


def test_docker_creates_0700_config_dir(tmp_path):
    res = _init(tmp_path).init_docker()
    dir_mode = stat.S_IMODE(os.stat(os.path.dirname(res.config_path)).st_mode)
    assert dir_mode == 0o700


def test_default_location_has_no_gitignore_warning(tmp_path):
    res = _init(tmp_path).init_docker()               # config_path = .../config/blacksea.env
    assert not any(n.startswith("⚠") for n in res.notes)


def test_config_outside_config_dir_warns(tmp_path):
    # A path git does not ignore (not config/*.env) → a loud do-not-commit warning.
    outside = Initializer(config_path=str(tmp_path / "infra.env"), volume_probe=lambda: False)
    res = outside.init_docker()
    assert any("not covered by .gitignore" in n.lower() or n.startswith("⚠") for n in res.notes)


def test_docker_refuses_overwrite_without_force(tmp_path):
    mgr = _init(tmp_path)
    mgr.init_docker()
    with pytest.raises(InitError):
        mgr.init_docker()


def test_default_write_target_is_package_anchored(tmp_path, monkeypatch):
    """With no explicit ``config_path``, init writes to ``<PROJECT_ROOT>/config/blacksea.env`` — the
    same location the loader reads from — so it is correct from any CWD (not the CWD-relative path).
    Locks the read/write symmetry that closes the 'stray config with mismatched creds' footgun."""
    monkeypatch.setattr(envload, "PROJECT_ROOT", str(tmp_path / "proj"))
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)                    # run init from a dir that is NOT the project root
    res = Initializer(volume_probe=lambda: False).init_docker()
    assert res.config_path == str(tmp_path / "proj" / "config" / "blacksea.env")
    assert os.path.exists(res.config_path)
    assert not os.path.exists(elsewhere / "config" / "blacksea.env")   # NOT CWD-relative


def test_overwrite_guard_sees_anchored_config_from_any_cwd(tmp_path, monkeypatch):
    """The overwrite guard checks the anchored path, so a second init from a *different* CWD still
    refuses (instead of silently minting a fresh config with new credentials elsewhere)."""
    monkeypatch.setattr(envload, "PROJECT_ROOT", str(tmp_path / "proj"))
    Initializer(volume_probe=lambda: False).init_docker()
    monkeypatch.chdir(tmp_path)                    # move away from the root
    with pytest.raises(InitError):
        Initializer(volume_probe=lambda: False).init_docker()


def test_docker_force_keeps_existing_creds(tmp_path):
    mgr = _init(tmp_path)
    first = _parse(mgr.init_docker().config_path)["POSTGRES_PASSWORD"]
    second = _parse(mgr.init_docker(force=True).config_path)["POSTGRES_PASSWORD"]
    assert first == second   # force rewrites the file but keeps the credentials (volume stays valid)


# ── external mode ───────────────────────────────────────────────────────────────


def test_external_writes_without_validation(tmp_path):
    res = _init(tmp_path).init_external(
        postgres_dsn="host=db.internal port=5432 dbname=bs user=bs password=sekret",
        nats_url="nats://nats.internal:4222", nats_user="u", nats_pass="pw", validate=False)
    assert res.mode == "external" and not res.validated
    env = _parse(res.config_path)
    assert env["BS_INFRA"] == "external"
    assert env["POSTGRES_DSN"] == "host=db.internal port=5432 dbname=bs user=bs password=sekret"
    assert env["NATS_URL"] == "nats://nats.internal:4222"
    assert env["NATS_USER"] == "u" and env["NATS_PASS"] == "pw"
    # TLS knobs are written commented-out when unset (discoverable, inert)
    assert "NATS_CA" not in env   # only the `# NATS_CA=` comment line, not a live key
    assert "password=sekret" not in _redact_dsn(env["POSTGRES_DSN"])


def test_external_tls_written_when_given(tmp_path):
    res = _init(tmp_path).init_external(
        postgres_dsn="host=db port=5432 dbname=x user=y password=z",
        nats_url="nats://n:4222", tls_ca="/ca.pem", validate=False)
    assert _parse(res.config_path)["NATS_CA"] == "/ca.pem"


def test_external_requires_dsn_and_url(tmp_path):
    with pytest.raises(InitError):
        _init(tmp_path).init_external(postgres_dsn="", nats_url="nats://n:4222", validate=False)
    with pytest.raises(InitError):
        _init(tmp_path).init_external(postgres_dsn="host=db", nats_url="", validate=False)


def test_external_refuses_overwrite(tmp_path):
    mgr = _init(tmp_path)
    mgr.init_external(postgres_dsn="host=db", nats_url="nats://n:4222", validate=False)
    with pytest.raises(InitError):
        mgr.init_external(postgres_dsn="host=db", nats_url="nats://n:4222", validate=False)


def test_external_validation_failure_writes_nothing(tmp_path):
    mgr = _init(tmp_path)
    # Nothing listens on port 1 → Postgres connect fails fast; the file must not be created.
    with pytest.raises(InitError):
        mgr.init_external(
            postgres_dsn="host=127.0.0.1 port=1 dbname=x user=y password=z connect_timeout=1",
            nats_url="nats://127.0.0.1:1", validate=True)
    assert not os.path.exists(mgr.config_path)


def test_redact_dsn():
    assert _redact_dsn("host=db port=5432 password=secret user=me") == "host=db port=5432 user=me"
