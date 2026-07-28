"""otel_ctl.py — env-file management + unit emission. No subprocess is spawned; no
DB needed."""

from __future__ import annotations

import os
import stat

import pytest

from blacksea.console.otel_ctl import OtelConfigError, OtelControl


def _ctl(tmp_path) -> OtelControl:
    return OtelControl(
        env_path=str(tmp_path / "otel.env"),
        postgres_dsn="host=db dbname=blacksea",
        unit_path=str(tmp_path / "blacksea-otel.service"),
    )


def test_env_roundtrip_and_perms(tmp_path) -> None:
    ctl = _ctl(tmp_path)
    assert ctl.read_env() == {}                      # missing file → empty, not an error
    merged = ctl.set_values({"BS_OTEL_ENDPOINT": "http://collector:4318"})
    assert merged["BS_OTEL_ENDPOINT"] == "http://collector:4318"
    assert ctl.read_env()["BS_OTEL_ENDPOINT"] == "http://collector:4318"
    # merges, doesn't clobber
    ctl.set_values({"BS_OTEL_PROTOCOL": "grpc"})
    cfg = ctl.read_env()
    assert cfg["BS_OTEL_ENDPOINT"] == "http://collector:4318" and cfg["BS_OTEL_PROTOCOL"] == "grpc"
    # 0600 — it can carry auth headers / TLS material
    assert stat.S_IMODE(os.stat(ctl.env_path).st_mode) == 0o600


def test_unknown_key_rejected(tmp_path) -> None:
    with pytest.raises(OtelConfigError):
        _ctl(tmp_path).set_values({"NOT_A_BS_OTEL_KEY": "x"})


def test_child_env_injects_dsn_and_enables(tmp_path) -> None:
    ctl = _ctl(tmp_path)
    ctl.set_values({"BS_OTEL_ENDPOINT": "http://c:4318"})
    env = ctl.child_env()
    assert env["POSTGRES_DSN"] == "host=db dbname=blacksea"
    assert env["BS_OTEL_ENABLED"] == "1"            # defaulted on for an explicit `otel run`
    assert env["BS_OTEL_ENDPOINT"] == "http://c:4318"


def test_install_systemd_unit(tmp_path) -> None:
    ctl = _ctl(tmp_path)
    path = ctl.install_unit(flavor="systemd")
    content = open(path, encoding="utf-8").read()
    assert "EnvironmentFile=" in content
    assert "blacksea.otel_export" in content
    assert "POSTGRES_DSN=" in content               # embedded (not a BS_OTEL_* key)


def test_install_compose_snippet(tmp_path) -> None:
    ctl = _ctl(tmp_path)
    path = ctl.install_unit(flavor="compose")
    content = open(path, encoding="utf-8").read()
    assert "otel-emitter:" in content and "env_file:" in content


def test_status_component_unknown_without_unit(tmp_path) -> None:
    comp = _ctl(tmp_path).status_component()
    assert comp.name == "otel" and comp.status == "unknown"
