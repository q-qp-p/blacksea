"""settings.py — the POSTGRES_DSN resolution gate: coordinate assembly fires only when a config file
was actually loaded, so a stray ambient POSTGRES_PASSWORD does not silently build a localhost DSN.

Each test reloads ``blacksea.config.settings`` under a controlled environment. Because settings loads
the config file into ``os.environ`` at import (a side effect outside monkeypatch's tracking), each
test snapshots the FULL ``os.environ`` and restores it — then reloads settings once more — so the
shared module and process env return to the repo's real config for any later test."""

from __future__ import annotations

import importlib
import os


def _reload():
    from blacksea.config import settings
    return importlib.reload(settings)


def test_ambient_password_without_config_file_yields_no_dsn():
    # No discoverable config file (BS_CONFIG points nowhere) + an ambient POSTGRES_PASSWORD as a dev
    # might have for another project's compose. Must NOT conjure a host=localhost DSN.
    saved = dict(os.environ)
    try:
        os.environ["BS_CONFIG"] = "/no/such/blacksea.env"
        os.environ["POSTGRES_PASSWORD"] = "ambientpw"
        os.environ.pop("POSTGRES_DSN", None)
        settings = _reload()
        assert settings.BS_CONFIG_PATH is None
        assert settings.POSTGRES_DSN is None      # gated: no file → no coordinate DSN
    finally:
        os.environ.clear()
        os.environ.update(saved)
        _reload()


def test_explicit_dsn_still_wins_without_a_file():
    saved = dict(os.environ)
    try:
        os.environ["BS_CONFIG"] = "/no/such/blacksea.env"
        os.environ["POSTGRES_DSN"] = "host=explicit dbname=x"
        settings = _reload()
        assert settings.POSTGRES_DSN == "host=explicit dbname=x"
    finally:
        os.environ.clear()
        os.environ.update(saved)
        _reload()


def test_loaded_docker_file_assembles_coordinate_dsn(tmp_path):
    # A real docker-style config file present → coordinates assemble into a DSN (the normal path).
    cfg = tmp_path / "config" / "blacksea.env"
    cfg.parent.mkdir(parents=True)
    cfg.write_text(
        "BS_INFRA=docker\nPOSTGRES_HOST=localhost\nPOSTGRES_PORT=5432\n"
        "POSTGRES_DB=blacksea\nPOSTGRES_USER=blacksea\nPOSTGRES_PASSWORD=filepw\n",
        encoding="utf-8")
    saved = dict(os.environ)
    try:
        os.environ["BS_CONFIG"] = str(cfg)
        for k in ("POSTGRES_DSN", "POSTGRES_PASSWORD", "POSTGRES_HOST"):
            os.environ.pop(k, None)               # let the file's values fill via setdefault
        settings = _reload()
        assert settings.BS_CONFIG_PATH == str(cfg)
        assert settings.POSTGRES_DSN == (
            "host=localhost port=5432 dbname=blacksea user=blacksea password=filepw")
    finally:
        os.environ.clear()
        os.environ.update(saved)
        _reload()
