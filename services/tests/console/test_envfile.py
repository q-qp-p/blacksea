"""envfile.py — the dev DSN fallback: dotenv parsing, DSN assembly, and resolution precedence
(--postgres > $POSTGRES_DSN > secrets/env). No DB needed."""

from __future__ import annotations

import os

from blacksea.config import settings
from blacksea.console import envfile


def _write(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


def test_read_env_file_parses_dotenv(tmp_path):
    p = tmp_path / "env"
    _write(p, "# comment\nPOSTGRES_PASSWORD=s3cret\nexport NATS_PASS='pw'\nBLANK=\n\nBAD_LINE\n")
    env = envfile.read_env_file(str(p))
    assert env["POSTGRES_PASSWORD"] == "s3cret"
    assert env["NATS_PASS"] == "pw"          # `export ` stripped, quotes stripped
    assert env["BLANK"] == ""
    assert "BAD_LINE" not in env


def test_read_env_file_missing_is_empty(tmp_path):
    assert envfile.read_env_file(str(tmp_path / "nope")) == {}


def test_dsn_full_line_wins():
    env = {"POSTGRES_DSN": "host=db dbname=x", "POSTGRES_PASSWORD": "ignored"}
    assert envfile.dsn_from_env(env) == "host=db dbname=x"


def test_dsn_assembled_from_password_with_dev_coords():
    dsn = envfile.dsn_from_env({"POSTGRES_PASSWORD": "pw"})
    assert dsn == "host=localhost port=5432 dbname=blacksea user=blacksea password=pw"


def test_dsn_assembly_honors_overrides():
    dsn = envfile.dsn_from_env(
        {"POSTGRES_PASSWORD": "pw", "POSTGRES_HOST": "db.internal", "POSTGRES_PORT": "6543"})
    assert "host=db.internal" in dsn and "port=6543" in dsn


def test_dsn_empty_without_password():
    assert envfile.dsn_from_env({"NATS_PASS": "x"}) == ""


def test_find_secrets_file_explicit(tmp_path):
    p = tmp_path / "env"
    _write(p, "POSTGRES_PASSWORD=pw\n")
    assert envfile.find_secrets_file(str(p)) == str(p)
    assert envfile.find_secrets_file(str(tmp_path / "absent")) is None


def test_find_secrets_file_searches_upward(tmp_path):
    secrets = tmp_path / "secrets"
    secrets.mkdir()
    _write(secrets / "env", "POSTGRES_PASSWORD=pw\n")
    sub = tmp_path / "a" / "b"
    sub.mkdir(parents=True)
    assert envfile.find_secrets_file(None, start=str(sub)) == str(secrets / "env")


def test_resolve_precedence_flag_wins(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "POSTGRES_DSN", "host=fromenv")
    dsn, source = envfile.resolve_postgres_dsn("host=fromflag", None, start=str(tmp_path))
    assert dsn == "host=fromflag" and source is None


def test_resolve_precedence_env_over_file(monkeypatch, tmp_path):
    (tmp_path / "secrets").mkdir()
    _write(tmp_path / "secrets" / "env", "POSTGRES_PASSWORD=pw\n")
    monkeypatch.setattr(settings, "POSTGRES_DSN", "host=fromenv")
    dsn, source = envfile.resolve_postgres_dsn(None, None, start=str(tmp_path))
    assert dsn == "host=fromenv" and source is None


def test_resolve_falls_back_to_secrets_file(monkeypatch, tmp_path):
    (tmp_path / "secrets").mkdir()
    envpath = tmp_path / "secrets" / "env"
    _write(envpath, "POSTGRES_PASSWORD=pw\n")
    monkeypatch.setattr(settings, "POSTGRES_DSN", None)
    dsn, source = envfile.resolve_postgres_dsn(None, None, start=str(tmp_path))
    assert "password=pw" in dsn and source == str(envpath)


def test_resolve_nothing(monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "POSTGRES_DSN", None)
    dsn, source = envfile.resolve_postgres_dsn(None, None, start=str(tmp_path))
    assert dsn == "" and source is None
