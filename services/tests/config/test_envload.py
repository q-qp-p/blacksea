"""envload.py — the unified config-file loader: dotenv parsing, DSN-from-coordinates, file
discovery (config/blacksea.env preferred over the legacy secrets/env), and environ population with
env-wins precedence. No DB, no third-party deps."""

from __future__ import annotations

import os

from blacksea.config import envload


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# ── parse_env_file ──────────────────────────────────────────────────────────────


def test_parse_env_file_dotenv(tmp_path):
    p = tmp_path / "blacksea.env"
    _write(p, "# comment\nBS_INFRA=docker\nexport NATS_PASS='pw'\nBLANK=\n\nBAD_LINE\n")
    env = envload.parse_env_file(str(p))
    assert env["BS_INFRA"] == "docker"
    assert env["NATS_PASS"] == "pw"          # `export ` + quotes stripped
    assert env["BLANK"] == ""
    assert "BAD_LINE" not in env


def test_parse_env_file_missing_is_empty(tmp_path):
    assert envload.parse_env_file(str(tmp_path / "nope")) == {}


def test_parse_preserves_dsn_spaces(tmp_path):
    p = tmp_path / "blacksea.env"
    _write(p, "POSTGRES_DSN=host=db port=5432 dbname=x user=y password=z\n")
    assert envload.parse_env_file(str(p))["POSTGRES_DSN"] == "host=db port=5432 dbname=x user=y password=z"


# ── dsn_from_coords ─────────────────────────────────────────────────────────────


def test_dsn_from_coords_defaults():
    dsn = envload.dsn_from_coords({"POSTGRES_PASSWORD": "pw"})
    assert dsn == "host=localhost port=5432 dbname=blacksea user=blacksea password=pw"


def test_dsn_from_coords_honors_overrides():
    dsn = envload.dsn_from_coords(
        {"POSTGRES_PASSWORD": "pw", "POSTGRES_HOST": "db.internal", "POSTGRES_PORT": "6543"})
    assert "host=db.internal" in dsn and "port=6543" in dsn


def test_dsn_from_coords_none_without_password():
    assert envload.dsn_from_coords({"NATS_PASS": "x"}) is None


# ── find_config_file ────────────────────────────────────────────────────────────


def test_find_prefers_config_over_legacy(tmp_path, monkeypatch):
    monkeypatch.delenv("BS_CONFIG", raising=False)
    _write(tmp_path / "config" / "blacksea.env", "BS_INFRA=docker\n")
    _write(tmp_path / "secrets" / "env", "POSTGRES_PASSWORD=old\n")
    found = envload.find_config_file(start=str(tmp_path))
    assert found == str(tmp_path / "config" / "blacksea.env")


def test_find_falls_back_to_legacy_secrets(tmp_path, monkeypatch):
    monkeypatch.delenv("BS_CONFIG", raising=False)
    _write(tmp_path / "secrets" / "env", "POSTGRES_PASSWORD=old\n")
    found = envload.find_config_file(start=str(tmp_path))
    assert found == str(tmp_path / "secrets" / "env")


def test_find_searches_upward(tmp_path, monkeypatch):
    monkeypatch.delenv("BS_CONFIG", raising=False)
    _write(tmp_path / "config" / "blacksea.env", "BS_INFRA=docker\n")
    sub = tmp_path / "a" / "b"
    sub.mkdir(parents=True)
    assert envload.find_config_file(start=str(sub)) == str(tmp_path / "config" / "blacksea.env")


def test_find_explicit_and_bs_config(tmp_path, monkeypatch):
    p = tmp_path / "custom.env"
    _write(p, "BS_INFRA=external\n")
    assert envload.find_config_file(str(p)) == str(p)
    assert envload.find_config_file(str(tmp_path / "absent.env")) is None
    monkeypatch.setenv("BS_CONFIG", str(p))
    assert envload.find_config_file(start=str(tmp_path)) == str(p)


def test_find_none_when_absent(tmp_path, monkeypatch):
    monkeypatch.delenv("BS_CONFIG", raising=False)
    monkeypatch.setattr(envload, "PROJECT_ROOT", None)   # suppress the package anchor for isolation
    assert envload.find_config_file(start=str(tmp_path)) is None


# ── package anchor (find from any CWD, not just inside the checkout) ─────────────


def test_find_uses_package_anchor_when_cwd_walk_misses(tmp_path, monkeypatch):
    """With nothing near ``start`` but a config under the (package-derived) project root, discovery
    falls back to ``<PROJECT_ROOT>/config/blacksea.env`` — this is what makes an installed
    ``blacksea`` resolve its config from any working directory."""
    monkeypatch.delenv("BS_CONFIG", raising=False)
    root = tmp_path / "proj"
    _write(root / "config" / "blacksea.env", "BS_INFRA=docker\n")
    monkeypatch.setattr(envload, "PROJECT_ROOT", str(root))
    empty = tmp_path / "somewhere" / "else"
    empty.mkdir(parents=True)
    assert envload.find_config_file(start=str(empty)) == str(root / "config" / "blacksea.env")


def test_cwd_config_wins_over_package_anchor(tmp_path, monkeypatch):
    """An in-tree ``config/blacksea.env`` (CWD-upward walk) takes precedence over the package anchor,
    so a checkout you are actively hacking in wins."""
    monkeypatch.delenv("BS_CONFIG", raising=False)
    root = tmp_path / "proj"
    _write(root / "config" / "blacksea.env", "BS_INFRA=external\n")
    monkeypatch.setattr(envload, "PROJECT_ROOT", str(root))
    local = tmp_path / "checkout"
    _write(local / "config" / "blacksea.env", "BS_INFRA=docker\n")
    assert envload.find_config_file(start=str(local)) == str(local / "config" / "blacksea.env")


def test_package_root_validated_by_pyproject(tmp_path, monkeypatch):
    """The package-derived root is trusted only when it contains ``pyproject.toml`` (else ``None``),
    so a relocated/non-editable install never yields a bogus anchor."""
    monkeypatch.delenv("BS_PROJECT_ROOT", raising=False)
    monkeypatch.setattr(envload, "__file__", str(tmp_path / "site-packages" / "blacksea"
                                                 / "config" / "envload.py"))
    assert envload._package_project_root() is None       # no pyproject.toml up there
    (tmp_path / "pyproject.toml").write_text("", encoding="utf-8")
    root = envload._package_project_root()
    assert root is not None and os.path.exists(os.path.join(root, "pyproject.toml"))


# ── load_into_environ (env wins) ────────────────────────────────────────────────


def test_load_sets_unset_keys_only(tmp_path, monkeypatch):
    monkeypatch.delenv("BS_CONFIG", raising=False)
    _write(tmp_path / "config" / "blacksea.env",
           "BS_INFRA=docker\nPOSTGRES_PASSWORD=fromfile\nNATS_PASS=filepw\n")
    monkeypatch.setenv("POSTGRES_PASSWORD", "fromenv")   # already set → must win
    monkeypatch.delenv("NATS_PASS", raising=False)
    monkeypatch.delenv("BS_INFRA", raising=False)
    path = envload.load_into_environ(start=str(tmp_path))
    assert path == str(tmp_path / "config" / "blacksea.env")
    assert os.environ["POSTGRES_PASSWORD"] == "fromenv"  # env wins over file
    assert os.environ["NATS_PASS"] == "filepw"           # file fills the unset key
    assert os.environ["BS_INFRA"] == "docker"


def test_load_missing_is_noop(tmp_path, monkeypatch):
    monkeypatch.delenv("BS_CONFIG", raising=False)
    monkeypatch.setattr(envload, "PROJECT_ROOT", None)   # suppress the package anchor for isolation
    assert envload.load_into_environ(start=str(tmp_path)) is None
