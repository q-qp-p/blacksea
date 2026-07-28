"""render.py — the JSON seam + the exception→exit-code mapping."""

from __future__ import annotations

import json

import click

from blacksea.console import render
from blacksea.console.models import ArtifactLocation, ComponentStatus
from blacksea.control_plane.forge import ForgeError
from blacksea.control_plane.operations import OperationError, UsageError
from blacksea.control_plane.registry import CatalogUnavailableError


def test_to_jsonable_dataclass() -> None:
    c = ComponentStatus("postgres", "up", "direct", "ok")
    assert render.to_jsonable(c) == {
        "name": "postgres", "status": "up", "source": "direct", "detail": "ok"}


def test_to_jsonable_list_is_array() -> None:
    rows = [ComponentStatus("a", "up", "direct", ""), ComponentStatus("b", "down", "inferred", "x")]
    out = render.to_jsonable(rows)
    assert isinstance(out, list) and len(out) == 2 and out[1]["status"] == "down"


def test_to_jsonable_nested_dict_and_list() -> None:
    obj = {"k": [ComponentStatus("a", "up", "direct", "")], "n": 3}
    out = render.to_jsonable(obj)
    assert out == {"k": [{"name": "a", "status": "up", "source": "direct", "detail": ""}], "n": 3}


def test_exit_codes_reuse_operations_convention() -> None:
    # 2 = usage, 1 = operational, and ForgeError / CatalogUnavailableError are operational (1).
    assert render.handle_exception(UsageError("bad flag")) == 2
    assert render.handle_exception(OperationError("cannot apply")) == 1
    assert render.handle_exception(ForgeError("build failed")) == 1
    assert render.handle_exception(CatalogUnavailableError("no dsn")) == 1


def test_click_exception_maps_to_its_own_code() -> None:
    assert render.handle_exception(click.UsageError("missing arg")) == 2


def test_json_print_shape(capsys) -> None:
    render.print_json([ComponentStatus("a", "up", "direct", "")])
    out = capsys.readouterr().out.strip()
    assert out.startswith("[") and out.endswith("]")
    render.print_json(ComponentStatus("a", "up", "direct", ""))
    out = capsys.readouterr().out.strip()
    assert out.startswith("{") and out.endswith("}")


def test_artifact_detail_json_is_single_object(capsys) -> None:
    """forge/instances build call this after a build to show every staged file, not just the
    primary one (a vessel like pwcrypt stages several equally-valid binaries). Under --json this
    must stay exactly one JSON object — the e2e harness's `grep '^{' | tail -1` picks the LAST
    `{`-line, so a second object here would silently replace the one it expects to parse."""
    rctx = render.RenderContext(json_mode=True)
    art = ArtifactLocation(
        instance_token="tok", bait_id="b", status="active", filename="primary.bin",
        sha256="abc", to_stage_dir="/a/to_stage", output_dir_root="/a",
        ready_for_vessel=None, files={"primary.bin": "abc", "alt.bin": "def"},
    )
    render.artifact_detail(rctx, art)
    out = capsys.readouterr().out.strip()
    lines = out.splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("{") and lines[0].endswith("}")
    assert json.loads(lines[0])["instance_token"] == "tok"


def test_print_json_flushes_immediately(tmp_path, monkeypatch) -> None:
    # Regression: `events tail --json` streams print_json from a long-running loop with stdout
    # often redirected to a file/pipe (block-buffered by default, unlike a tty) — without an
    # explicit flush, a process killed via SIGTERM (no flush-on-exit hook, unlike the SIGINT the
    # loop itself catches) silently loses its most recently written record.
    path = tmp_path / "out.json"
    with open(path, "w") as f:
        monkeypatch.setattr("sys.stdout", f)
        render.print_json(ComponentStatus("a", "up", "direct", ""))
        # A second, independent read while `f` is still open only sees bytes print_json itself
        # pushed past Python's buffer — this fails if the flush() call is ever removed.
        assert path.read_text().strip().startswith("{")
