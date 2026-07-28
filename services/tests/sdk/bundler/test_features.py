"""Discovery edge cases, size passes, flattening, determinism, dynamic imports."""

from __future__ import annotations

import textwrap

import pytest

from conftest import FIXTURES, run_clean_room

from blacksea.bundler.builder import BuildOptions, build
from blacksea.bundler.discovery import Discovery, exec_order
from blacksea.bundler.flatten import FlattenError

PAYLOAD = FIXTURES / "payload.py"


# --- determinism / reproducibility -----------------------------------------

def test_output_is_byte_for_byte_reproducible():
    opts = BuildOptions(roots=[str(FIXTURES)])
    a = build(PAYLOAD, opts).text
    b = build(PAYLOAD, opts).text
    assert a == b


def test_module_order_is_sorted():
    result = Discovery([str(FIXTURES)]).discover(PAYLOAD)
    ordered = [m.name for m in result.sorted_modules()]
    assert ordered == sorted(ordered)


def test_exec_order_is_dependency_first():
    result = Discovery([str(FIXTURES)]).discover(PAYLOAD)
    order = result.exec_order()
    pos = {name: i for i, name in enumerate(order)}
    # every dependency is inlined before the module that needs its symbols
    for dep, dependent in result.edges:
        assert pos[dep] < pos[dependent], (dep, dependent)
    # the re-exporting package __init__ comes last
    assert order[-1] == "sdk"


def test_exec_order_breaks_cycles_deterministically():
    names = ["a", "b"]
    edges = [("a", "b"), ("b", "a")]  # genuine cycle
    order = exec_order(names, edges)
    assert sorted(order) == ["a", "b"]  # both present, no hang


# --- flattening: real inlined source, no runtime --------------------------

def test_flatten_inlines_source_and_dequalifies():
    text = build(PAYLOAD, BuildOptions(roots=[str(FIXTURES)])).text
    # cross-module references are de-qualified to the shared namespace
    assert "self.transport.send" in text
    assert "return encode(" in text          # was `codec.encode(...)`
    assert "name = normalize(who)" in text   # was `_util.normalize(who)`
    # intra-bundle imports are gone
    assert "from . import" not in text
    assert "from sdk import" not in text


def test_flatten_name_collision_fails_loudly(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "__init__.py").write_text("")
    # two modules both define a top-level `dup`
    (tmp_path / "a" / "one.py").write_text("def dup():\n    return 1\n")
    (tmp_path / "a" / "two.py").write_text("def dup():\n    return 2\n")
    payload = tmp_path / "p.py"
    payload.write_text("from a.one import dup as d1\nfrom a.two import dup as d2\nprint(d1(), d2())\n")
    with pytest.raises(FlattenError) as exc:
        build(payload, BuildOptions(roots=[str(tmp_path)], experimental_treeshake=False))
    assert "collision" in str(exc.value)
    assert "dup" in str(exc.value)


def test_flatten_star_import_of_vendored_fails(tmp_path):
    root = tmp_path / "lib"
    root.mkdir()
    (root / "__init__.py").write_text("")
    (root / "thing.py").write_text("VALUE = 7\n")
    payload = tmp_path / "p.py"
    payload.write_text("from lib.thing import *\nprint(VALUE)\n")
    with pytest.raises(FlattenError) as exc:
        build(payload, BuildOptions(roots=[str(tmp_path)], experimental_treeshake=False))
    assert "*" in str(exc.value)


# --- size passes ------------------------------------------------------------

def test_minify_shrinks_and_is_smaller():
    pytest.importorskip("python_minifier")
    plain = build(PAYLOAD, BuildOptions(roots=[str(FIXTURES)])).text
    mini = build(PAYLOAD, BuildOptions(roots=[str(FIXTURES)], minify=True)).text
    assert len(mini) < len(plain)


def test_minified_bundle_still_runs(make_bundle):
    pytest.importorskip("python_minifier")
    bundle = make_bundle(PAYLOAD, minify=True)
    assert run_clean_room(bundle).stdout.strip() == "HELLO WORLD #T"


def test_treeshake_removes_unused_symbol():
    result = build(PAYLOAD, BuildOptions(roots=[str(FIXTURES)], experimental_treeshake=True))
    assert "sdk._util.unused_helper" in result.removed_symbols
    assert "unused_helper" not in result.text
    # used symbols survive
    assert "normalize" in result.text


def test_treeshake_defaults_on():
    result = build(PAYLOAD, BuildOptions(roots=[str(FIXTURES)]))
    assert "sdk._util.unused_helper" in result.removed_symbols
    assert "unused_helper" not in result.text


def test_treeshake_can_be_disabled():
    result = build(PAYLOAD, BuildOptions(roots=[str(FIXTURES)], experimental_treeshake=False))
    assert result.removed_symbols == []
    assert "unused_helper" in result.text


def test_strip_comments_removes_docstrings():
    result = build(PAYLOAD, BuildOptions(roots=[str(FIXTURES)]))
    assert '"""' not in result.text
    assert "'''" not in result.text


def test_strip_comments_can_be_disabled():
    from blacksea.bundler.transform import CompressionOptions
    opts = BuildOptions(
        roots=[str(FIXTURES)],
        compression=CompressionOptions(strip_comments=False),
    )
    result = build(PAYLOAD, opts)
    assert '"""' in result.text or "'''" in result.text


def test_cli_strip_comments_flag_defaults_and_negation():
    from blacksea.bundler.cli import _parser
    base = ["p.py", "--root", "."]
    assert _parser().parse_args(base).strip_comments is True
    assert _parser().parse_args(base + ["--no-strip-comments"]).strip_comments is False
    assert _parser().parse_args(base + ["--strip-comments"]).strip_comments is True


def test_cli_treeshake_flag_defaults_and_negation():
    from blacksea.bundler.cli import _parser

    base = ["p.py", "--root", "."]
    assert _parser().parse_args(base).experimental_treeshake is True
    assert _parser().parse_args(base + ["--no-experimental-treeshake"]).experimental_treeshake is False
    assert _parser().parse_args(base + ["--experimental-treeshake"]).experimental_treeshake is True


# --- dynamic imports / include-module --------------------------------------

def test_dynamic_import_warns():
    payload = FIXTURES / "dynamic_payload.py"
    result = build(payload, BuildOptions(roots=[str(FIXTURES)]))
    assert any("dynamic import" in w for w in result.warnings)


def test_include_module_inlines_but_warns_on_dynamic(make_bundle):
    """`--include-module` inlines the source, but a dynamic import of it can't be
    wired up in a flattened bundle -- the build says so instead of silently lying."""
    payload = FIXTURES / "dynamic_payload.py"
    result = build(payload, BuildOptions(roots=[str(FIXTURES)], include_modules=["sdk.plugins.extra"]))
    # the plugin's real source is inlined
    assert "def run():" in result.text
    # ...and the user is warned the dynamic call won't resolve
    assert any("import_module" in w or "dynamic" in w for w in result.warnings)


def test_static_dynamic_import_of_vendored_errors(tmp_path):
    root = tmp_path / "lib"
    root.mkdir()
    (root / "__init__.py").write_text("")
    (root / "plug.py").write_text("def go():\n    return 'ok'\n")
    payload = tmp_path / "p.py"
    payload.write_text("import importlib\nm = importlib.import_module('lib.plug')\nprint(m.go())\n")
    with pytest.raises(FlattenError) as exc:
        build(payload, BuildOptions(roots=[str(tmp_path)],
                                    include_modules=["lib.plug"],
                                    experimental_treeshake=False))
    assert "import_module" in str(exc.value)


def test_include_module_missing_errors():
    from blacksea.bundler.errors import ResolveError

    with pytest.raises(ResolveError):
        build(PAYLOAD, BuildOptions(roots=[str(FIXTURES)], include_modules=["sdk.nope.nada"]))


# --- external/stdlib left as-is, hoisted -----------------------------------

def test_stdlib_not_vendored():
    result = Discovery([str(FIXTURES)]).discover(FIXTURES / "dynamic_payload.py")
    # importlib is stdlib; never vendored, never warned about.
    assert "importlib" not in result.modules
    assert "importlib" not in result.external


def test_external_imports_hoisted(tmp_path):
    root = tmp_path / "lib"
    root.mkdir()
    (root / "__init__.py").write_text("")
    (root / "mod.py").write_text("import os\n\ndef where():\n    return os.getcwd()\n")
    payload = tmp_path / "p.py"
    payload.write_text("from lib.mod import where\nprint(where())\n")
    text = build(payload, BuildOptions(roots=[str(tmp_path)], experimental_treeshake=False)).text
    # `import os` is lifted above the function body that uses it
    assert text.index("import os") < text.index("def where():")


def test_global_vars_placed_after_future_imports(tmp_path):
    """--var must not precede 'from __future__ import annotations' (PEP 236)."""
    root = tmp_path / "lib"
    root.mkdir()
    (root / "__init__.py").write_text("from __future__ import annotations\n")
    (root / "mod.py").write_text("from __future__ import annotations\ndef f(): return 1\n")
    payload = tmp_path / "p.py"
    payload.write_text("from lib.mod import f\nprint(f())\n")
    result = build(
        payload,
        BuildOptions(roots=[str(tmp_path)], global_vars={"X": "42"}, experimental_treeshake=False),
    )
    # Must be valid Python (no SyntaxError).
    import ast
    ast.parse(result.text)
    # __future__ import must precede the injected var.
    assert result.text.index("from __future__") < result.text.index("X = 42")
