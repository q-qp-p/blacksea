"""Size-reduction passes (safe first).

0. :func:`run_compression_pipeline`  -- staged compression (strip comments, …)
1. :func:`minify`                    -- python-minifier (ws collapse, rename locals)
2. :func:`treeshake`                 -- EXPERIMENTAL, opt-in, conservative dead-code

Minify is on the safe path. Tree-shaking is unsafe in the presence of
getattr/string-dispatch/decorator-registration/__all__ and must be validated by
the project's own test suite against the built bundle.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from .errors import BundlerError


# --- 0. compression pipeline ------------------------------------------------

@dataclass
class CompressionOptions:
    strip_comments: bool = True


_METADATA_DUNDERS = frozenset({
    "__version__", "__author__", "__license__", "__copyright__",
    "__maintainer__", "__email__", "__description__",
})


def _is_metadata_dunder(stmt: ast.stmt) -> bool:
    return (
        isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
        and stmt.targets[0].id in _METADATA_DUNDERS
    )


def _strip_docstrings(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                node.body.pop(0)
        if isinstance(node, ast.Module):
            node.body = [s for s in node.body if not _is_metadata_dunder(s)]
        elif isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if not node.body:
                node.body.append(ast.Pass())


def strip_comments(source: str, *, where: str = "<module>") -> str:
    """Remove all # comments and docstrings from Python source.

    Uses an AST round-trip: # comments are lost in the parse, docstrings are
    removed explicitly. Returns compact ast.unparse output — well-suited as
    input to subsequent compression stages.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return source
    _strip_docstrings(tree)
    return ast.unparse(ast.fix_missing_locations(tree))


def run_compression_pipeline(
    sources: dict[str, str],
    payload: str,
    opts: CompressionOptions,
) -> tuple[dict[str, str], str]:
    """Apply all enabled compression stages in order to module sources and payload."""
    if opts.strip_comments:
        sources = {name: strip_comments(src, where=name) for name, src in sources.items()}
        payload = strip_comments(payload)
    return sources, payload


# --- 1. minification --------------------------------------------------------

def minify(source: str, *, where: str = "<module>") -> str:
    try:
        import python_minifier
    except ImportError as exc:  # pragma: no cover - exercised via clear-error path
        raise BundlerError(
            "--minify requires python-minifier; install it with "
            "`pip install python-minifier` (or `pip install bundler[minify]`)."
        ) from exc
    try:
        return python_minifier.minify(source, rename_globals=True)
    except Exception as exc:  # noqa: BLE001 - report which module failed
        raise BundlerError(f"failed to minify {where}: {exc}") from exc


# --- 2. experimental tree-shaking ------------------------------------------

# Patterns that make module-level pruning unsafe; if a module contains any of
# these we leave it completely untouched.
_DYNAMIC_NAMES = {"getattr", "globals", "vars", "eval", "exec", "locals"}


def _module_used_names(source: str) -> tuple[set[str], set[str], set[str], bool]:
    """Return (referenced_names, attribute_names, imported_names, is_dynamic).

    ``imported_names`` are the bound names of every ``import``/``from ... import``
    (e.g. ``Client`` in ``from .client import Client``) -- a re-export keeps the
    underlying symbol alive even when nothing references it *by name*.
    """
    referenced: set[str] = set()
    attributes: set[str] = set()
    imported: set[str] = set()
    dynamic = False
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return referenced, attributes, imported, True  # be conservative
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            referenced.add(node.id)
            if node.id in _DYNAMIC_NAMES:
                dynamic = True
        elif isinstance(node, ast.Attribute):
            attributes.add(node.attr)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                imported.add(alias.asname or alias.name.split(".")[-1])
                imported.add(alias.name.split(".")[-1])
        elif isinstance(node, ast.FunctionDef) and node.name == "__getattr__":
            dynamic = True
    return referenced, attributes, imported, dynamic


def treeshake(sources: dict[str, str], payload: str) -> tuple[dict[str, str], list[str]]:
    """Drop top-level functions/classes that are provably unreferenced bundle-wide.

    Conservative rules (each is a reason to KEEP a symbol):
      * referenced by name anywhere in the bundle or payload
      * accessed as an attribute (``pkg.symbol``) anywhere
      * imported/re-exported anywhere (``from .client import Client``)
      * listed in ANY module's ``__all__`` (re-exports list names defined elsewhere)
      * decorated (decorators may register it as a side effect)

    A module that uses getattr/globals/eval/exec/__getattr__ is left entirely intact.
    Returns (new_sources, removed_symbol_descriptions).
    """
    # Global keep-set across every module + payload.
    all_referenced: set[str] = set()
    all_attributes: set[str] = set()
    all_imported: set[str] = set()
    all_exported: set[str] = set()
    for src in list(sources.values()) + [payload]:
        ref, attr, imp, _ = _module_used_names(src)
        all_referenced |= ref
        all_attributes |= attr
        all_imported |= imp
        try:
            all_exported |= _dunder_all(ast.parse(src))
        except SyntaxError:
            pass
    keep = all_referenced | all_attributes | all_imported | all_exported

    removed: list[str] = []
    new_sources: dict[str, str] = {}

    for name, src in sources.items():
        _, _, _, dynamic = _module_used_names(src)
        if dynamic:
            new_sources[name] = src
            continue
        try:
            tree = ast.parse(src)
        except SyntaxError:
            new_sources[name] = src
            continue

        keep_body = []
        changed = False
        for stmt in tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                sym = stmt.name
                if not stmt.decorator_list and sym not in keep:
                    removed.append(f"{name}.{sym}")
                    changed = True
                    continue
            keep_body.append(stmt)

        if not changed:
            new_sources[name] = src
            continue
        tree.body = keep_body
        new_sources[name] = ast.unparse(ast.fix_missing_locations(tree))

    return new_sources, removed


def _dunder_all(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "__all__" for t in stmt.targets
        ):
            if isinstance(stmt.value, (ast.List, ast.Tuple)):
                for elt in stmt.value.elts:
                    if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                        names.add(elt.value)
    return names
