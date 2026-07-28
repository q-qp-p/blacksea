"""Source-level flattening: inline vendored modules as real top-level code.

Instead of embedding each module as a string and loading it through a runtime
importer, the flattener rewrites every source into a single shared namespace:

  * intra-bundle imports (``from . import x``, ``from sdk import Client``) are
    *removed* -- the symbols they bound are about to exist at top level;
  * references qualified through a vendored-module alias are de-qualified
    (``_util.normalize`` -> ``normalize``, ``get_data.collect_host_info`` ->
    ``collect_host_info``);
  * external/stdlib imports are hoisted to the top (deduped);
  * module bodies are emitted in dependency-first order, then the payload.

This is heuristic and unsafe in general: it collapses every module into one
global namespace, so it **fails loudly** on the things that make that unsound --
top-level name collisions between modules, ``from x import *``, a vendored module
used as a bare value, or a dynamic import of a vendored module. The output is
plain readable Python with no loader, no strings, and no runtime machinery.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from .discovery import Module, dynamic_import_target, resolve_relative_import
from .errors import BundlerError


class FlattenError(BundlerError):
    """A construct that source-flattening cannot soundly rewrite."""


@dataclass
class _Processed:
    body: list[ast.stmt]          # statements to inline (imports stripped, refs rewritten)
    hoist: list[ast.stmt]         # external top-level imports to lift to the file top
    defined: set[str]             # top-level def/class names this source contributes
    warnings: list[str] = field(default_factory=list)


class _Rewriter(ast.NodeTransformer):
    """Drop stripped imports and de-qualify references to vendored modules."""

    def __init__(self, module_aliases: set[str], symbol_renames: dict[str, str], strip: set[int]):
        self._aliases = module_aliases
        self._renames = symbol_renames
        self._strip = strip
        self.bare_alias_uses: set[str] = set()

    def visit_Import(self, node: ast.Import):
        return None if id(node) in self._strip else node

    def visit_ImportFrom(self, node: ast.ImportFrom):
        return None if id(node) in self._strip else node

    def visit_Attribute(self, node: ast.Attribute):
        value = node.value
        if isinstance(value, ast.Name) and value.id in self._aliases:
            # ``alias.symbol`` -> ``symbol`` (the symbol is now top-level).
            return ast.copy_location(ast.Name(id=node.attr, ctx=node.ctx), node)
        return self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        if node.id in self._renames:
            return ast.copy_location(ast.Name(id=self._renames[node.id], ctx=node.ctx), node)
        if node.id in self._aliases:
            # A vendored module used as a bare value (not ``alias.x``) has no
            # object to stand in for it once flattened.
            self.bare_alias_uses.add(node.id)
        return node


def _classify(node, package: str, vendored: set[str], where: str):
    """Classify one import node: ('intra'|'external', module_aliases, symbol_renames)."""
    module_aliases: dict[str, str] = {}
    symbol_renames: dict[str, str] = {}

    if isinstance(node, ast.Import):
        hits = [a for a in node.names if a.name in vendored]
        if not hits:
            return "external", module_aliases, symbol_renames
        if len(hits) != len(node.names):
            raise FlattenError(
                f"{where}: cannot flatten a mixed `import` of vendored and external "
                f"modules; split it into separate statements."
            )
        for alias in node.names:
            if alias.asname:
                module_aliases[alias.asname] = alias.name
            elif "." in alias.name:
                raise FlattenError(
                    f"{where}: `import {alias.name}` (dotted, no `as`) can't be flattened; "
                    f"use `import {alias.name} as <name>` or `from ... import ...`."
                )
            else:
                module_aliases[alias.name] = alias.name
        return "intra", module_aliases, symbol_renames

    # ast.ImportFrom
    from_mod = resolve_relative_import(node.module, node.level, package)
    names = [a.name for a in node.names]
    if "*" in names:
        if from_mod in vendored or any(f"{from_mod}.{n}" in vendored for n in names if n != "*"):
            raise FlattenError(
                f"{where}: `from {from_mod or '.'} import *` of a vendored module can't be "
                f"flattened (unknown names); import the names explicitly."
            )
        return "external", module_aliases, symbol_renames

    submods = {a.name: f"{from_mod}.{a.name}" for a in node.names}
    intra = from_mod in vendored or any(s in vendored for s in submods.values())
    if not intra:
        return "external", module_aliases, symbol_renames

    for alias in node.names:
        local = alias.asname or alias.name
        if submods[alias.name] in vendored:
            module_aliases[local] = submods[alias.name]  # a re-exported submodule
        elif alias.asname:
            symbol_renames[local] = alias.name           # `from m import a as b`
    return "intra", module_aliases, symbol_renames


def _check_dynamic(node: ast.Call, vendored: set[str], where: str, warnings: list[str]) -> None:
    target = dynamic_import_target(node)
    if target is None:
        return
    first = node.args[0] if node.args else None
    if isinstance(first, ast.Constant) and isinstance(first.value, str) and first.value in vendored:
        raise FlattenError(
            f"{where}: {target}({first.value!r}) dynamically imports a vendored module; "
            f"flattening has no module object to resolve it. Reference it statically."
        )
    if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
        warnings.append(
            f"{where}: dynamic {target}(...) is left as-is; a vendored target would not "
            f"resolve in the flattened bundle (no runtime importer)."
        )


def _process(source: str, package: str, vendored: set[str], where: str) -> _Processed:
    tree = ast.parse(source, filename=where)
    top_ids = {id(n) for n in tree.body}
    module_aliases: dict[str, str] = {}
    symbol_renames: dict[str, str] = {}
    strip: set[int] = set()
    hoist: list[ast.stmt] = []
    warnings: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            kind, m_al, s_ren = _classify(node, package, vendored, where)
            if kind == "intra":
                strip.add(id(node))
                module_aliases.update(m_al)
                symbol_renames.update(s_ren)
            elif id(node) in top_ids:
                hoist.append(node)        # external + top-level -> lift to file top
                strip.add(id(node))
        elif isinstance(node, ast.Call):
            _check_dynamic(node, vendored, where, warnings)

    rewriter = _Rewriter(set(module_aliases), symbol_renames, strip)
    new_tree = rewriter.visit(tree)
    ast.fix_missing_locations(new_tree)
    if rewriter.bare_alias_uses:
        raise FlattenError(
            f"{where}: vendored module(s) {sorted(rewriter.bare_alias_uses)} used as a bare "
            f"value (not `module.attr`); flattening can't represent the module object."
        )

    defined = {
        s.name
        for s in new_tree.body
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }
    return _Processed(body=new_tree.body, hoist=hoist, defined=defined, warnings=warnings)


def _hoist_key(node: ast.stmt) -> tuple[int, str]:
    text = ast.unparse(node)
    # __future__ imports must precede all other code.
    future = isinstance(node, ast.ImportFrom) and node.module == "__future__"
    return (0 if future else 1, text)


def flatten(
    modules: list[Module],
    sources: dict[str, str],
    payload_source: str,
    order: list[str],
    payload_name: str,
    *,
    strip_comments: bool = False,
) -> tuple[str, list[str]]:
    """Return (flattened_source, warnings). Raises FlattenError on unsound input."""
    vendored = {m.name for m in modules}
    packages = {m.name: m.package for m in modules}

    processed: dict[str, _Processed] = {
        name: _process(sources[name], packages[name], vendored, name) for name in vendored
    }
    payload = _process(payload_source, "", vendored, payload_name)

    # Top-level def/class collisions across the shared namespace are fatal.
    owners: dict[str, list[str]] = {}
    for name in order:
        for sym in processed[name].defined:
            owners.setdefault(sym, []).append(name)
    for sym in payload.defined:
        owners.setdefault(sym, []).append(payload_name)
    clashes = {sym: where for sym, where in owners.items() if len(where) > 1}
    if clashes:
        detail = "; ".join(f"{sym!r} in {', '.join(w)}" for sym, w in sorted(clashes.items()))
        raise FlattenError(
            "flatten: top-level name collision in the shared namespace -- "
            f"{detail}. Rename one, or build without flattening."
        )

    warnings: list[str] = list(payload.warnings)
    for name in order:
        warnings.extend(processed[name].warnings)

    # Hoisted external imports (deduped, __future__ first, then sorted).
    hoist_nodes: list[ast.stmt] = []
    seen: set[str] = set()
    for proc in [processed[name] for name in order] + [payload]:
        for node in proc.hoist:
            text = ast.unparse(node)
            if text not in seen:
                seen.add(text)
                hoist_nodes.append(node)
    hoist_nodes.sort(key=_hoist_key)

    chunks: list[str] = []
    if hoist_nodes:
        chunks.append("\n".join(ast.unparse(n) for n in hoist_nodes))
    for name in order:                       # dependency-first
        body = processed[name].body
        if body:
            prefix = "" if strip_comments else f"# --- {name} ---\n"
            chunks.append(prefix + ast.unparse(ast.Module(body=body, type_ignores=[])))
    if payload.body:
        prefix = "" if strip_comments else "# --- payload ---\n"
        chunks.append(prefix + ast.unparse(ast.Module(body=payload.body, type_ignores=[])))

    return "\n\n\n".join(chunks) + "\n", warnings
