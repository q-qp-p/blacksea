"""Static import-graph discovery.

Walks the import graph starting from a payload script, following ``import`` and
``from ... import`` statements transitively. Only modules found *under the given
roots* are vendored; stdlib / third-party imports are left untouched (assumed
present on the target). Resolution understands:

  * absolute imports          ``from sdk.config import Config``
  * package __init__ vendoring ``from sdk import Client``  -> vendors sdk/__init__.py
  * submodule-vs-attribute     ``from sdk import Client``  -> also tries sdk/Client.py
  * relative imports           ``from . import y`` / ``from ..errors import X``
  * implicit parent packages   importing ``a.b.c`` pulls in ``a`` and ``a.b``

Because pruning happens at the *module* level, modules never reached from the
payload simply never enter the bundle.
"""

from __future__ import annotations

import ast
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .errors import CExtError, ResolveError

# Suffixes that indicate a compiled extension we must refuse to vendor.
import importlib.machinery as _machinery

_CEXT_SUFFIXES = tuple(sorted(set(_machinery.EXTENSION_SUFFIXES) | {".so", ".pyd"}))

_STDLIB = set(sys.stdlib_module_names)


def _case_exact(path: Path, expected_name: str) -> bool:
    """True iff ``path``'s final component exists with this exact case.

    macOS/Windows filesystems are case-insensitive, so ``sdk.Client`` would
    otherwise wrongly resolve to ``client.py``. Checking the real directory entry
    keeps resolution (and therefore bundle contents) identical across platforms.
    """
    try:
        return expected_name in os.listdir(path.parent)
    except OSError:
        return False


def resolve_relative_import(module: str | None, level: int, package: str) -> str:
    """Absolute module name a ``from ... import`` targets, resolving relative levels.

    Single source for this arithmetic — discovery's import-graph walk and flatten's source
    rewrite both consume it, so they can never drift (they used to hand-copy it).
    """
    if level == 0:
        return module or ""
    base_parts = package.split(".") if package else []
    up = level - 1
    if up:
        base_parts = base_parts[:-up] if up <= len(base_parts) else []
    base = ".".join(base_parts)
    if module:
        return f"{base}.{module}" if base else module
    return base


def dynamic_import_target(node: ast.Call) -> str | None:
    """If ``node`` is an ``importlib.import_module(...)`` / ``__import__(...)`` call, return the
    target label (for diagnostics); otherwise ``None``. Shared by discovery + flatten."""
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr == "import_module":
        return "importlib.import_module"
    if isinstance(func, ast.Name) and func.id == "__import__":
        return "__import__"
    return None


@dataclass
class Module:
    """A pure-Python module selected for vendoring."""

    name: str          # fully-qualified dotted name, e.g. "sdk.config"
    path: Path         # source file on disk
    is_pkg: bool       # True if this is a package (came from __init__.py)
    source: str        # raw source text

    @property
    def package(self) -> str:
        """The ``__package__`` value this module would have at import time."""
        if self.is_pkg:
            return self.name
        return self.name.rpartition(".")[0]


@dataclass
class DiscoveryResult:
    modules: dict[str, Module]
    warnings: list[str] = field(default_factory=list)
    external: set[str] = field(default_factory=set)
    # Import edges between vendored modules: ``(dependency, dependent)`` means the
    # dependency's body must be executed before the dependent's. Drives the inline
    # loader's execution order (see :func:`exec_order`).
    edges: set[tuple[str, str]] = field(default_factory=set)

    def sorted_modules(self) -> list[Module]:
        """Deterministic, dependency-safe order: parents before children, sorted."""
        return [self.modules[name] for name in sorted(self.modules)]

    def exec_order(self) -> list[str]:
        """Names in an order safe to ``exec`` eagerly (dependencies first)."""
        return exec_order(self.modules.keys(), self.edges)


def exec_order(names: Iterable[str], edges: Iterable[tuple[str, str]]) -> list[str]:
    """Deterministic topological sort: a dependency comes before its dependents.

    The inline loader pre-registers every module object, then runs the bodies in
    this order. Pre-registration means relative imports and import *cycles* still
    resolve (against ``sys.modules``); this ordering additionally guarantees that a
    module which reads *symbols* from another at import time runs after it.

    ``edges`` are ``(dependency, dependent)`` pairs. Ties break alphabetically for
    byte-reproducible output. A genuine cycle (rare; would also trip CPython) is
    broken by forcing the alphabetically-first remaining node, so a build never
    hangs or drops a module.
    """
    remaining = set(names)
    deps: dict[str, set[str]] = {n: set() for n in remaining}
    for dependency, dependent in edges:
        if dependency in remaining and dependent in remaining and dependency != dependent:
            deps[dependent].add(dependency)

    ordered: list[str] = []
    done: set[str] = set()
    while remaining:
        ready = sorted(n for n in remaining if deps[n] <= done)
        if not ready:
            # Cycle: force the smallest remaining name to make progress.
            ready = [min(remaining)]
        for name in ready:
            ordered.append(name)
            done.add(name)
            remaining.discard(name)
    return ordered


class Discovery:
    def __init__(self, roots: Iterable[str | Path]) -> None:
        self.roots = [Path(r).resolve() for r in roots]
        self.modules: dict[str, Module] = {}
        self.warnings: list[str] = []
        self.external: set[str] = set()
        # Raw ``(target, importer)`` import edges, filtered to vendored modules in
        # :meth:`discover`. ``target`` must be exec'd before ``importer``.
        self._raw_edges: list[tuple[str, str]] = []
        self._queue: list[Module] = []
        self._seen_external: set[str] = set()

    # -- file resolution ---------------------------------------------------

    def _resolve_file(self, name: str) -> tuple[Path, bool] | None:
        """Locate ``name`` under the roots.

        Returns ``(path, is_pkg)`` for a pure-Python hit, ``None`` if not found
        under any root (stdlib/third-party), or raises :class:`CExtError` if the
        only on-root match is a compiled extension.
        """
        parts = name.split(".")
        leaf = parts[-1]
        for root in self.roots:
            pkg_dir = root.joinpath(*parts)
            pkg_init = pkg_dir / "__init__.py"
            if pkg_init.is_file() and _case_exact(pkg_dir, leaf):
                return pkg_init, True
            mod_py = root.joinpath(*parts).with_suffix(".py")
            if mod_py.is_file() and _case_exact(mod_py, leaf + ".py"):
                return mod_py, False
            # Pure-Python not found here: is there a compiled extension instead?
            stem_dir = root.joinpath(*parts[:-1]) if len(parts) > 1 else root
            for ext in _CEXT_SUFFIXES:
                cext = stem_dir / (parts[-1] + ext)
                if cext.is_file():
                    raise CExtError(name, cext)
        return None

    # -- graph construction ------------------------------------------------

    def _add(self, name: str, *, attempt: bool = False) -> Module | None:
        """Vendor ``name`` (and its parent packages) if it lives under a root.

        ``attempt=True`` marks a speculative ``from pkg import X`` where ``X`` may
        be a submodule *or* a re-exported attribute; a miss is silent in that case.
        A non-attempt miss for a non-stdlib top-level package is recorded as an
        external dependency to warn about.
        """
        if not name:
            return None
        if name in self.modules:
            return self.modules[name]

        resolved = self._resolve_file(name)  # may raise CExtError
        if resolved is None:
            if not attempt:
                top = name.split(".")[0]
                if top not in _STDLIB and top not in self._seen_external:
                    self._seen_external.add(top)
                    self.external.add(top)
            return None

        path, is_pkg = resolved
        source = path.read_text(encoding="utf-8")
        module = Module(name=name, path=path, is_pkg=is_pkg, source=source)
        self.modules[name] = module
        self._queue.append(module)

        # Importing a.b.c at runtime requires a and a.b to be importable packages.
        parent = name.rpartition(".")[0]
        if parent:
            self._add(parent)
        return module

    def _scan(self, module: Module) -> None:
        self._scan_source(module.source, module.package, str(module.path), importer=module.name)

    def _scan_source(
        self, source: str, package: str, where: str, importer: str | None = None
    ) -> None:
        try:
            tree = ast.parse(source, filename=where)
        except SyntaxError as exc:  # pragma: no cover - defensive
            self.warnings.append(f"could not parse {where}: {exc}")
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self._add(alias.name)  # also pulls parents
                    self._edge(alias.name, importer)
            elif isinstance(node, ast.ImportFrom):
                self._handle_from(node, package, importer)
            elif isinstance(node, ast.Call):
                self._check_dynamic(node, where)

    def _edge(self, target: str, importer: str | None) -> None:
        """Record that ``target`` should be exec'd before ``importer``.

        Ancestor packages of ``importer`` are skipped: they're satisfied by the
        loader pre-registering every module object, and constraining them would
        invent a false parent<->child cycle (a package ``__init__`` that re-exports
        a submodule, while that submodule imports relatively from the package)."""
        if not target or not importer or target == importer:
            return
        if importer == target or importer.startswith(target + "."):
            return  # target is an ancestor of importer -> registration is enough
        self._raw_edges.append((target, importer))

    def _handle_from(self, node: ast.ImportFrom, package: str, importer: str | None = None) -> None:
        from_mod = resolve_relative_import(node.module, node.level, package)
        if not from_mod:
            return

        self._add(from_mod)
        self._edge(from_mod, importer)
        # Each imported name might itself be a submodule (re-export vs attribute).
        for alias in node.names:
            if alias.name == "*":
                continue
            submod = f"{from_mod}.{alias.name}"
            self._add(submod, attempt=True)
            self._edge(submod, importer)

    def _check_dynamic(self, node: ast.Call, where: str) -> None:
        target = dynamic_import_target(node)
        if target is None:
            return
        first = node.args[0] if node.args else None
        if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
            self.warnings.append(
                f"dynamic import via {target}(...) in {where}:{getattr(node, 'lineno', '?')} "
                f"is invisible to static analysis; add it with --include-module if it "
                f"must be vendored."
            )

    # -- public API --------------------------------------------------------

    def discover(self, payload: str | Path, include_modules: Iterable[str] = ()) -> DiscoveryResult:
        payload = Path(payload)
        payload_src = payload.read_text(encoding="utf-8")
        # Seed from the payload script (a top-level module, package == "").
        self._scan_source(payload_src, package="", where=str(payload))

        for name in include_modules:
            module = self._add(name)
            if module is None:
                raise ResolveError(
                    f"--include-module {name!r} was not found under any --root "
                    f"({', '.join(str(r) for r in self.roots)})"
                )

        # Breadth-first transitive walk.
        while self._queue:
            module = self._queue.pop(0)
            self._scan(module)

        if self.external:
            self.warnings.append(
                "external/unvendored imports (assumed present on target): "
                + ", ".join(sorted(self.external))
            )

        # Keep only edges between modules we actually vendored.
        edges = {
            (dep, dependent)
            for dep, dependent in self._raw_edges
            if dep in self.modules and dependent in self.modules
        }

        return DiscoveryResult(
            modules=dict(self.modules),
            warnings=list(self.warnings),
            external=set(self.external),
            edges=edges,
        )
