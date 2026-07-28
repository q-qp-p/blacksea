"""Orchestrates discovery -> size passes -> single-file assembly."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import emit, transform
from .discovery import Discovery
from .transform import CompressionOptions


@dataclass
class BuildOptions:
    roots: list[str]
    include_modules: list[str] = field(default_factory=list)
    compression: CompressionOptions = field(default_factory=CompressionOptions)
    minify: bool = False
    experimental_treeshake: bool = True
    global_vars: dict[str, str] = field(default_factory=dict)


@dataclass
class BuildResult:
    text: str
    module_names: list[str]
    warnings: list[str]
    removed_symbols: list[str]
    pre_minified_text: str | None = None


def build(payload: str | Path, options: BuildOptions) -> BuildResult:
    payload_path = Path(payload)
    payload_source = payload_path.read_text(encoding="utf-8")

    # 1. Static import-graph discovery (module-level pruning + C-ext detection).
    result = Discovery(options.roots).discover(payload_path, options.include_modules)
    modules = result.sorted_modules()
    # Dependency-first order the inline loader execs bodies in (modules are still
    # *emitted* sorted; this is only the runtime execution order).
    order = result.exec_order()
    warnings = list(result.warnings)

    # Working copy of every source we will embed.
    sources = {m.name: m.source for m in modules}

    # 2. Experimental tree-shaking (opt-in, conservative): drop unused top-level
    #    defs/classes so less dead code gets inlined.
    removed: list[str] = []
    if options.experimental_treeshake:
        sources, removed = transform.treeshake(sources, payload_source)

    # 3. Compression pipeline: apply all enabled stages in order.
    sources, payload_source = transform.run_compression_pipeline(
        sources, payload_source, options.compression
    )

    # Collect names of active compression passes for the bundle header.
    active_passes: list[str] = []
    if options.compression.strip_comments:
        active_passes.append("strip-comments")

    # 4. Flatten everything into one dependency-free .py (inlined real source).
    text, flatten_warnings = emit.assemble(
        payload_path,
        modules,
        sources,
        payload_source,
        order=order,
        minified=options.minify,
        treeshaken=options.experimental_treeshake,
        compression_passes=active_passes,
        strip_comments=options.compression.strip_comments,
        global_vars=options.global_vars,
    )
    warnings.extend(flatten_warnings)

    # 5. Minification (safe, biggest easy win): runs over the final single module.
    pre_minified_text = None
    if options.minify:
        pre_minified_text = text
        if options.compression.strip_comments:
            text = transform.minify(text, where=payload_path.name)
        else:
            # Keep the header comment block; minify only the code below it.
            header, _, code = text.partition("\n\n")
            text = header + "\n\n" + transform.minify(code, where=payload_path.name)
        if not text.endswith("\n"):
            text += "\n"

    return BuildResult(
        text=text,
        module_names=[m.name for m in modules],
        warnings=warnings,
        removed_symbols=removed,
        pre_minified_text=pre_minified_text,
    )
