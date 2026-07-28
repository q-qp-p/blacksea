"""``bundle`` command-line entry point."""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

from .builder import BuildOptions, build
from .transform import CompressionOptions
from .errors import BundlerError


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bundle",
        description=(
            "Bundle a Python payload script and its on-root SDK dependencies into "
            "one self-contained, zero-disk-write .py file."
        ),
    )
    p.add_argument("payload", help="the entry-point .py script to bundle")
    p.add_argument(
        "--root",
        action="append",
        default=[],
        metavar="DIR",
        required=True,
        help="directory to vendor modules from (repeatable). Only modules under a "
        "--root are inlined; stdlib/third-party imports are left as-is.",
    )
    p.add_argument(
        "-o", "--output", metavar="OUT",
        help="output path (default: <payload stem>.bundle.py)",
    )
    p.add_argument(
        "--strip-comments", action=argparse.BooleanOptionalAction, default=True,
        dest="strip_comments",
        help="Remove all # comments and docstrings from inlined module sources. "
        "ON by default; pass --no-strip-comments to disable.",
    )
    p.add_argument(
        "--minify", action="store_true",
        help="run python-minifier over the flattened output (safe; biggest easy win)",
    )
    p.add_argument(
        "--include-module", action="append", default=[], metavar="NAME", dest="include_modules",
        help="force-vendor a module invisible to static analysis (dynamic imports); "
        "repeatable. Must resolve under a --root.",
    )
    p.add_argument(
        "--experimental-treeshake", action=argparse.BooleanOptionalAction, default=True,
        dest="experimental_treeshake",
        help="UNSAFE: drop top-level functions/classes that appear unreferenced "
        "bundle-wide. ON by default; pass --no-experimental-treeshake to disable. "
        "Validate with your test suite against the bundle.",
    )
    p.add_argument(
        "--var", action="append", default=[], metavar="NAME=VALUE", dest="vars",
        help="inject a global variable into the output before all other code; "
        "VALUE is a Python expression (e.g. --var DEBUG=True --var TIMEOUT=30 "
        '--var API_URL=\\"https://example.com\\"). Repeatable.',
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)

    payload = Path(args.payload)
    if not payload.is_file():
        print(f"bundle: payload not found: {payload}", file=sys.stderr)
        return 2

    global_vars: dict[str, str] = {}
    for entry in args.vars:
        if "=" not in entry:
            print(f"bundle: --var must be NAME=VALUE, got: {entry!r}", file=sys.stderr)
            return 2
        name, _, value = entry.partition("=")
        name = name.strip()
        if not name.isidentifier():
            print(f"bundle: --var name is not a valid identifier: {name!r}", file=sys.stderr)
            return 2
        try:
            ast.parse(value, mode="eval")
        except SyntaxError:
            value = repr(value)
        global_vars[name] = value

    output = Path(args.output) if args.output else payload.with_suffix("").with_name(
        payload.stem + ".bundle.py"
    )

    options = BuildOptions(
        roots=args.root,
        include_modules=args.include_modules,
        compression=CompressionOptions(
            strip_comments=args.strip_comments,
        ),
        minify=args.minify,
        experimental_treeshake=args.experimental_treeshake,
        global_vars=global_vars,
    )

    try:
        result = build(payload, options)
    except BundlerError as exc:
        print(f"bundle: error: {exc}", file=sys.stderr)
        return 1

    output.write_text(result.text, encoding="utf-8")

    for warning in result.warnings:
        print(f"bundle: warning: {warning}", file=sys.stderr)
    if result.removed_symbols:
        print(
            f"bundle: tree-shake removed {len(result.removed_symbols)} symbol(s): "
            + ", ".join(result.removed_symbols),
            file=sys.stderr,
        )

    size = len(result.text.encode("utf-8"))
    print(
        f"bundle: wrote {output} ({len(result.module_names)} modules, {size:,} bytes)",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
