"""envfile.py — resolve a Postgres DSN from the project's `secrets/env`, for dev convenience.

Anything the console does against the database needs a DSN. Under `make`, the Makefile assembles
it from `secrets/env` (`POSTGRES_PASSWORD` + the docker-compose coordinates) and exports it; a bare
`blacksea` in a plain activated shell has neither. So when no DSN is supplied explicitly
(`--postgres`) and none is in the environment (`$POSTGRES_DSN`), the console falls back to reading
`secrets/env` (dotenv-style) and building the same dev DSN `make` uses.

**Dev convenience, inert in production:** it only fires when nothing else provides a DSN, and a real
deployment sets `POSTGRES_DSN` (or passes `--postgres`), so the fallback never triggers. Precedence
is always ``--postgres`` > ``$POSTGRES_DSN`` > ``secrets/env``. No click/rich here.
"""

from __future__ import annotations

import os

from blacksea.config import envload, settings


def read_env_file(path: str) -> dict[str, str]:
    """Parse a dotenv-style file into a dict (delegates to the canonical
    :func:`blacksea.config.envload.parse_env_file`). A missing/unreadable file is an empty dict."""
    return envload.parse_env_file(path)


def find_secrets_file(explicit: str | None, start: str | None = None) -> str | None:
    """Locate the secrets env file. If ``explicit`` is given, use it (or ``None`` if absent);
    otherwise search for ``secrets/env`` from ``start`` (default CWD) upward a few levels — so it
    resolves whether the console is run from ``services/`` or a subdirectory."""
    if explicit:
        return explicit if os.path.exists(explicit) else None
    directory = os.path.abspath(start or os.getcwd())
    for _ in range(5):  # CWD + up to 4 parents
        candidate = os.path.join(directory, "secrets", "env")
        if os.path.exists(candidate):
            return candidate
        parent = os.path.dirname(directory)
        if parent == directory:
            break
        directory = parent
    return None


def dsn_from_env(env: dict[str, str]) -> str:
    """Build a DSN from a parsed env dict: a full ``POSTGRES_DSN`` wins; else assemble from
    ``POSTGRES_PASSWORD`` + the dev coordinates (via the canonical
    :func:`blacksea.config.envload.dsn_from_coords`, the single source of the coordinate defaults).
    ``""`` if neither is present."""
    if env.get("POSTGRES_DSN"):
        return env["POSTGRES_DSN"]
    return envload.dsn_from_coords(env) or ""


def resolve_postgres_dsn(
    cli_value: str | None, secrets_path: str | None, *, start: str | None = None
) -> tuple[str, str | None]:
    """Resolve the effective DSN and where it came from.

    Returns ``(dsn, source)`` where ``source`` is ``None`` for an explicit flag / env value, or the
    path of the ``secrets/env`` it was read from. Precedence: ``--postgres`` > ``$POSTGRES_DSN`` >
    ``secrets/env``. ``dsn`` is ``""`` when nothing provides one (the caller reports it as unset)."""
    if cli_value is not None:
        return cli_value, None
    if settings.POSTGRES_DSN:
        return settings.POSTGRES_DSN, None
    found = find_secrets_file(secrets_path, start=start)
    if found:
        dsn = dsn_from_env(read_env_file(found))
        if dsn:
            return dsn, found
    return "", None
