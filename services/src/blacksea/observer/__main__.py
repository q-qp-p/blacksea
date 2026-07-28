"""Entry point: python -m blacksea.observer [--host HOST] [--port PORT]

Environment variables:
  BS_REGISTRY   — filesystem root that parents the material store artifacts/ (default: registry)
  POSTGRES_DSN  — libpq DSN for the design/instance catalog and the event store (D2); omit to
                  run with baits, instances, and events all returned empty
"""

from __future__ import annotations

import argparse

import uvicorn

from blacksea.config import settings

from .api import make_app


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Blacksea Observer — read-only web UI for manual testing"
    )
    parser.add_argument("--host", default=settings.OBSERVER_HOST,
                        help="bind address (default 127.0.0.1 or $OBSERVER_HOST)")
    parser.add_argument("--port", type=int, default=settings.OBSERVER_PORT,
                        help="listen port (default 8000 or $OBSERVER_PORT)")
    args = parser.parse_args()

    app = make_app(settings.BS_REGISTRY, settings.POSTGRES_DSN)
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
