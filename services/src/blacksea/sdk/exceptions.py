"""SDK exceptions raised across the build / interpret boundary.

These are the only exception types the framework expects a BoobyBait author to
raise or catch by name. See src/blacksea/sdk/context.md.
"""


class BodyDecodeError(Exception):
    """Raised by ``BoobyBait.decode_body()`` when body bytes are completely
    uninterpretable (wrong magic bytes, incompatible body version).

    ``interpret()`` catches this and returns a degraded ``AnalyzerOutput``
    (event_type="signal_only" + an ``_decode_error`` meta-key). It must **not**
    be raised for merely truncated / partially-corrupt input — ``decode_body()``
    must return a best-effort dict in that case.
    """


class BuildError(Exception):
    """Raised by ``BuildContext.run()`` on a non-zero subprocess exit during
    the build-orchestration flow (see control_plane/context.md). A build step
    that lets this propagate fails staging; the registry record stays ``draft``.
    """
