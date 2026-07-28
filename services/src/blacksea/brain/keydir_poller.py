"""brain.keydir_poller — hot-reload for the brain's key directory, the SOLE key directory now
that the edge is a dumb dead-drop (see src/blacksea/brain/context.md).

An atomic full-replace of an immutable directory object, never a partial/in-place mutation, and
never-fail-open on a bad poll (keep serving the last-good directory). `brain_keydir.json` never
crosses the edge-facing diode, so no signing/anti-rollback/pinned-key threat model applies to it —
ordinary server-side access control suffices. This is a plain stat/read/parse/swap on an interval.

asyncio is single-threaded, so reassigning `KeyDirectoryHolder.current` is atomic with respect to
concurrently-scheduled coroutines — no lock is needed as long as the KeyDirectory itself is never
mutated in place (it isn't; `KeyDirectory` has no mutating methods).
"""

from __future__ import annotations

import asyncio
import logging

from blacksea.brain.verifier import KeyDirectory

log = logging.getLogger(__name__)


class KeyDirectoryHolder:
    """Holds the live `KeyDirectory`; the poll loop swaps `.current` wholesale.

    Readers (e.g. `pool._handle`) should read `.current` fresh for each message rather than
    capturing it once, so they observe swaps made after they started running.
    """

    def __init__(self, initial: KeyDirectory) -> None:
        self.current = initial


async def poll_keydir(holder: KeyDirectoryHolder, path: str, interval_s: float) -> None:
    """Re-read `path` every `interval_s` seconds and hot-swap `holder.current`.

    Runs until cancelled. On any read/parse failure the last-good directory is kept and the
    failure is logged — a bad or momentarily-missing file must not blind the brain to every
    previously-known instance (never fail open, matching the edge's poller policy, §5.5).
    """
    while True:
        await asyncio.sleep(interval_s)
        try:
            new_dir = KeyDirectory.from_file(path)
        except Exception:
            log.exception(
                "brain keydir poll failed for %r — keeping last-good directory", path
            )
            continue
        if new_dir != holder.current:
            log.info("brain keydir reloaded from %r (%d entries)", path, len(new_dir))
        holder.current = new_dir
