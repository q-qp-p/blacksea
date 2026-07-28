"""keydir_poller.py — hot-reload for the brain's own key directory.

Locks what was previously an open gap: a running brain must converge on
brain_keydir.json changes (build/approve/revoke) without a process restart.
See brain/context.md's key-directory section for the contract.
"""

from __future__ import annotations

import asyncio
import json

from blacksea.brain.keydir_poller import KeyDirectoryHolder, poll_keydir
from blacksea.brain.verifier import KeyDirectory, VerificationError, verify

from _helpers import encrypted_https_envelope, gen_key


def _entry(tok_hex: str, key: bytes) -> dict:
    return {
        "instance_token": tok_hex,
        "key": key.hex(),
        "status": "active",
        "bait_id": "hostname-probe",
        "campaign_id": "camp-1",
        "assurance_tier": 2,
        "default_channel": "https",
        "valid_from": 0,
        "valid_until": None,
    }


async def _run_briefly_then_cancel(holder, path, interval_s, body_coro):
    poll_task = asyncio.create_task(poll_keydir(holder, path, interval_s))
    try:
        await body_coro
    finally:
        poll_task.cancel()
        try:
            await poll_task
        except asyncio.CancelledError:
            pass


def test_poll_keydir_hot_swaps_on_file_rewrite(tmp_path):
    """A new instance written to disk (e.g. by `build`) becomes decryptable without
    recreating the pool process — verify() succeeds against the new token after one poll."""
    path = tmp_path / "brain_keydir.json"
    old_tok, old_key = "1111111111111111", gen_key()
    new_tok, new_key = "2222222222222222", gen_key()
    path.write_text(json.dumps([_entry(old_tok, old_key)]))

    holder = KeyDirectoryHolder(KeyDirectory.from_file(str(path)))
    queued = encrypted_https_envelope(new_key, instance_token=new_tok)

    async def _body():
        try:
            verify(queued, holder.current)
            assert False, "new instance_token should not be recognized before the rewrite"
        except VerificationError:
            pass

        path.write_text(json.dumps([_entry(old_tok, old_key), _entry(new_tok, new_key)]))
        await asyncio.sleep(0.2)

        env, body, sig_valid = verify(queued, holder.current)
        assert sig_valid is True
        assert body == b'{"hostname":"victim-box"}'
        assert env.bait_id == "hostname-probe"
        # Full replace, not additive — the pre-existing entry survives because the rewritten
        # file re-included it, not because the poller merged in the new one.
        assert holder.current.lookup(bytes.fromhex(old_tok)) is not None

    asyncio.run(_run_briefly_then_cancel(holder, str(path), 0.05, _body()))


def test_poll_keydir_keeps_last_good_on_parse_failure(tmp_path):
    """A malformed on-disk file must not blind the brain to instances it already knew about
    (never fail open, mirroring the edge poller's policy — but for parse/structural failures,
    not a missing file, which KeyDirectory.from_file already treats as a valid empty state)."""
    path = tmp_path / "brain_keydir.json"
    tok, key = "3333333333333333", gen_key()
    path.write_text(json.dumps([_entry(tok, key)]))

    holder = KeyDirectoryHolder(KeyDirectory.from_file(str(path)))

    async def _body():
        path.write_text("{not valid json")
        await asyncio.sleep(0.2)

        entry = holder.current.lookup(bytes.fromhex(tok))
        assert entry is not None
        assert entry.key_bytes == key

    asyncio.run(_run_briefly_then_cancel(holder, str(path), 0.05, _body()))
