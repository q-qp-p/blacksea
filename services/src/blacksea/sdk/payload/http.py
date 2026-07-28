import urllib.request as _req


def send_http(url: str, data: bytes, headers: dict | None = None) -> None:
    """POST data to url with optional headers.

    Swallows all errors — a payload must never crash on a failed callback.
    """
    try:
        req = _req.Request(url, data=data, method="POST")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        _req.urlopen(req, timeout=10)
    except Exception:
        pass


def send_https_encrypted(
    url: str,
    body: bytes,
    key_hex: str,
    instance_token_hex: str,
    *,
    session_id: bytes | None = None,
    seq_no: int = 0,
) -> None:
    """Build a tier-2 encrypted envelope and POST it to the edge URL.

    bait_id, campaign_id, channel are never transmitted — the brain derives
    them from instance_token_hex via its key directory.
    """
    from blacksea.sdk.payload.envelope import build_encrypted_envelope
    try:
        envelope_bytes = build_encrypted_envelope(
            body, key_hex, instance_token_hex,
            session_id=session_id, seq_no=seq_no,
        )
        send_http(url, envelope_bytes, headers={"Content-Type": "application/json"})
    except Exception:
        pass
