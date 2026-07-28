"""Hostname-beacon listener.

Interprets HTTP beacon hits from payload.py. The body is a JSON object
containing the attacker host's name and instance token.
"""

from __future__ import annotations

import json

from blacksea.sdk.listener import (
    AnalyzerOutput,
    BodyDecodeError,
    Envelope,
    GoldenCase,
    Listener,
    test_envelope,
)


class HostnameBeaconListener(Listener):

    def encode_body(self, data: dict) -> bytes:
        return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()

    def decode_body(self, body: bytes) -> dict:
        try:
            return json.loads(body.decode())
        except Exception as exc:
            raise BodyDecodeError(str(exc))

    def interpret(self, envelope: Envelope, body: bytes) -> AnalyzerOutput:
        if not body:
            return AnalyzerOutput(event_type="signal_only")
        try:
            data = self.decode_body(body)
        except BodyDecodeError as exc:
            return AnalyzerOutput(
                event_type="signal_only", details={"_decode_error": str(exc)}
            )
        return AnalyzerOutput(
            event_type="payload_exec_collect",
            details={"hostname": data.get("hostname")},
        )

    def golden_cases(self) -> list[GoldenCase]:
        return [
            GoldenCase(
                label="normal hit — hostname collected",
                body=self.encode_body({"hostname": "victim-box", "token": "aabbccdd"}),
                envelope=test_envelope(tier=2, bait_id="hostname-beacon"),
                expected=AnalyzerOutput(
                    event_type="payload_exec_collect",
                    details={"hostname": "victim-box"},
                ),
            ),
            GoldenCase(
                label="signal-only (zero body, tier 0)",
                body=b"",
                envelope=test_envelope(tier=0, bait_id="hostname-beacon"),
                expected=AnalyzerOutput(event_type="signal_only"),
            ),
        ]
