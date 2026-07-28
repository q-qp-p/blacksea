package main

// envelope.go — logical envelope types and the edge-group stamp logic.
//
// The edge is a dumb dead-drop (inv 3): it parses only the routing-critical header, treats `enc`
// and the DNS payload as opaque bytes, appends the `edge` group OUTSIDE any signature (inv 17) so
// a popped sensor cannot forge its own source IP or our receive clock, and forwards. It holds NO
// key directory and derives NO routing/status/tier — the brain resolves all of that from `tok`
// against its own (sole) key directory (see src/blacksea/brain/context.md).
//
// Two physical projections feed this module — HTTPS JSON (fat form) and DNS base32 (thin form).
// Both are normalised into a single QueuedEnvelope before publishing, which the brain consumes
// off the queue, resolves routing for, and (for tier≥1) decrypts (inv 13).

// Channel enum strings (§1.1 `channel`). Kept as strings to match the SDK side
// (blacksea/sdk types: "dns" | "https" | ...). The channel is edge-stamped and authoritative —
// it is the brain's tier-0-vs-tier≥1 signal (DNS is the sole tier-0 channel).
const (
	channelDNS   = "dns"
	channelHTTPS = "https"
)

// observed_source.source_type values. On DNS the observed source is the recursive resolver, not
// the attacker's client (§1.9-b) — flagged here so the brain can weight it below an HTTPS client IP.
const (
	sourceTypeClient   = "client"   // HTTPS/TCP — true client IP
	sourceTypeResolver = "resolver" // DNS — recursive resolver IP (weaker-observed)
)

// ObservedSource is the edge-stamped, observed-tier source struct (§1.1 `observed_source`).
type ObservedSource struct {
	IP         string `json:"ip"`
	JA3        string `json:"ja3,omitempty"` // TLS fingerprint; empty/absent for DNS (non-TLS)
	SourceType string `json:"source_type"`   // "client" | "resolver"
}

// EdgeStamp is the `edge` group (§1.1): appended outside the signature, observed-tier, trusted.
// This is the edge's irreducible contribution — the only observed-tier facts in the whole record,
// unreconstructable downstream since the brain never sees the network hop.
type EdgeStamp struct {
	RecvTime int64          `json:"recv_time"` // edge-stamped receive time, ms (inv 17)
	Source   ObservedSource `json:"source"`
	EdgeID   string         `json:"edge_id"` // which edge node received (provenance)
}

// QueuedEnvelope is the normalised logical record the edge publishes to the single ingest subject.
//
// It is NOT one of the locked wire projections (those are sensor→edge, §1.5). It is the
// edge→brain hand-off: the outer `tok`, the opaque `enc` material (forwarded verbatim for the
// brain to decrypt, §1.7), the DNS-derived tier-0 per-hit fields, and the `edge` group. The edge
// no longer carries bait_id/campaign_id/assurance_tier/status/orphan — it holds no directory to
// derive them from; the brain resolves them from `tok` (see verifier.bait_id_for / verify).
//
// Field presence by channel:
//   - HTTPS (tier ≥ 1): Enc carries the encrypted-core opaquely; SessionID/SeqNo/ObsBody absent.
//   - DNS (tier 0, the sole tier-0 channel): no Enc; SessionID, SeqNo, Flags, ObsBody carry the
//     unencrypted, observed-tier per-hit data parsed from the base32 labels.
type QueuedEnvelope struct {
	EV      uint8  `json:"ev"`      // envelope_version (§1.6)
	Channel string `json:"channel"` // transport used (edge-stamped, authoritative; brain's tier signal)
	// The outer instance_token (8 B hex). The edge forwards it verbatim; the brain resolves all
	// routing from it against its own key directory. It is the only cleartext routing field.
	InstanceToken string `json:"instance_token"`

	// Opaque encrypted material — HTTPS (tier ≥ 1) only. Forwarded verbatim; the brain decrypts it
	// against its own key directory (inv 13, §5.11) — the edge has no key to do so itself.
	Enc string `json:"enc,omitempty"` // base64url(nonce || HMAC-SHA256 AEAD ciphertext || tag)

	// Tier-0 per-hit fields — unencrypted, observed-tier; populated from the DNS base32 labels
	// (DNS is the sole tier-0 channel).
	SessionID string  `json:"session_id,omitempty"` // 8 B hex
	SeqNo     *uint16 `json:"seq_no,omitempty"`     // event order; 0 = single-shot tripwire
	Flags     uint8   `json:"flags,omitempty"`      // DNS pack byte-0 low nibble (LAST bit etc.)
	ObsBody   string  `json:"obs_body,omitempty"`   // base64(raw observed payload bytes); untrusted

	// Edge group — observed-tier, appended outside the encrypted core (§1.4).
	Edge EdgeStamp `json:"edge"`
}
