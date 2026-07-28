package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// receiver_https.go — the HTTPS/TCP fat-form receiver (§1.5 HTTPS projection).
//
// Flow per request (the dumb dead-drop contract, inv 3):
//   1. hard size cap + rate limit BEFORE parsing (§1.7 step 2).
//   2. parse ONLY the top-level tok + the opaque enc (never the body); drop empty-enc / bad shape.
//   3. forward enc opaquely — the edge holds no key and never decrypts (§1.4/§1.7). The brain is
//      the sole decryptor (inv 13) and resolves all routing from tok.
//   4. stamp the edge group (§1.7 step 5) and publish to the single ingest subject.
//
// The edge holds no directory: it does NOT look up tok, derive bait_id/campaign_id/tier/status,
// or check validity windows — the brain does all of that authoritatively (inv 13/18).
//
// The handler always returns 204 regardless of outcome: the edge gives a hostile sensor no
// signal about acceptance, decryption, or routing (it never had a verdict to leak — inv 13).

// httpsEnvelope is exactly what a sensor sends (everything EXCEPT the edge group, §1.5).
//
// Post-HMAC migration (2026-07-14) HTTPS carries exactly one shape — the encrypted
// {ev, tok, enc} form, tier ≥ 1, with `enc` opaque to the edge. The old plaintext tier-0
// fallback {ev, tok, sid, seq, body} was removed: DNS is now the sole tier-0 channel, so an
// HTTPS request with no `enc` is not a legitimate shape and the handler drops it.
//
// bait_id, campaign_id, channel, assurance_tier are never transmitted, and the edge no longer
// derives them: the brain resolves them from tok against its own key directory (§1.2/§5.11).
type httpsEnvelope struct {
	EV  uint8  `json:"ev"`
	Tok string `json:"tok"` // 8 B hex instance_token (16 chars); only cleartext routing hint
	Enc string `json:"enc"` // base64url(nonce || HMAC-SHA256 AEAD ciphertext || tag); opaque to edge
}

// httpsHandler returns an http.HandlerFunc bound to the edge's dependencies.
func (e *Edge) httpsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Always answer the same way; never leak processing outcome to the sensor.
		defer func() { w.WriteHeader(http.StatusNoContent) }()

		if r.Method != http.MethodPost {
			return
		}

		srcIP := e.clientIP(r)

		// (1) Rate limit before touching the body.
		if !e.limiter.Allow(srcIP) {
			edgeMetrics.add("https_ratelimited", 1)
			return
		}

		// (1) Hard size cap before parse — MaxBytesReader aborts the read past the limit.
		r.Body = http.MaxBytesReader(w, r.Body, e.maxBodyBytes)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			edgeMetrics.add("https_oversize_or_read_err", 1)
			return
		}

		// (2) Parse only the envelope wrapper. enc/body stay opaque.
		var env httpsEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			edgeMetrics.add("https_parse_err", 1)
			return
		}
		if !e.knownEV[env.EV] {
			// Unknown-but-newer ev: the edge does not interpret; it would normally pass through
			// for the brain (§1.6). We accept only the versions in knownEV ({1,2}), so log + drop
			// anything else to keep the surface tight.
			edgeMetrics.add("https_unknown_ev", 1)
			slog.Debug("https unknown ev", "ev", env.EV, "src", srcIP)
			return
		}

		// HTTPS is always tier ≥ 1 / encrypted post-HMAC migration (§1.4). A missing `enc` is not a
		// legitimate shape (the plaintext tier-0 fallback was removed) — drop it rather than forward
		// an empty ciphertext the brain can only dead-letter. This also closes the injection vector
		// where a `tok` sniffer POSTs attacker-chosen {tok,sid,seq,body} to mint tier-0 records.
		if env.Enc == "" {
			edgeMetrics.add("https_missing_enc", 1)
			return
		}

		// (3) Validate the token shape (cheap junk rejection). The edge forwards the hex verbatim;
		// it never looks tok up (it holds no directory) — the brain resolves routing from it.
		if _, err := decodeToken(env.Tok); err != nil {
			edgeMetrics.add("https_bad_token", 1)
			return
		}

		// (4) Forward `enc` opaquely + stamp the edge group. No directory lookup, no routing/tier/
		// status derivation, no validity-window check — all of that is the brain's job now.
		out := &QueuedEnvelope{
			EV:            env.EV,
			Channel:       channelHTTPS,
			InstanceToken: env.Tok,
			Enc:           env.Enc,
			Edge: EdgeStamp{
				RecvTime: time.Now().UnixMilli(),
				Source:   ObservedSource{IP: srcIP, SourceType: sourceTypeClient},
				EdgeID:   e.edgeID,
			},
		}
		edgeMetrics.add("https_accepted", 1)
		e.publish(out, srcIP)
	}
}

// decodeToken parses an 8-byte instance_token from its 16-char hex form (§1.1 wire type 8 B). The
// edge uses it only to reject a malformed token; it forwards the original hex string, not the bytes.
func decodeToken(hexTok string) ([8]byte, error) {
	var tok [8]byte
	b, err := hex.DecodeString(hexTok)
	if err != nil {
		return tok, fmt.Errorf("not hex: %w", err)
	}
	if len(b) != 8 {
		return tok, fmt.Errorf("instance_token must be 8 bytes, got %d", len(b))
	}
	copy(tok[:], b)
	return tok, nil
}

// clientIP extracts the source IP from the request, honouring X-Forwarded-For only when the edge
// is configured to trust an upstream proxy (default: false — the edge is internet-facing, §inv2).
func (e *Edge) clientIP(r *http.Request) string {
	if e.trustForwardedFor {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// First hop is the client.
			if i := strings.IndexByte(xff, ','); i >= 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
