package main

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// receiver_dns.go — the DNS thin-form receiver (§1.5 DNS projection, modes 1–3).
//
// A beacon name is `<base32(header ‖ payload)>[.<base32(overflow)>...].<canary-zone>`. Each data
// label (everything left of the configured zone) is base32-decoded independently and the bytes
// are concatenated (§1.5 modes 1–2 — all labels of one query are decoded before the dot-zone
// boundary). The first 19 bytes are the mandatory header:
//
//	[ev:4 | flags:4](1B) ‖ instance_token(8B) ‖ session_id(8B) ‖ seq_no(2B)  = 19 B
//
// channel is `dns` (tier 0 — DNS is the sole tier-0 channel). bait_id/campaign_id are NOT derived
// here: the edge holds no directory; the brain resolves them from instance_token against its own
// key directory (inv 13/18). Tier 0 is unsigned by definition (§1.3): it rides the inv-6
// rate-limit + sample gate and is never fully persisted by itself.
//
// Mode 3 (DNS sequence across multiple queries) reassembly is deliberately NOT done at the edge:
// the edge stays stateless (inv 3) and forwards each chunk with its (instance_token, session_id,
// seq_no, LAST-flag, payload). The brain reassembles using the §1.8 dedup tuple — it already
// holds that state. See context.md "DNS sequence reassembly" note.
//
// On DNS the observed source is the recursive RESOLVER, not the attacker's client (§1.9-b) — so
// source_type is "resolver" and the brain weights it below an HTTPS client IP.

const dnsHeaderLen = 19 // [ev|flags](1) + instance_token(8) + session_id(8) + seq_no(2)

const dnsFlagLast = 0x1 // flags bit 0: LAST chunk of a DNS sequence (§1.5 mode 3)

const dnsSinkTTLSeconds = 60 // TTL on the sink A-record answer so beacons resolve but don't cache long

// b32 is the DNS label codec: RFC 4648 base32, no padding (the SDK strips '=' and lowercases;
// we upper-case on read since StdEncoding's alphabet is upper-case). Case-insensitive per §1.5.
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// dnsHandler returns a miekg/dns handler bound to the edge's dependencies. It is authoritative
// for the configured canary zone(s); queries outside them are REFUSED.
func (e *Edge) dnsHandler() dns.HandlerFunc {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true

		srcIP := dnsSourceIP(w.RemoteAddr())

		if len(req.Question) == 0 {
			resp.Rcode = dns.RcodeFormatError
			_ = w.WriteMsg(resp)
			return
		}
		q := req.Question[0]
		qname := strings.ToLower(q.Name)

		zone, ok := e.matchZone(qname)
		if !ok {
			resp.Rcode = dns.RcodeRefused
			_ = w.WriteMsg(resp)
			return
		}

		// (1) Rate limit before parsing the labels.
		if !e.limiter.Allow(srcIP) {
			edgeMetrics.add("dns_ratelimited", 1)
			e.answerSink(w, resp, q)
			return
		}

		// Parse + (on success) publish. We answer with a benign sink record regardless, so the
		// beacon looks like an ordinary resolution and the sensor learns nothing about acceptance.
		if env := e.parseDNS(qname, zone, srcIP); env != nil {
			// (inv 6) tier-0 sample gate: pass only 1-in-N.
			if e.sampler.Keep() {
				edgeMetrics.add("dns_accepted", 1)
				e.publish(env, srcIP)
			} else {
				edgeMetrics.add("dns_sampled_out", 1)
			}
		}

		e.answerSink(w, resp, q)
	}
}

// parseDNS decodes the data labels of qname (zone already matched + stripped) into a tier-0
// QueuedEnvelope, deriving the routing/compartment fields from the directory. Returns nil if the
// name is malformed or too short to carry the mandatory header.
func (e *Edge) parseDNS(qname, zone, srcIP string) *QueuedEnvelope {
	dataPart := strings.TrimSuffix(qname, "."+zone)
	dataPart = strings.TrimSuffix(dataPart, ".") // tolerate trailing dot edge cases
	if dataPart == "" || dataPart == qname {
		edgeMetrics.add("dns_no_data_labels", 1)
		return nil
	}

	// Decode each data label independently, concatenating the raw bytes (§1.5 modes 1–2).
	var buf []byte
	for _, label := range strings.Split(dataPart, ".") {
		if label == "" {
			edgeMetrics.add("dns_empty_label", 1)
			return nil
		}
		dec, err := b32.DecodeString(strings.ToUpper(label))
		if err != nil {
			edgeMetrics.add("dns_b32_err", 1)
			return nil
		}
		buf = append(buf, dec...)
	}

	if len(buf) < dnsHeaderLen {
		edgeMetrics.add("dns_short_header", 1)
		return nil
	}

	// [ev:4 | flags:4] ‖ instance_token(8) ‖ session_id(8) ‖ seq_no(2)
	ev := buf[0] >> 4
	flags := buf[0] & 0x0f
	var tok [8]byte
	copy(tok[:], buf[1:9])
	sessionID := buf[9:17]
	seqNo := binary.BigEndian.Uint16(buf[17:19])
	payload := buf[dnsHeaderLen:] // ≤ 20 B (mode 1) or more across labels (mode 2)

	if !e.knownEV[ev] {
		edgeMetrics.add("dns_unknown_ev", 1)
		slog.Debug("dns unknown ev", "ev", ev, "src", srcIP)
		return nil
	}

	// Forward the parsed thin-form fields + the edge stamp. The edge holds no directory: it does
	// NOT look tok up, derive bait_id/campaign_id/status, or check validity windows — the brain
	// resolves all routing from tok against its own key directory (inv 13/18). Every well-formed
	// beacon is forwarded; the brain decides routable vs orphan.
	seq := seqNo
	out := &QueuedEnvelope{
		EV:            ev,
		Channel:       channelDNS,
		InstanceToken: hex.EncodeToString(tok[:]),
		SessionID:     hex.EncodeToString(sessionID),
		SeqNo:         &seq,
		Flags:         flags,
		Edge: EdgeStamp{
			RecvTime: time.Now().UnixMilli(),
			Source:   ObservedSource{IP: srcIP, SourceType: sourceTypeResolver},
			EdgeID:   e.edgeID,
		},
	}
	if len(payload) > 0 {
		out.ObsBody = base64.StdEncoding.EncodeToString(payload)
	}
	return out
}

// matchZone returns the matching configured canary zone (without leading dot, with trailing dot)
// for qname, and whether one matched. Zones are stored fully-qualified + lower-cased.
func (e *Edge) matchZone(qname string) (string, bool) {
	for _, z := range e.zones {
		if qname == z {
			// Query for the bare zone — no data labels; not a beacon.
			return z, true
		}
		if strings.HasSuffix(qname, "."+z) {
			return z, true
		}
	}
	return "", false
}

// answerSink writes a benign response so the beacon resolves like any other name. For an A query
// it returns the configured sink IP; otherwise NOERROR with no answer. The DNS exfil channel only
// needs the query to LEAVE the attacker network — the answer is irrelevant to the sensor.
func (e *Edge) answerSink(w dns.ResponseWriter, resp *dns.Msg, q dns.Question) {
	if q.Qtype == dns.TypeA && e.dnsSinkIP != nil {
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: dnsSinkTTLSeconds},
			A:   e.dnsSinkIP,
		})
	}
	_ = w.WriteMsg(resp)
}

// dnsSourceIP extracts the IP from a DNS client address (UDP or TCP).
func dnsSourceIP(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP.String()
	case *net.TCPAddr:
		return a.IP.String()
	default:
		host, _, err := net.SplitHostPort(addr.String())
		if err != nil {
			return addr.String()
		}
		return host
	}
}
