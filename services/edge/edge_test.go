package main

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// --- test doubles ------------------------------------------------------------------------

// fakePublisher captures published messages instead of talking to NATS.
type fakePublisher struct {
	mu   sync.Mutex
	msgs []captured
	err  error // if set, Publish returns it
}

type captured struct {
	subject string
	env     QueuedEnvelope
}

func (f *fakePublisher) Publish(subject string, data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	var env QueuedEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return err
	}
	f.msgs = append(f.msgs, captured{subject: subject, env: env})
	return nil
}
func (f *fakePublisher) Close() {}
func (f *fakePublisher) last() captured {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.msgs) == 0 {
		return captured{}
	}
	return f.msgs[len(f.msgs)-1]
}
func (f *fakePublisher) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.msgs)
}

// fakeDNSWriter implements dns.ResponseWriter, capturing the response message.
type fakeDNSWriter struct {
	remote net.Addr
	msg    *dns.Msg
}

func (w *fakeDNSWriter) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}
func (w *fakeDNSWriter) RemoteAddr() net.Addr        { return w.remote }
func (w *fakeDNSWriter) WriteMsg(m *dns.Msg) error   { w.msg = m; return nil }
func (w *fakeDNSWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *fakeDNSWriter) Close() error                { return nil }
func (w *fakeDNSWriter) TsigStatus() error           { return nil }
func (w *fakeDNSWriter) TsigTimersOnly(bool)         {}
func (w *fakeDNSWriter) Hijack()                     {}

// --- fixtures ----------------------------------------------------------------------------

const testZone = "c.example.com."

func testToken() [8]byte {
	return [8]byte{0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65}
}

func testTokenHex() string {
	tok := testToken()
	return hex.EncodeToString(tok[:])
}

// newTestEdge builds a dead-drop Edge wired with a fake publisher. The edge holds no key
// directory: it parses, stamps, rate-limits, and forwards every well-formed hit — the brain
// resolves all routing from `tok` (inv 3/13/18).
func newTestEdge(t *testing.T) (*Edge, *fakePublisher) {
	t.Helper()
	fp := &fakePublisher{}
	edge := &Edge{
		edgeID:       "edge-test",
		limiter:      NewRateLimiter(RateLimitConfig{GlobalRate: 1e6, GlobalBurst: 1e6, PerSrcRate: 1e6, PerSrcBurst: 1e6}),
		sampler:      NewSampler(1),
		pub:          fp,
		knownEV:      map[uint8]bool{1: true},
		maxBodyBytes: 65536,
		zones:        []string{testZone},
		dnsSinkIP:    net.ParseIP("0.0.0.0"),
	}
	return edge, fp
}

// --- HTTPS: the dead-drop exit criterion --------------------------------------------------

func TestHTTPS_EncryptedForwards_And_Queues(t *testing.T) {
	edge, fp := newTestEdge(t)

	// enc is opaque to the edge (the HMAC-SHA256 AEAD is the brain's concern, §1.4/§1.7). The edge
	// must forward it verbatim without attempting to decrypt or verify anything.
	enc := base64.RawURLEncoding.EncodeToString([]byte("opaque-nonce-ciphertext-tag-bytes"))

	body, _ := json.Marshal(httpsEnvelope{EV: 1, Tok: testTokenHex(), Enc: enc})

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
	req.RemoteAddr = "203.0.113.7:54321"
	rr := httptest.NewRecorder()
	edge.httpsHandler()(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rr.Code)
	}
	if fp.count() != 1 {
		t.Fatalf("published %d messages, want 1", fp.count())
	}
	got := fp.last()
	// Every hit goes to the single ingest subject — the edge no longer computes a per-bait subject.
	if got.subject != ingestSubject {
		t.Errorf("subject = %q, want %q", got.subject, ingestSubject)
	}
	if got.env.Channel != channelHTTPS {
		t.Errorf("channel = %q, want https", got.env.Channel)
	}
	if got.env.InstanceToken != testTokenHex() {
		t.Errorf("instance_token = %q, want %q", got.env.InstanceToken, testTokenHex())
	}
	if got.env.Enc != enc {
		t.Errorf("enc blob not forwarded verbatim")
	}
	// Edge group present + correct (observed-tier, §1.7 step 5) — the edge's irreducible contribution.
	if got.env.Edge.Source.IP != "203.0.113.7" {
		t.Errorf("observed source ip = %q, want 203.0.113.7", got.env.Edge.Source.IP)
	}
	if got.env.Edge.Source.SourceType != sourceTypeClient {
		t.Errorf("source_type = %q, want client", got.env.Edge.Source.SourceType)
	}
	if got.env.Edge.EdgeID != "edge-test" {
		t.Errorf("edge_id = %q, want edge-test", got.env.Edge.EdgeID)
	}
	if got.env.Edge.RecvTime == 0 {
		t.Errorf("recv_time not stamped")
	}
}

func TestHTTPS_GarbageEnc_StillForwarded(t *testing.T) {
	// The edge cannot tell a garbage enc from a legitimate one — it has no key (§1.7). It must
	// still forward the hit; the brain rejects it on decryption failure.
	edge, fp := newTestEdge(t)

	body, _ := json.Marshal(httpsEnvelope{
		EV:  1,
		Tok: testTokenHex(),
		Enc: base64.RawURLEncoding.EncodeToString([]byte("not-a-real-ciphertext")),
	})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
	req.RemoteAddr = "203.0.113.7:1"
	rr := httptest.NewRecorder()
	edge.httpsHandler()(rr, req)

	if fp.count() != 1 {
		t.Fatalf("garbage-enc hit was dropped at the edge (%d msgs), want 1 (brain rejects it, not the edge)", fp.count())
	}
}

func TestHTTPS_AnyToken_Forwarded(t *testing.T) {
	// The dead-drop property: the edge holds no directory, so a token it has never "heard of" is
	// forwarded exactly like any other — the brain decides routable vs orphan. There is no
	// edge-side orphan/unknown handling anymore.
	edge, fp := newTestEdge(t)
	body, _ := json.Marshal(httpsEnvelope{
		EV:  1,
		Tok: "0011223344556677", // arbitrary token, not special to the edge
		Enc: base64.RawURLEncoding.EncodeToString([]byte("x")),
	})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
	req.RemoteAddr = "198.51.100.9:2"
	rr := httptest.NewRecorder()
	edge.httpsHandler()(rr, req)

	if fp.count() != 1 {
		t.Fatalf("arbitrary-token hit published %d, want 1 (edge forwards every well-formed hit)", fp.count())
	}
	if got := fp.last(); got.subject != ingestSubject || got.env.InstanceToken != "0011223344556677" {
		t.Errorf("forwarded wrong: subject=%q token=%q", got.subject, got.env.InstanceToken)
	}
}

func TestHTTPS_BadTokenHex_Dropped(t *testing.T) {
	// A malformed token (not 8 B hex) is cheap junk — dropped before publish.
	edge, fp := newTestEdge(t)
	body, _ := json.Marshal(httpsEnvelope{
		EV:  1,
		Tok: "nothex!!",
		Enc: base64.RawURLEncoding.EncodeToString([]byte("x")),
	})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
	req.RemoteAddr = "203.0.113.7:4"
	rr := httptest.NewRecorder()
	edge.httpsHandler()(rr, req)

	if fp.count() != 0 {
		t.Fatalf("malformed-token POST published %d, want 0", fp.count())
	}
}

func TestHTTPS_EmptyEnc_Rejected(t *testing.T) {
	// Post-HMAC migration HTTPS is always encrypted; the plaintext tier-0 fallback was removed.
	// An envelope with no `enc` must be DROPPED at the edge — not published — so a `tok` sniffer
	// cannot inject attacker-chosen tier-0 records under a real instance token.
	edge, fp := newTestEdge(t)
	body, _ := json.Marshal(httpsEnvelope{EV: 1, Tok: testTokenHex(), Enc: ""})
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(string(body)))
	req.RemoteAddr = "203.0.113.7:9"
	rr := httptest.NewRecorder()
	edge.httpsHandler()(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (edge never signals outcome)", rr.Code)
	}
	if fp.count() != 0 {
		t.Fatalf("empty-enc POST published %d messages, want 0 (must be rejected)", fp.count())
	}
}

// --- DNS: the dead-drop exit criterion ----------------------------------------------------

func TestDNS_Beacon_ForwardsFields_And_Queues(t *testing.T) {
	edge, fp := newTestEdge(t)

	sessionID := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	payload := []byte("FIRED")
	name := buildDNSName(t, 1, 0, testToken(), sessionID, 7, payload, testZone)

	w := &fakeDNSWriter{remote: &net.UDPAddr{IP: net.ParseIP("192.0.2.53"), Port: 33333}}
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	edge.dnsHandler()(w, req)

	if fp.count() != 1 {
		t.Fatalf("dns beacon published %d, want 1", fp.count())
	}
	got := fp.last()
	if got.subject != ingestSubject {
		t.Errorf("subject = %q, want %q", got.subject, ingestSubject)
	}
	if got.env.Channel != channelDNS {
		t.Errorf("channel = %q, want dns", got.env.Channel)
	}
	if got.env.InstanceToken != testTokenHex() {
		t.Errorf("instance_token = %q", got.env.InstanceToken)
	}
	if got.env.SessionID != hex.EncodeToString(sessionID) {
		t.Errorf("session_id = %q, want %q", got.env.SessionID, hex.EncodeToString(sessionID))
	}
	if got.env.SeqNo == nil || *got.env.SeqNo != 7 {
		t.Errorf("seq_no = %v, want 7", got.env.SeqNo)
	}
	// DNS observed source is the resolver, weaker-observed (§1.9-b).
	if got.env.Edge.Source.IP != "192.0.2.53" || got.env.Edge.Source.SourceType != sourceTypeResolver {
		t.Errorf("dns source = %q/%q, want 192.0.2.53/resolver", got.env.Edge.Source.IP, got.env.Edge.Source.SourceType)
	}
	gotPayload, _ := base64.StdEncoding.DecodeString(got.env.ObsBody)
	if string(gotPayload) != "FIRED" {
		t.Errorf("payload = %q, want FIRED", gotPayload)
	}
	// LAST flag (bit 0) set in our header → forwarded.
	if got.env.Flags&dnsFlagLast == 0 {
		t.Errorf("LAST flag not propagated; flags=%d", got.env.Flags)
	}
	// Edge answers with the sink A record so the beacon resolves normally.
	if w.msg == nil || len(w.msg.Answer) != 1 {
		t.Errorf("expected one sink answer, got %v", w.msg)
	}
}

func TestDNS_MultiLabel_Mode2(t *testing.T) {
	edge, fp := newTestEdge(t)
	sessionID := []byte{8, 7, 6, 5, 4, 3, 2, 1}

	// 19 B header + 20 B in first label, then overflow in a second label (§1.5 mode 2).
	header := dnsHeader(t, 1, 0, testToken(), sessionID, 0)
	first := append(append([]byte{}, header...), []byte("first20bytespayload!")...) // 20 B payload
	overflow := []byte("OVERFLOW-IN-SECOND-LABEL")
	label1 := strings.ToLower(b32.EncodeToString(first))
	label2 := strings.ToLower(b32.EncodeToString(overflow))
	name := label1 + "." + label2 + "." + testZone

	w := &fakeDNSWriter{remote: &net.UDPAddr{IP: net.ParseIP("192.0.2.53"), Port: 1}}
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	edge.dnsHandler()(w, req)

	if fp.count() != 1 {
		t.Fatalf("mode2 published %d, want 1", fp.count())
	}
	gotPayload, _ := base64.StdEncoding.DecodeString(fp.last().env.ObsBody)
	want := "first20bytespayload!" + "OVERFLOW-IN-SECOND-LABEL"
	if string(gotPayload) != want {
		t.Errorf("reassembled payload = %q, want %q", gotPayload, want)
	}
}

func TestDNS_OutOfZone_Refused(t *testing.T) {
	edge, fp := newTestEdge(t)
	w := &fakeDNSWriter{remote: &net.UDPAddr{IP: net.ParseIP("192.0.2.53"), Port: 1}}
	req := new(dns.Msg)
	req.SetQuestion("foo.bar.evil.com.", dns.TypeA)
	edge.dnsHandler()(w, req)

	if fp.count() != 0 {
		t.Fatalf("out-of-zone query published %d, want 0", fp.count())
	}
	if w.msg == nil || w.msg.Rcode != dns.RcodeRefused {
		t.Errorf("rcode = %v, want REFUSED", w.msg)
	}
}

func TestDNS_AnyToken_Forwarded(t *testing.T) {
	// The dead-drop property on DNS: an arbitrary token is forwarded like any other (no directory
	// gating, no edge-side orphan handling).
	edge, fp := newTestEdge(t)
	var arbitrary [8]byte
	copy(arbitrary[:], []byte{0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0})
	name := buildDNSName(t, 1, 0, arbitrary, make([]byte, 8), 0, nil, testZone)

	w := &fakeDNSWriter{remote: &net.UDPAddr{IP: net.ParseIP("192.0.2.53"), Port: 1}}
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	edge.dnsHandler()(w, req)

	if fp.count() != 1 {
		t.Fatalf("arbitrary-token dns published %d, want 1", fp.count())
	}
	if got := fp.last(); got.subject != ingestSubject || got.env.InstanceToken != hex.EncodeToString(arbitrary[:]) {
		t.Errorf("forwarded wrong: subject=%q token=%q", got.subject, got.env.InstanceToken)
	}
}

// --- rate limit + sampler -----------------------------------------------------------------

func TestRateLimiter_PerSourceCap(t *testing.T) {
	rl := NewRateLimiter(RateLimitConfig{GlobalRate: 1e6, GlobalBurst: 1e6, PerSrcRate: 0, PerSrcBurst: 3})
	allowed := 0
	for i := 0; i < 10; i++ {
		if rl.Allow("1.2.3.4") {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("per-source allowed %d, want 3 (burst)", allowed)
	}
	// A different source has its own bucket.
	if !rl.Allow("5.6.7.8") {
		t.Errorf("second source should have its own budget")
	}
}

func TestSampler_OneInN(t *testing.T) {
	s := NewSampler(3)
	kept := 0
	for i := 0; i < 9; i++ {
		if s.Keep() {
			kept++
		}
	}
	if kept != 3 {
		t.Errorf("kept %d of 9 with N=3, want 3", kept)
	}
	if !NewSampler(1).Keep() {
		t.Errorf("N=1 must keep all")
	}
}

// --- helpers ------------------------------------------------------------------------------

// dnsHeader builds the 19 B DNS mandatory header (§1.5).
func dnsHeader(t *testing.T, ev, flags uint8, tok [8]byte, sessionID []byte, seq uint16) []byte {
	t.Helper()
	if len(sessionID) != 8 {
		t.Fatalf("sessionID must be 8 B")
	}
	h := make([]byte, 0, dnsHeaderLen)
	h = append(h, (ev<<4)|(flags&0x0f))
	h = append(h, tok[:]...)
	h = append(h, sessionID...)
	var seqB [2]byte
	binary.BigEndian.PutUint16(seqB[:], seq)
	h = append(h, seqB[:]...)
	return h
}

// buildDNSName builds a mode-1 single-label beacon name with LAST flag bit 0 set.
func buildDNSName(t *testing.T, ev uint8, _ uint8, tok [8]byte, sessionID []byte, seq uint16, payload []byte, zone string) string {
	t.Helper()
	h := dnsHeader(t, ev, dnsFlagLast, tok, sessionID, seq)
	raw := append(append([]byte{}, h...), payload...)
	label := strings.ToLower(b32EncodeNoPad(raw))
	return label + "." + zone
}

func b32EncodeNoPad(b []byte) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
}
