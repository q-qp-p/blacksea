package main

import (
	"log/slog"
	"net"
	"sort"
	"sync"
)

// core.go — the Edge struct that bundles the shared dependencies both receivers use, plus a
// tiny in-process metrics counter. Keeping the dependencies in one value (rather than package
// globals) makes the receivers trivially testable: a test builds an Edge with a fake Publisher
// and exercises the handlers directly.

// Edge holds everything the HTTPS + DNS receivers need. It is immutable after construction. The
// edge is a dumb dead-drop: it holds no key directory — routing is resolved by the brain (inv 3).
type Edge struct {
	edgeID string

	limiter *RateLimiter
	sampler *Sampler
	pub     Publisher

	knownEV map[uint8]bool // ev values this edge build understands (§1.6)

	// HTTPS
	maxBodyBytes      int64
	trustForwardedFor bool

	// DNS
	zones     []string // fully-qualified, lower-cased canary zones (trailing dot)
	dnsSinkIP net.IP   // A-record answer for beacons; nil = answer NOERROR/no-answer
}

// publish marshals + sends a normalised envelope to its bait subject, logging (not failing) on
// queue errors — a queue outage must not crash the receiver; the edge keeps accepting traffic
// and the publish error is surfaced as a metric for alerting.
func (e *Edge) publish(env *QueuedEnvelope, srcIP string) {
	if err := PublishEnvelope(e.pub, env); err != nil {
		edgeMetrics.add("publish_err", 1)
		slog.Error("publish failed",
			"err", err, "token", env.InstanceToken, "channel", env.Channel, "src", srcIP)
		return
	}
	edgeMetrics.add("published", 1)
}

// --- minimal metrics ---------------------------------------------------------------------

// metrics is a concurrency-safe named counter set. The edge has no Prometheus dep; main.go
// can dump these on a signal or interval. Production scrape wiring is deferred hardening.
type metrics struct {
	mu sync.Mutex
	c  map[string]int64
}

func newMetrics() *metrics { return &metrics{c: map[string]int64{}} }

func (m *metrics) add(name string, n int64) {
	m.mu.Lock()
	m.c[name] += n
	m.mu.Unlock()
}

// snapshot returns a stable, sorted copy for logging/inspection.
func (m *metrics) snapshot() map[string]int64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]int64, len(m.c))
	for k, v := range m.c {
		out[k] = v
	}
	return out
}

// logSnapshot emits the current counters in a deterministic order.
func (m *metrics) logSnapshot() {
	snap := m.snapshot()
	keys := make([]string, 0, len(snap))
	for k := range snap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	attrs := make([]any, 0, len(keys)*2)
	for _, k := range keys {
		attrs = append(attrs, k, snap[k])
	}
	slog.Info("edge metrics", attrs...)
}

// edgeMetrics is the process-wide counter set (one edge process).
var edgeMetrics = newMetrics()
