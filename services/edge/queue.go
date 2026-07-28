package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// contextTimeout is a small helper for the short-lived contexts JetStream calls require.
func contextTimeout(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// queue.go — NATS JetStream publisher (§1.7 step 6).
//
// The dead-drop edge publishes EVERY normalised hit to one fixed subject — it holds no directory
// and cannot compute a per-bait subject, and the brain re-derives routing from `tok` anyway. The
// subject sits under the `bait.>` namespace so the existing stream + brain subscription (`bait.>`)
// need no change. Publishing is the edge's only outbound action toward the trusted plane — it
// never opens a connection to a sensor (inv 7) or to the brain (inv 2); it speaks only to the queue.

// ingestSubject is the single subject the dead-drop edge publishes to. The brain consumes the
// `bait.>` stream, reads `tok`, and resolves bait_id/routing from its own key directory.
const ingestSubject = "bait._ingest"

// Publisher is the edge's queue surface. Kept as an interface so tests inject a fake and main.go
// wires the real JetStream client — receivers never depend on NATS directly.
type Publisher interface {
	// Publish sends data to subject. It must be safe for concurrent use.
	Publish(subject string, data []byte) error
	Close()
}

// PublishEnvelope marshals a QueuedEnvelope to JSON and publishes it to the ingest subject.
func PublishEnvelope(p Publisher, env *QueuedEnvelope) error {
	data, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	return p.Publish(ingestSubject, data)
}

// NATSPublisher is the production JetStream publisher.
type NATSPublisher struct {
	nc *nats.Conn
	js jetstream.JetStream
}

// baitsStreamConfig builds the JetStream config for the shared BAITS stream. Split out from
// NewNATSPublisher so it is unit-testable without a live NATS, and so the exact limit fields are
// visible in one place.
//
// maxBytes / maxAge are the disk caps that bound the stream (0 = unbounded for that dimension).
// Under LimitsPolicy a consumer ack does NOT evict a message — only a size/count/age limit can —
// so WITHOUT these the stream is an append-only log of every hit ever published, bounded only by
// host disk, which an unauthenticated party can drive to exhaustion through the edge's own beacon
// endpoints. Discard=DiscardOld makes the cap self-trimming: once full the
// OLDEST messages are evicted rather than new publishes rejected. In steady state those oldest
// messages are already consumed (the brain persists to Postgres in near-real-time), so nothing is
// lost — BUT this is exactly the residual risk of choosing a cap over WorkQueuePolicy: during a
// flood that outpaces the consumer, DiscardOld can drop legitimate not-yet-consumed hits along with
// the attacker's. That trade (bounded disk, possible intel loss under active attack) is deliberate;
// a lag/drop alert on the consumer is a deferred hardening follow-on. These fields MUST match the brain's
// _baits_stream_config() in src/blacksea/brain/pool.py — the brain provisions the same stream, and
// whichever side runs last on a fresh deploy wins.
func baitsStreamConfig(streamName string, maxBytes int64, maxAge time.Duration) jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:       streamName,
		Subjects:   []string{"bait.>"},
		Retention:  jetstream.LimitsPolicy,
		Storage:    jetstream.FileStorage,
		Discard:    jetstream.DiscardOld,
		MaxBytes:   maxBytes, // disk cap (bytes); DiscardOld trims oldest when reached
		MaxAge:     maxAge,   // age cap; self-trims by time regardless of volume
		Duplicates: 2 * time.Minute,
	}
}

// NewNATSPublisher connects to NATS and ensures a stream covering `bait.>` exists.
//
// streamName is the JetStream stream that captures every bait subject; subjects = `bait.>`
// per the locked technology decision (NATS JetStream, subjects = bait.<bait_id>).
//
// maxBytes / maxAge bound the stream's on-disk size and age (see baitsStreamConfig); pass 0 to
// leave a dimension unbounded (not recommended — reopens the disk-exhaustion gap).
//
// user/pass authenticate to NATS and are mandatory — the edge refuses to connect anonymously.
// They are passed as separate arguments (not embedded in url) so the credential never appears in
// the url we log on connection failure.
func NewNATSPublisher(url, streamName, user, pass string, maxBytes int64, maxAge time.Duration) (*NATSPublisher, error) {
	if user == "" || pass == "" {
		return nil, fmt.Errorf("NATS_USER and NATS_PASS are required (edge will not connect anonymously)")
	}
	nc, err := nats.Connect(url,
		nats.Name("blacksea-edge"),
		nats.UserInfo(user, pass),
		nats.MaxReconnects(-1), // edge keeps retrying; it must not drop authenticated telemetry (inv 6)
		nats.ReconnectWait(time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}
	js, err := jetstream.New(nc)
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("jetstream init: %w", err)
	}

	ctx, cancel := contextTimeout(5 * time.Second)
	defer cancel()
	// CreateOrUpdateStream applies the caps to an existing stream too — MaxBytes/MaxAge are
	// updatable — so restarting the edge re-tightens a stream an older build left unbounded.
	_, err = js.CreateOrUpdateStream(ctx, baitsStreamConfig(streamName, maxBytes, maxAge))
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("ensure stream %q: %w", streamName, err)
	}
	return &NATSPublisher{nc: nc, js: js}, nil
}

// Publish sends data to subject using a synchronous JetStream publish (the ack confirms the
// message is persisted — at-least-once with consumer-side dedup on the §1.8 tuple).
func (p *NATSPublisher) Publish(subject string, data []byte) error {
	ctx, cancel := contextTimeout(5 * time.Second)
	defer cancel()
	if _, err := p.js.Publish(ctx, subject, data); err != nil {
		return fmt.Errorf("jetstream publish to %q: %w", subject, err)
	}
	return nil
}

// Close drains and closes the NATS connection.
func (p *NATSPublisher) Close() {
	if p.nc != nil {
		_ = p.nc.Drain()
	}
}
