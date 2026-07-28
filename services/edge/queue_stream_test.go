package main

import (
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// TestBaitsStreamConfig_HasDiskLimits locks the disk-cap fix: the BAITS stream MUST be
// provisioned with a size cap, an age cap, and DiscardOld — without them a LimitsPolicy stream is
// an append-only log an unauthenticated party can drive to disk exhaustion through the edge's
// beacon endpoints. Kept in lockstep with the brain's _baits_stream_config()
// (tests/brain/test_stream_config.py) via the shared NATS_MAX_BYTES / NATS_MAX_AGE_S defaults.
func TestBaitsStreamConfig_HasDiskLimits(t *testing.T) {
	cfg := baitsStreamConfig("BAITS", defaultNATSMaxBytes, defaultNATSMaxAgeS*time.Second)

	if cfg.MaxBytes <= 0 {
		t.Fatalf("MaxBytes must be a positive disk cap, got %d (unbounded — disk-exhaustion regression)", cfg.MaxBytes)
	}
	if cfg.MaxAge <= 0 {
		t.Fatalf("MaxAge must be a positive age cap, got %v (unbounded — disk-exhaustion regression)", cfg.MaxAge)
	}
	if cfg.Discard != jetstream.DiscardOld {
		t.Fatalf("Discard must be DiscardOld so the cap self-trims, got %v", cfg.Discard)
	}
	if cfg.Retention != jetstream.LimitsPolicy {
		t.Fatalf("Retention must stay LimitsPolicy (single sole-consumer topology), got %v", cfg.Retention)
	}
	if cfg.Storage != jetstream.FileStorage {
		t.Fatalf("Storage must be FileStorage, got %v", cfg.Storage)
	}
	if want := int64(1 << 30); cfg.MaxBytes != want {
		t.Errorf("default MaxBytes = %d, want %d (must match brain settings.NATS_MAX_BYTES)", cfg.MaxBytes, want)
	}
	if want := 7 * 24 * time.Hour; cfg.MaxAge != want {
		t.Errorf("default MaxAge = %v, want %v (must match brain settings.NATS_MAX_AGE_S)", cfg.MaxAge, want)
	}
}
