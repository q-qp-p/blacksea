package main

import (
	"sync"
	"sync/atomic"
	"time"
)

// Sampler implements the tier-0 unsigned sample gate (§1.7 step 4, inv 6): tier-0 traffic is
// never fully persisted by itself, so the edge passes only 1-in-N tier-0 hits to the queue.
// N <= 1 keeps everything (the default). Counter-based rather than random so it needs no entropy
// source on the hot path and is trivially testable.
type Sampler struct {
	n uint64
	c atomic.Uint64
}

func NewSampler(n int) *Sampler {
	if n < 1 {
		n = 1
	}
	return &Sampler{n: uint64(n)}
}

// Keep reports whether this tier-0 hit should be passed (kept) rather than sampled out.
func (s *Sampler) Keep() bool {
	if s.n <= 1 {
		return true
	}
	return s.c.Add(1)%s.n == 0
}

// ratelimit.go — hard, pre-parse defences (§1.7 step 2, §13).
//
// Hostile sensors flood the edge and probe for parser bugs, so the edge applies size + rate
// caps BEFORE any envelope parsing. Two layers:
//   - a global token bucket (whole-edge throughput ceiling), and
//   - a per-source token bucket (one misbehaving source can't starve the rest).
// Plus a hard byte cap enforced at the receiver (HTTPS body) / name-length cap (DNS).
//
// The limiter is stateless w.r.t. bait logic (inv 3): it keys only on source IP, which the edge
// already observes. Per-source buckets are reclaimed lazily so the map can't grow unbounded
// under a spoofed-source flood.

// tokenBucket is a classic token bucket: capacity `burst`, refilling at `rate` tokens/sec.
type tokenBucket struct {
	tokens   float64
	burst    float64
	rate     float64
	lastFill time.Time
}

func newTokenBucket(rate, burst float64) *tokenBucket {
	return &tokenBucket{tokens: burst, burst: burst, rate: rate, lastFill: time.Now()}
}

// allow refills based on elapsed time and consumes one token if available.
func (b *tokenBucket) allow(now time.Time) bool {
	elapsed := now.Sub(b.lastFill).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.lastFill = now
	}
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// RateLimiter combines a global bucket with per-source buckets.
type RateLimiter struct {
	mu sync.Mutex

	global *tokenBucket

	perSrc       map[string]*tokenBucket
	srcRate      float64
	srcBurst     float64
	idleEviction time.Duration // per-source buckets untouched this long are reclaimed
	lastSweep    time.Time
}

// RateLimitConfig holds the tunables. config.go builds one from the RL_* env vars (falling back
// to DefaultRateLimitConfig for each field) and main.go passes it to NewRateLimiter.
type RateLimitConfig struct {
	GlobalRate   float64       // tokens/sec across the whole edge
	GlobalBurst  float64       //
	PerSrcRate   float64       // tokens/sec per source IP
	PerSrcBurst  float64       //
	IdleEviction time.Duration // per-source buckets untouched this long are reclaimed
}

// DefaultRateLimitConfig is a conservative baseline; each field is overridable via its RL_* env
// var (see config.go). It remains the single home for the default numbers.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		GlobalRate:   2000,
		GlobalBurst:  4000,
		PerSrcRate:   20,
		PerSrcBurst:  40,
		IdleEviction: 10 * time.Minute,
	}
}

func NewRateLimiter(cfg RateLimitConfig) *RateLimiter {
	idle := cfg.IdleEviction
	if idle <= 0 {
		idle = 10 * time.Minute
	}
	return &RateLimiter{
		global:       newTokenBucket(cfg.GlobalRate, cfg.GlobalBurst),
		perSrc:       map[string]*tokenBucket{},
		srcRate:      cfg.PerSrcRate,
		srcBurst:     cfg.PerSrcBurst,
		idleEviction: idle,
		lastSweep:    time.Now(),
	}
}

// Allow reports whether a hit from `srcIP` may proceed to parsing. It charges both the global
// and the per-source bucket; a hit is allowed only if BOTH have a token (the global cap is the
// hard ceiling, the per-source cap is the fairness floor).
func (r *RateLimiter) Allow(srcIP string) bool {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	r.sweepLocked(now)

	if !r.global.allow(now) {
		return false
	}
	b := r.perSrc[srcIP]
	if b == nil {
		b = newTokenBucket(r.srcRate, r.srcBurst)
		r.perSrc[srcIP] = b
	}
	return b.allow(now)
}

// sweepLocked reclaims per-source buckets that have refilled to capacity and gone idle, bounding
// map growth under a spoofed-source flood. Called under r.mu.
func (r *RateLimiter) sweepLocked(now time.Time) {
	if now.Sub(r.lastSweep) < r.idleEviction {
		return
	}
	r.lastSweep = now
	for ip, b := range r.perSrc {
		if now.Sub(b.lastFill) > r.idleEviction && b.tokens >= b.burst {
			delete(r.perSrc, ip)
		}
	}
}
