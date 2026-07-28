package main

import (
	"log/slog"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// config.go — the edge's single configuration surface. The edge runs directly on the host (no
// container) and is configured entirely through environment variables; every value has a
// documented default here so a bare `edge` binary starts sanely and a deployment overrides only
// what it needs.
//
// This is the Go-side mirror of the Python operational config in
// `src/blacksea/config/settings.py`. Go cannot import that module, so the values
// SHARED with the rest of the system (NATS_URL / NATS_STREAM / subjects) must be kept in sync by
// hand — the NATS_STREAM default in particular MUST equal settings.NATS_STREAM ("BAITS") or the
// edge and brain provision two overlapping JetStream streams. The defaults below are fallbacks: in a
// normal run the shared NATS values come from the ONE unified config file `config/blacksea.env`
// (written by `make init`), which the console supervisor (`blacksea up`) reads
// and passes to this binary as env — so the edge reads the same file as everything else.
//
// Environment:
//
//	EDGE_ID              edge node id stamped into the edge group         (default "edge-local")
//	NATS_URL             NATS server URL                                  (default nats://127.0.0.1:4222)
//	NATS_USER            NATS username                                    (required)
//	NATS_PASS            NATS password                                    (required)
//	NATS_STREAM          JetStream stream name covering bait.>            (default BAITS; MUST match the brain)
//	NATS_MAX_BYTES       BAITS stream disk cap, bytes; 0 = unbounded       (default 1 GiB; MUST match the brain)
//	NATS_MAX_AGE_S       BAITS stream age cap, seconds; 0 = unbounded      (default 604800 = 7d; MUST match the brain)
//	HTTPS_ADDR           listen addr for the HTTPS/TCP receiver           (default :8443; empty disables)
//	TLS_CERT, TLS_KEY    PEM paths; if both set, serve TLS, else plain HTTP (testing)
//	DNS_ADDR             listen addr for the DNS receiver                 (default :5353; empty disables)
//	DNS_ZONES            comma-separated canary zones, e.g. c.example.com (required for DNS)
//	DNS_SINK_IP          A-record answer for beacons                      (default 0.0.0.0)
//	MAX_BODY_BYTES       hard HTTPS body cap, pre-parse                   (default 65536)
//	TIER0_SAMPLE_N       keep 1-in-N tier-0 DNS hits (inv 6)              (default 1 = keep all)
//	TRUST_XFF            trust X-Forwarded-For for client IP              (default false)
//	METRICS_INTERVAL_S   seconds between metric log dumps                 (default 60; 0 disables)
//	RL_GLOBAL_RATE       rate limiter: whole-edge tokens/sec              (default 2000)
//	RL_GLOBAL_BURST      rate limiter: whole-edge burst                   (default 4000)
//	RL_PERSRC_RATE       rate limiter: per-source tokens/sec              (default 20)
//	RL_PERSRC_BURST      rate limiter: per-source burst                   (default 40)
//	RL_IDLE_EVICTION_S   rate limiter: reclaim idle per-source buckets    (default 600)
//	HTTP_READ_HEADER_TIMEOUT_S  HTTPS server ReadHeaderTimeout (s)        (default 5)
//	HTTP_READ_TIMEOUT_S         HTTPS server ReadTimeout (s)              (default 15)
//	HTTP_WRITE_TIMEOUT_S        HTTPS server WriteTimeout (s)             (default 15)
//	SHUTDOWN_DRAIN_S            graceful-shutdown drain budget (s)        (default 10)

// Defaults for the BAITS-stream disk caps (defense-in-depth against unauthenticated
// disk-exhaustion — see edge/context.md). These MUST equal the brain's
// settings.NATS_MAX_BYTES / NATS_MAX_AGE_S defaults, or whichever provisioner runs last on a
// fresh deploy silently re-widens the stream back toward unbounded.
const (
	defaultNATSMaxBytes int64 = 1 << 30      // 1 GiB
	defaultNATSMaxAgeS        = 7 * 24 * 3600 // 604800s = 7 days
)

// config holds the parsed environment.
type config struct {
	edgeID          string
	natsURL         string
	natsUser        string
	natsPass        string
	natsStream      string
	natsMaxBytes    int64
	natsMaxAge      time.Duration
	httpsAddr       string
	tlsCert, tlsKey string
	dnsAddr         string
	dnsZones        []string
	dnsSinkIP       net.IP
	maxBodyBytes    int64
	tier0SampleN    int
	trustXFF        bool
	metricsInterval time.Duration

	// Rate limiter (previously hardcoded in DefaultRateLimitConfig with no override path).
	rl RateLimitConfig

	// HTTPS server + shutdown timeouts (previously literal in main.go).
	httpReadHeaderTimeout time.Duration
	httpReadTimeout       time.Duration
	httpWriteTimeout      time.Duration
	shutdownDrain         time.Duration
}

func loadConfig() config {
	rlDef := DefaultRateLimitConfig()
	c := config{
		edgeID:          envOr("EDGE_ID", "edge-local"),
		natsURL:         envOr("NATS_URL", "nats://127.0.0.1:4222"),
		natsUser:        os.Getenv("NATS_USER"), // required; no default (NewNATSPublisher rejects empty)
		natsPass:        os.Getenv("NATS_PASS"),
		natsStream:      envOr("NATS_STREAM", "BAITS"),
		natsMaxBytes:    envInt64Or("NATS_MAX_BYTES", defaultNATSMaxBytes),
		natsMaxAge:      durationSecondsOr("NATS_MAX_AGE_S", defaultNATSMaxAgeS),
		httpsAddr:       envOr("HTTPS_ADDR", ":8443"),
		tlsCert:         os.Getenv("TLS_CERT"),
		tlsKey:          os.Getenv("TLS_KEY"),
		dnsAddr:         envOr("DNS_ADDR", ":5353"),
		maxBodyBytes:    int64(envIntOr("MAX_BODY_BYTES", 65536)),
		tier0SampleN:    envIntOr("TIER0_SAMPLE_N", 1),
		trustXFF:        envBoolOr("TRUST_XFF", false),
		metricsInterval: time.Duration(envIntOr("METRICS_INTERVAL_S", 60)) * time.Second,
		rl: RateLimitConfig{
			GlobalRate:   envFloatOr("RL_GLOBAL_RATE", rlDef.GlobalRate),
			GlobalBurst:  envFloatOr("RL_GLOBAL_BURST", rlDef.GlobalBurst),
			PerSrcRate:   envFloatOr("RL_PERSRC_RATE", rlDef.PerSrcRate),
			PerSrcBurst:  envFloatOr("RL_PERSRC_BURST", rlDef.PerSrcBurst),
			IdleEviction: time.Duration(envIntOr("RL_IDLE_EVICTION_S", int(rlDef.IdleEviction.Seconds()))) * time.Second,
		},
		httpReadHeaderTimeout: time.Duration(envIntOr("HTTP_READ_HEADER_TIMEOUT_S", 5)) * time.Second,
		httpReadTimeout:       time.Duration(envIntOr("HTTP_READ_TIMEOUT_S", 15)) * time.Second,
		httpWriteTimeout:      time.Duration(envIntOr("HTTP_WRITE_TIMEOUT_S", 15)) * time.Second,
		shutdownDrain:         time.Duration(envIntOr("SHUTDOWN_DRAIN_S", 10)) * time.Second,
	}
	for _, z := range strings.Split(os.Getenv("DNS_ZONES"), ",") {
		z = strings.TrimSpace(strings.ToLower(z))
		if z == "" {
			continue
		}
		c.dnsZones = append(c.dnsZones, dns.Fqdn(z))
	}
	c.dnsSinkIP = net.ParseIP(envOr("DNS_SINK_IP", "0.0.0.0"))
	return c
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envIntOr(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
		slog.Warn("invalid int env; using default", "key", key, "value", v, "default", def)
	}
	return def
}

// durationSecondsOr reads an integer-seconds env var and converts it to a Duration, guarding the
// `* time.Second` (×1e9) multiply against int64 overflow: a wildly large value would otherwise wrap
// to a NEGATIVE Duration, which NATS rejects — failing stream provisioning and (via os.Exit in
// main) taking the edge down. 0 stays 0 (the "unbounded age" sentinel); a negative or overflowing
// value falls back to the default with a warning.
func durationSecondsOr(key string, defSeconds int64) time.Duration {
	secs := envInt64Or(key, defSeconds)
	const maxSeconds = int64(math.MaxInt64) / int64(time.Second) // ≈9.22e9 s before Duration overflow
	if secs < 0 || secs > maxSeconds {
		slog.Warn("seconds env out of range for a Duration; using default",
			"key", key, "value", secs, "max", maxSeconds, "default", defSeconds)
		secs = defSeconds
	}
	return time.Duration(secs) * time.Second
}

func envInt64Or(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
		slog.Warn("invalid int64 env; using default", "key", key, "value", v, "default", def)
	}
	return def
}

func envFloatOr(key string, def float64) float64 {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
		slog.Warn("invalid float env; using default", "key", key, "value", v, "default", def)
	}
	return def
}

func envBoolOr(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}
