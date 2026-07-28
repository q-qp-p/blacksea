package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// main.go — wires config → receivers → NATS → rate limiter and runs the two servers (HTTPS/TCP +
// DNS) until a signal arrives. The edge runs directly on the host (no container); configuration is
// via environment variables, all parsed in config.go (see that file's header for the full
// environment reference). The edge is a dumb dead-drop: it holds no key directory — routing is
// resolved by the brain from `tok` (inv 3/13/18).
func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg := loadConfig()

	// Queue publisher.
	pub, err := NewNATSPublisher(cfg.natsURL, cfg.natsStream, cfg.natsUser, cfg.natsPass, cfg.natsMaxBytes, cfg.natsMaxAge)
	if err != nil {
		slog.Error("connect NATS", "err", err, "url", cfg.natsURL)
		os.Exit(1)
	}
	defer pub.Close()

	edge := &Edge{
		edgeID:  cfg.edgeID,
		limiter: NewRateLimiter(cfg.rl),
		sampler: NewSampler(cfg.tier0SampleN),
		pub:     pub,
		// ev=1: the original AES-256-GCM+CBOR envelope (additive versioning — never
		// removed for back-compat). ev=2: the current HMAC-SHA256 AEAD + fixed binary core
		// envelope (landed 2026-07-14, see edge/context.md). The edge never
		// interprets either version's `enc` payload — this allowlist only gates the
		// routing-critical fast-parse check; the brain is the sole decoder.
		knownEV:           map[uint8]bool{1: true, 2: true},
		maxBodyBytes:      cfg.maxBodyBytes,
		trustForwardedFor: cfg.trustXFF,
		zones:             cfg.dnsZones,
		dnsSinkIP:         cfg.dnsSinkIP,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var httpSrv *http.Server
	var dnsSrvUDP, dnsSrvTCP *dns.Server

	// --- HTTPS / TCP receiver ---
	if cfg.httpsAddr != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/", edge.httpsHandler())
		httpSrv = &http.Server{
			Addr:              cfg.httpsAddr,
			Handler:           mux,
			ReadHeaderTimeout: cfg.httpReadHeaderTimeout,
			ReadTimeout:       cfg.httpReadTimeout,
			WriteTimeout:      cfg.httpWriteTimeout,
		}
		go func() {
			var err error
			if cfg.tlsCert != "" && cfg.tlsKey != "" {
				httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
				slog.Info("https receiver listening (TLS)", "addr", cfg.httpsAddr)
				err = httpSrv.ListenAndServeTLS(cfg.tlsCert, cfg.tlsKey)
			} else {
				slog.Warn("https receiver listening WITHOUT TLS (testing only)", "addr", cfg.httpsAddr)
				err = httpSrv.ListenAndServe()
			}
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("https server", "err", err)
				stop()
			}
		}()
	}

	// --- DNS receiver (UDP + TCP) ---
	if cfg.dnsAddr != "" {
		if len(cfg.dnsZones) == 0 {
			slog.Error("DNS_ADDR set but DNS_ZONES empty — refusing to start DNS with no zone")
			os.Exit(1)
		}
		handler := edge.dnsHandler()
		dnsSrvUDP = &dns.Server{Addr: cfg.dnsAddr, Net: "udp", Handler: handler}
		dnsSrvTCP = &dns.Server{Addr: cfg.dnsAddr, Net: "tcp", Handler: handler}
		for _, s := range []*dns.Server{dnsSrvUDP, dnsSrvTCP} {
			s := s
			go func() {
				slog.Info("dns receiver listening", "addr", s.Addr, "net", s.Net, "zones", cfg.dnsZones)
				if err := s.ListenAndServe(); err != nil {
					slog.Error("dns server", "err", err, "net", s.Net)
					stop()
				}
			}()
		}
	}

	// --- periodic metrics dump ---
	if cfg.metricsInterval > 0 {
		go func() {
			t := time.NewTicker(cfg.metricsInterval)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-t.C:
					edgeMetrics.logSnapshot()
				}
			}
		}()
	}

	slog.Info("edge started", "edge_id", cfg.edgeID)
	<-ctx.Done()
	slog.Info("shutdown signal received; draining")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.shutdownDrain)
	defer cancel()
	if httpSrv != nil {
		_ = httpSrv.Shutdown(shutdownCtx)
	}
	if dnsSrvUDP != nil {
		_ = dnsSrvUDP.ShutdownContext(shutdownCtx)
	}
	if dnsSrvTCP != nil {
		_ = dnsSrvTCP.ShutdownContext(shutdownCtx)
	}
	edgeMetrics.logSnapshot()
	slog.Info("edge stopped")
}
