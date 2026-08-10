// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server expose les métriques système sur :9191/metrics.
type Server struct {
	port        int
	scrapeMS    int
	log         *slog.Logger
	nodeLabel   string
	srv         *http.Server

	cpuUsage  prometheus.Gauge
	memTotal  prometheus.Gauge
	memUsed   prometheus.Gauge
	memPct    prometheus.Gauge
}

// NewServer crée un serveur de télémétrie.
func NewServer(port, scrapeMS int, nodeLabel string, log *slog.Logger) *Server {
	reg := prometheus.NewRegistry()
	factory := promauto.With(reg)

	s := &Server{
		port:      port,
		scrapeMS:  scrapeMS,
		log:       log,
		nodeLabel: nodeLabel,
	}

	lbls := prometheus.Labels{"node": nodeLabel}

	s.cpuUsage = factory.NewGauge(prometheus.GaugeOpts{
		Name: "gpx_agent_cpu_usage_pct",
		Help: "Pourcentage CPU utilisé (0-100)",
		ConstLabels: lbls,
	})
	s.memTotal = factory.NewGauge(prometheus.GaugeOpts{
		Name: "gpx_agent_mem_total_bytes",
		Help: "Mémoire totale en octets",
		ConstLabels: lbls,
	})
	s.memUsed = factory.NewGauge(prometheus.GaugeOpts{
		Name: "gpx_agent_mem_used_bytes",
		Help: "Mémoire utilisée en octets",
		ConstLabels: lbls,
	})
	s.memPct = factory.NewGauge(prometheus.GaugeOpts{
		Name: "gpx_agent_mem_usage_pct",
		Help: "Pourcentage mémoire utilisé (0-100)",
		ConstLabels: lbls,
	})

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	s.srv = &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	return s
}

// Start démarre le serveur HTTP et la goroutine de collecte.
func (s *Server) Start(ctx context.Context) {
	s.log.Info("télémétrie agent démarrée", "port", s.port, "node", s.nodeLabel)

	go func() {
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.Error("télémétrie: serveur", "err", err)
		}
	}()

	go s.collect(ctx)
}

// Stop arrête proprement le serveur.
func (s *Server) Stop(ctx context.Context) {
	if s.srv != nil {
		_ = s.srv.Shutdown(ctx)
	}
}

func (s *Server) collect(ctx context.Context) {
	interval := time.Duration(s.scrapeMS) * time.Millisecond
	if interval <= 0 {
		interval = 5 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var prevCPU CPUStat
	var err error
	prevCPU, err = ReadCPUStat()
	if err != nil {
		s.log.Warn("télémétrie: lecture CPU initiale", "err", err)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cur, err := ReadCPUStat()
			if err == nil {
				s.cpuUsage.Set(CPUUsagePct(prevCPU, cur))
				prevCPU = cur
			}
			mem, err := ReadMemStat()
			if err == nil {
				s.memTotal.Set(float64(mem.TotalKB * 1024))
				s.memUsed.Set(float64(mem.UsedKB() * 1024))
				s.memPct.Set(mem.UsagePct())
			}
		}
	}
}
