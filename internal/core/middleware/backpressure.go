// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vincamok/goproxify/internal/core/metrics"
	"github.com/vincamok/goproxify/internal/core/router"
)

const defaultBackpressureQueueTimeout = time.Second

// Backpressure limite les requêtes simultanées d'une route. Les excédentaires
// attendent dans une file bornée, puis reçoivent 503 + Retry-After : la mémoire
// du Core reste bornée quand les backends ralentissent.
func Backpressure(host string, cfg *router.BackpressureConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil || cfg.MaxInflight <= 0 {
			return next
		}
		slots := make(chan struct{}, cfg.MaxInflight)
		maxQueue := int64(max(cfg.Queue, 0))
		wait := defaultBackpressureQueueTimeout
		if cfg.QueueTimeoutMs > 0 {
			wait = time.Duration(cfg.QueueTimeoutMs) * time.Millisecond
		}
		var queued atomic.Int64
		inflight := metrics.Backpressure.Inflight.WithLabelValues(host)
		queuedG := metrics.Backpressure.Queued.WithLabelValues(host)
		reject := func(w http.ResponseWriter, reason string) {
			metrics.Backpressure.Rejected.WithLabelValues(host, reason).Inc()
			w.Header().Set("Retry-After", "1")
			http.Error(w, "503 Service Unavailable — backend saturated", http.StatusServiceUnavailable)
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Une connexion longue (WebSocket) monopoliserait un slot indéfiniment.
			if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
				next.ServeHTTP(w, r)
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				if queued.Add(1) > maxQueue {
					queued.Add(-1)
					reject(w, "queue_full")
					return
				}
				queuedG.Inc()
				timer := time.NewTimer(wait)
				acquired := false
				reason := ""
				select {
				case slots <- struct{}{}:
					acquired = true
				case <-timer.C:
					reason = "timeout"
				case <-r.Context().Done():
					reason = "canceled"
				}
				timer.Stop()
				queued.Add(-1)
				queuedG.Dec()
				if !acquired {
					reject(w, reason)
					return
				}
			}
			inflight.Inc()
			defer func() {
				inflight.Dec()
				<-slots
			}()
			next.ServeHTTP(w, r)
		})
	}
}
