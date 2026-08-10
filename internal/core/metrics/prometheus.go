// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Métriques plan de contrôle WebSocket (noms roadmap : goproxify_ws_*).
var (
	WSConnectionsActive = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "goproxify_ws_connections_active",
		Help: "Nombre de connexions WebSocket actives du plan de contrôle (Admin ou Agent).",
	}, []string{"role"})

	WSMessagesSentTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "goproxify_ws_messages_sent_total",
		Help: "Messages WebSocket envoyés par le Core (plan de contrôle).",
	}, []string{"role", "type"})
)

// Core expose les métriques Prometheus du Core.
var Core = struct {
	RequestsTotal   *prometheus.CounterVec
	RequestDuration *prometheus.HistogramVec
	ActiveRequests  *prometheus.GaugeVec
	BytesIn         prometheus.Counter
	BytesOut        prometheus.Counter
	RouteCount      prometheus.Gauge
	CertCount       prometheus.Gauge
}{
	RequestsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "core",
		Name:      "requests_total",
		Help:      "Nombre total de requêtes HTTP proxifiées.",
	}, []string{"host", "method", "status"}),

	RequestDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "gpx",
		Subsystem: "core",
		Name:      "request_duration_seconds",
		Help:      "Durée des requêtes HTTP proxifiées.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"host"}),

	ActiveRequests: promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "gpx",
		Subsystem: "core",
		Name:      "active_requests",
		Help:      "Nombre de requêtes HTTP en cours.",
	}, []string{"host"}),

	BytesIn: promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "core",
		Name:      "bytes_received_total",
		Help:      "Octets reçus (tous protocoles).",
	}),

	BytesOut: promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "core",
		Name:      "bytes_sent_total",
		Help:      "Octets envoyés (tous protocoles).",
	}),

	RouteCount: promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "gpx",
		Subsystem: "core",
		Name:      "routes_total",
		Help:      "Nombre de routes actives en mémoire.",
	}),

	CertCount: promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "gpx",
		Subsystem: "core",
		Name:      "certs_total",
		Help:      "Nombre de certificats TLS en mémoire.",
	}),
}
