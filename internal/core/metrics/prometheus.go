// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// UpdateCertExpiries met à jour la gauge gpx_tls_cert_expiry_seconds pour toutes les entrées.
// Appeler après chaque StorePEM/Delete sur le CertStore.
func UpdateCertExpiries(expiries map[string]time.Time) {
	now := time.Now()
	for domain, notAfter := range expiries {
		secs := notAfter.Sub(now).Seconds()
		if secs < 0 {
			secs = 0
		}
		CertExpirySeconds.WithLabelValues(domain).Set(secs)
	}
}

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

// CertExpirySeconds expose la durée avant expiration de chaque certificat TLS.
var CertExpirySeconds = promauto.NewGaugeVec(prometheus.GaugeOpts{
	Namespace: "gpx",
	Subsystem: "tls",
	Name:      "cert_expiry_seconds",
	Help:      "Secondes avant expiration du certificat TLS (0 = expiré).",
}, []string{"domain"})

// Pipeline expose les métriques de blocage par étape du pipeline de sécurité.
var Pipeline = struct {
	BlockedTotal *prometheus.CounterVec
}{
	BlockedTotal: promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "pipeline",
		Name:      "blocked_total",
		Help:      "Requêtes bloquées par le pipeline de sécurité.",
	}, []string{"host", "stage", "reason"}),
}

// Routing expose les métriques canary et shadow.
var Routing = struct {
	CanaryTotal *prometheus.CounterVec
	ShadowTotal *prometheus.CounterVec
}{
	CanaryTotal: promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "routing",
		Name:      "canary_requests_total",
		Help:      "Requêtes routées vers le backend canary.",
	}, []string{"host"}),

	ShadowTotal: promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "routing",
		Name:      "shadow_requests_total",
		Help:      "Requêtes dupliquées vers le backend shadow mirror.",
	}, []string{"host"}),
}

// Backend expose les métriques Prometheus par backend upstream.
var Backend = struct {
	RequestsTotal *prometheus.CounterVec
	Duration      *prometheus.HistogramVec
	ErrorsTotal   *prometheus.CounterVec
	RetriesTotal  *prometheus.CounterVec
}{
	RequestsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "backend",
		Name:      "requests_total",
		Help:      "Nombre de requêtes envoyées à chaque backend upstream.",
	}, []string{"host", "backend", "status"}),

	Duration: promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "gpx",
		Subsystem: "backend",
		Name:      "duration_seconds",
		Help:      "Durée des requêtes vers les backends upstream.",
		Buckets:   prometheus.DefBuckets,
	}, []string{"host", "backend"}),

	ErrorsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "backend",
		Name:      "errors_total",
		Help:      "Erreurs transport vers les backends upstream.",
	}, []string{"host", "backend", "error_type"}),

	RetriesTotal: promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "backend",
		Name:      "retries_total",
		Help:      "Tentatives de failover vers un autre backend.",
	}, []string{"host", "backend"}),
}
