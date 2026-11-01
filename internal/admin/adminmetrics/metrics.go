// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package adminmetrics expose les métriques Prometheus des moteurs de sécurité Admin.
package adminmetrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Fleet expose les métriques des Seuils multi-passerelles.
var Fleet = struct {
	BansTotal  prometheus.Counter
	ScansTotal prometheus.Counter
}{
	BansTotal: promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "fleet",
		Name:      "bans_total",
		Help:      "Nombre total d'IPs bannies automatiquement par les Seuils multi-passerelles.",
	}),
	ScansTotal: promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "fleet",
		Name:      "scans_total",
		Help:      "Nombre total de cycles de scan des Seuils multi-passerelles.",
	}),
}

// CrowdSec expose les métriques du bouncer CrowdSec.
var CrowdSec = struct {
	DecisionsTotal *prometheus.CounterVec
	SyncsTotal     *prometheus.CounterVec
}{
	DecisionsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "crowdsec",
		Name:      "decisions_total",
		Help:      "Décisions CrowdSec traitées (new/deleted).",
	}, []string{"action"}),

	SyncsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "crowdsec",
		Name:      "syncs_total",
		Help:      "Cycles de synchronisation CrowdSec LAPI.",
	}, []string{"result"}),
}

// Automation expose les métriques des flux d'automatisation.
var Automation = struct {
	EvalsTotal   prometheus.Counter
	EvalDuration prometheus.Histogram
	ActiveFlows  *prometheus.GaugeVec
	RunsTotal    *prometheus.CounterVec
	ActionsTotal *prometheus.CounterVec
	EventsDrop   prometheus.Counter
}{
	EvalsTotal: promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gpx", Subsystem: "automation", Name: "evals_total",
		Help: "Passages d'évaluation des flux à condition.",
	}),
	EvalDuration: promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "gpx", Subsystem: "automation", Name: "eval_duration_seconds",
		Help:    "Durée d'un passage d'évaluation des flux à condition.",
		Buckets: []float64{.001, .005, .01, .05, .1, .5, 1, 5},
	}),
	ActiveFlows: promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "gpx", Subsystem: "automation", Name: "active_flows",
		Help: "Flux activés, par type de déclencheur.",
	}, []string{"trigger"}),
	RunsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx", Subsystem: "automation", Name: "runs_total",
		Help: "Exécutions de flux terminées, par déclencheur et statut.",
	}, []string{"trigger", "status"}),
	ActionsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx", Subsystem: "automation", Name: "actions_total",
		Help: "Actions exécutées par les flux.",
	}, []string{"action", "result"}),
	EventsDrop: promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gpx", Subsystem: "automation", Name: "events_dropped_total",
		Help: "Événements ignorés faute de place dans la file des déclencheurs.",
	}),
}

// RulesEngine exposes the rule engine's evaluation and action metrics.
var RulesEngine = struct {
	EvalsTotal   prometheus.Counter
	EvalDuration prometheus.Histogram
	ActiveRules  prometheus.Gauge
	ActionsTotal *prometheus.CounterVec
}{
	EvalsTotal: promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gpx", Subsystem: "rulesengine", Name: "evals_total",
		Help: "Total rule evaluation cycles.",
	}),
	EvalDuration: promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "gpx", Subsystem: "rulesengine", Name: "eval_duration_seconds",
		Help:    "Duration of a rule evaluation cycle.",
		Buckets: []float64{.001, .005, .01, .05, .1, .5, 1, 5},
	}),
	ActiveRules: promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "gpx", Subsystem: "rulesengine", Name: "active_rules",
		Help: "Number of enabled rules.",
	}),
	ActionsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx", Subsystem: "rulesengine", Name: "actions_total",
		Help: "Total rule actions by type and result.",
	}, []string{"action", "result"}),
}

// VulnScan expose les métriques du scanner de vulnérabilités.
var VulnScan = struct {
	CVEsDetectedTotal *prometheus.CounterVec
	ScansTotal        *prometheus.CounterVec
	ScanDuration      prometheus.Histogram
}{
	CVEsDetectedTotal: promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "vulnscan",
		Name:      "cves_detected_total",
		Help:      "CVEs détectées par sévérité (critical/high/medium/low).",
	}, []string{"severity"}),
	ScansTotal: promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "vulnscan",
		Name:      "scans_total",
		Help:      "Cycles de scan de vulnérabilités.",
	}, []string{"result"}),
	ScanDuration: promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "gpx",
		Subsystem: "vulnscan",
		Name:      "scan_duration_seconds",
		Help:      "Durée totale d'un cycle de scan.",
		Buckets:   []float64{1, 5, 10, 30, 60, 120, 300},
	}),
}

// AdminHTTP expose les métriques du serveur HTTP Admin.
var AdminHTTP = struct {
	RequestsTotal *prometheus.CounterVec
	Duration      *prometheus.HistogramVec
}{
	RequestsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "admin",
		Name:      "http_requests_total",
		Help:      "Requêtes HTTP reçues par l'Admin.",
	}, []string{"method", "status"}),
	Duration: promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "gpx",
		Subsystem: "admin",
		Name:      "http_request_duration_seconds",
		Help:      "Durée des requêtes HTTP Admin.",
		Buckets:   []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
	}, []string{"method"}),
}
