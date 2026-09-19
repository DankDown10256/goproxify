// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package adminmetrics expose les métriques Prometheus des moteurs de sécurité Admin.
package adminmetrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// F2B expose les métriques du moteur Fail2Ban.
var F2B = struct {
	BansTotal  prometheus.Counter
	ScansTotal prometheus.Counter
}{
	BansTotal: promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "f2b",
		Name:      "bans_total",
		Help:      "Nombre total d'IPs bannies automatiquement par Fail2Ban.",
	}),
	ScansTotal: promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "f2b",
		Name:      "scans_total",
		Help:      "Nombre total de cycles de scan Fail2Ban.",
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

// RulesEngine expose les métriques du moteur de règles.
var RulesEngine = struct {
	EvalsTotal    prometheus.Counter
	EvalDuration  prometheus.Histogram
	ActiveRules   prometheus.Gauge
	ActionsTotal  *prometheus.CounterVec
}{
	EvalsTotal: promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "rulesengine",
		Name:      "evals_total",
		Help:      "Nombre total de cycles d'évaluation du moteur de règles.",
	}),
	EvalDuration: promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: "gpx",
		Subsystem: "rulesengine",
		Name:      "eval_duration_seconds",
		Help:      "Durée d'un cycle complet d'évaluation des règles.",
		Buckets:   []float64{.001, .005, .01, .05, .1, .5, 1, 5},
	}),
	ActiveRules: promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "gpx",
		Subsystem: "rulesengine",
		Name:      "active_rules",
		Help:      "Nombre de règles activées dans le moteur.",
	}),
	ActionsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "rulesengine",
		Name:      "actions_total",
		Help:      "Actions déclenchées par le moteur de règles.",
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
