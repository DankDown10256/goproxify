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
	EvalsTotal   prometheus.Counter
	ActionsTotal *prometheus.CounterVec
}{
	EvalsTotal: promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "rulesengine",
		Name:      "evals_total",
		Help:      "Nombre total de cycles d'évaluation du moteur de règles.",
	}),
	ActionsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "rulesengine",
		Name:      "actions_total",
		Help:      "Actions déclenchées par le moteur de règles.",
	}, []string{"action", "result"}),
}
