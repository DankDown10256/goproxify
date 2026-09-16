// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	threatChecksTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "threat",
		Name:      "checks_total",
		Help:      "Nombre de requêtes inspectées par Sentinel.",
	}, []string{"action"}) // action: allow | detect | block

	threatSignalsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "threat",
		Name:      "signals_total",
		Help:      "Signaux de menace détectés par Sentinel.",
	}, []string{"reason"}) // reason: ip | ua | path | rate | error4xx | custom_ip | custom_ua | custom_path

	threatBansTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "threat",
		Name:      "bans_total",
		Help:      "Nombre de bans automatiques émis par Sentinel.",
	}, []string{"reason"})

	threatGlobalRateLimitTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "threat",
		Name:      "global_ratelimit_total",
		Help:      "Requêtes rejetées par le limiteur global (DDoS volumétrique).",
	})
)
