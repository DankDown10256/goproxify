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
		Help:      "Nombre de requêtes inspectées par Ephor.",
	}, []string{"action"}) // action: allow | detect | block

	threatSignalsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "threat",
		Name:      "signals_total",
		Help:      "Signaux de menace détectés par Ephor.",
	}, []string{"reason"}) // reason: ip | ua | path | rate | error4xx | custom_ip | custom_ua | custom_path

	threatBansTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "threat",
		Name:      "bans_total",
		Help:      "Nombre de bans automatiques émis par Ephor.",
	}, []string{"reason"})

	threatShadowBansTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "threat",
		Name:      "shadow_bans_total",
		Help:      "Bans que la note commune d'Ephor aurait posés si ses signaux en detect étaient en block (ou en mode detect).",
	})

	threatChallengeTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "threat",
		Name:      "challenge_total",
		Help:      "Défis à preuve de travail imposés par Ephor avant le ban (result: served = page servie, shadow = mode detect, solved | failed = solution reçue).",
	}, []string{"result"})

	threatDecoyTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "threat",
		Name:      "decoy_total",
		Help:      "Accès à un chemin-leurre (result: hit = versé à la note, shadow = mode detect, skipped = chemin que le trafic légitime du proxy utilise).",
	}, []string{"result"})

	threatThresholdTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "threat",
		Name:      "threshold_total",
		Help:      "Dépassements d'un Seuil (result: hit = action appliquée, shadow = mode detect).",
	}, []string{"result"})

	threatUnknownHostTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "threat",
		Name:      "unknown_host_total",
		Help:      "Accès à un hôte inconnu vus par Ephor (result: counted = versé à la note, shadow = mode detect, exempt = sonde déclarée, liste blanche, réseau privé ou Cloudflare, regular = cadence régulière : sonde probable).",
	}, []string{"result"})

	threatGlobalRateLimitTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "threat",
		Name:      "global_ratelimit_total",
		Help:      "Requêtes rejetées par le limiteur global (DDoS volumétrique).",
	})

	threatTarpitTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "threat",
		Name:      "tarpit_total",
		Help:      "Requêtes traitées par le tarpit Ephor (result: held = retenue, full = refusée faute de slot).",
	}, []string{"result"})

	threatTarpitActive = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "gpx",
		Subsystem: "threat",
		Name:      "tarpit_active",
		Help:      "Requêtes actuellement retenues par le tarpit Ephor.",
	})

	threatEvictionsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "gpx",
		Subsystem: "threat",
		Name:      "counter_evictions_total",
		Help:      "Entrées de suivi par IP évincées faute de place (table pleine, attaque distribuée probable).",
	})
)

// inc incrémente un compteur, sauf pour un moteur de simulation (Simulate).
func (e *Engine) inc(v *prometheus.CounterVec, label string) {
	if !e.sim {
		v.WithLabelValues(label).Inc()
	}
}

var threatSeasonalTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "gpx",
	Subsystem: "threat",
	Name:      "seasonal_total",
	Help:      "Changements d'état des alertes de trafic de la référence saisonnière (kind: start | escalate | end ; level: warning | probable).",
}, []string{"kind", "level"})

func (e *Engine) inc2(v *prometheus.CounterVec, a, b string) {
	if !e.sim {
		v.WithLabelValues(a, b).Inc()
	}
}

var threatSeasonalHardenTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "gpx",
	Subsystem: "threat",
	Name:      "seasonal_harden_total",
	Help:      "Requêtes traitées par le profil durci d'une route en attaque probable (result: challenged = défi servi, shed = plafond atteint).",
}, []string{"result"})

var threatEnumerationTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "gpx",
	Subsystem: "threat",
	Name:      "enumeration_total",
	Help:      "Dépassements de la norme de valeurs distinctes d'un gabarit de chemin (result: hit = points versés, shadow = mode detect, unproven = profil de surface absent, non convergé ou gabarit inconnu).",
}, []string{"result"})
