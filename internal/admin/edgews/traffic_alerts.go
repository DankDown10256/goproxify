// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/admin/alerting"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

// Alerte « trafic hors de sa référence saisonnière » (ADR 0020, étape 3.b). Chaque passerelle redit toutes ses alertes en cours ; l'Admin
// n'alerte qu'une fois par alerte (route et date de début) et de nouveau si elle s'aggrave (avertissement → attaque probable). Une
// alerte qui disparaît est oubliée : si le trafic dérive de nouveau, une nouvelle alerte part.

type trafficAlertKey struct{ node, route string }

type trafficAlertSeen struct {
	since    time.Time
	level    string
	hardened bool
}

type trafficAlertState struct {
	mu   sync.Mutex
	seen map[trafficAlertKey]trafficAlertSeen
}

func (m *Manager) handleTrafficDeviation(raw json.RawMessage) {
	var p edgeWS.TrafficDeviationPayload
	if err := json.Unmarshal(raw, &p); err != nil || p.NodeName == "" {
		return
	}
	m.trafficAlerts.mu.Lock()
	events := trafficDeviationEvents(p, m.trafficAlerts.seenMap())
	m.trafficAlerts.mu.Unlock()
	if m.alertEngine == nil {
		return
	}
	for _, ev := range events {
		m.alertEngine.Emit(ev)
	}
}

func (s *trafficAlertState) seenMap() map[trafficAlertKey]trafficAlertSeen {
	if s.seen == nil {
		s.seen = map[trafficAlertKey]trafficAlertSeen{}
	}
	return s.seen
}

// trafficDeviationEvents rend les alertes à émettre pour ce message et met à jour ce qui a déjà été signalé.
func trafficDeviationEvents(p edgeWS.TrafficDeviationPayload, seen map[trafficAlertKey]trafficAlertSeen) []alerting.Event {
	live := map[trafficAlertKey]bool{}
	var out []alerting.Event
	for _, a := range p.Alerts {
		k := trafficAlertKey{p.NodeName, a.Route}
		live[k] = true
		prev, known := seen[k]
		if known && prev.since.Equal(a.Since) && (prev.level == a.Level || a.Level != "probable") && (prev.hardened || !a.Hardened) {
			continue
		}
		seen[k] = trafficAlertSeen{since: a.Since, level: a.Level, hardened: a.Hardened}
		sev := alerting.SevWarning
		if a.Level == "probable" {
			sev = alerting.SevCritical
		}
		out = append(out, alerting.Event{
			Trigger:  alerting.TriggerTrafficDeviation,
			Severity: sev,
			NodeName: p.NodeName,
			Domain:   a.Route,
			Detail: map[string]any{
				"route": a.Route, "level": a.Level, "rps": round1(a.RPS), "expected": round1(a.Expected),
				"natures": strings.Join(a.Natures, ", "), "hardened": a.Hardened,
			},
		})
	}
	for k := range seen {
		if k.node == p.NodeName && !live[k] {
			delete(seen, k)
		}
	}
	return out
}

func round1(f float64) float64 { return float64(int(f*10+0.5)) / 10 }
