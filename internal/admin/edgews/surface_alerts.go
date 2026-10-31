// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/admin/alerting"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

// Alerte « ajout suggéré à la politique de surface » (ADR 0016). Chaque passerelle envoie l'état de ses suggestions ; l'Admin en
// déduit les nouvelles et alerte une fois par proxy et par lot. Une suggestion déjà signalée ne re-déclenche pas, et celle qui
// disparaît (acceptée, ou plus assez soutenue) est oubliée : si elle revient, elle alertera de nouveau.

// surfaceMaxListed : nombre d'ajouts nommés dans le message d'alerte.
const surfaceMaxListed = 5

type surfaceSuggestionState struct {
	mu      sync.Mutex
	byNode  map[string]map[string]edgeWS.SurfaceProxyPayload // passerelle → proxy → suggestions
	alerted map[string]time.Time                             // « proxy|clé » → date de l'alerte
}

func (m *Manager) handleSurfaceSuggestions(raw json.RawMessage) {
	var p edgeWS.SurfaceSuggestionsPayload
	if err := json.Unmarshal(raw, &p); err != nil || p.NodeName == "" {
		return
	}
	now := time.Now()
	m.surfaceAlerts.mu.Lock()
	if m.surfaceAlerts.byNode == nil {
		m.surfaceAlerts.byNode = map[string]map[string]edgeWS.SurfaceProxyPayload{}
		m.surfaceAlerts.alerted = map[string]time.Time{}
	}
	cur := make(map[string]edgeWS.SurfaceProxyPayload, len(p.Proxies))
	for _, px := range p.Proxies {
		cur[px.Route] = px
	}
	m.surfaceAlerts.byNode[p.NodeName] = cur
	events := surfaceSuggestionEvents(p.NodeName, m.surfaceAlerts.byNode, m.surfaceAlerts.alerted, now)
	m.surfaceAlerts.mu.Unlock()
	if m.alertEngine == nil {
		return
	}
	for _, ev := range events {
		m.alertEngine.Emit(ev)
	}
}

// surfaceSuggestionEvents rend les alertes à émettre : une par proxy qui a de nouvelles suggestions de confiance haute. Les basses
// (« à examiner », où un scanner distribué se confond avec des clients ordinaires) ne réveillent personne ; elles sont comptées dans
// le message. byNode porte l'état de toutes les passerelles : les membres d'un groupe HA rendent le même profil fusionné, une
// suggestion n'alerte donc qu'une fois, quelle que soit la passerelle qui la signale la première.
func surfaceSuggestionEvents(node string, byNode map[string]map[string]edgeWS.SurfaceProxyPayload, alerted map[string]time.Time, now time.Time) []alerting.Event {
	live := map[string]bool{}
	for _, proxies := range byNode {
		for route, px := range proxies {
			for _, s := range px.Suggestions {
				live[route+"|"+s.Key] = true
			}
		}
	}
	for k := range alerted {
		if !live[k] {
			delete(alerted, k)
		}
	}

	routes := make([]string, 0, len(byNode[node]))
	for r := range byNode[node] {
		routes = append(routes, r)
	}
	sort.Strings(routes)
	var out []alerting.Event
	for _, route := range routes {
		px := byNode[node][route]
		var fresh []edgeWS.SurfaceSuggestionPayload
		low := 0
		for _, s := range px.Suggestions {
			key := route + "|" + s.Key
			if s.Confidence != "high" {
				low++
				continue
			}
			if _, done := alerted[key]; done {
				continue
			}
			alerted[key] = now
			fresh = append(fresh, s)
		}
		if len(fresh) == 0 {
			continue
		}
		listed := make([]string, 0, surfaceMaxListed+1)
		for i, s := range fresh {
			if i == surfaceMaxListed {
				listed = append(listed, "… (+"+strconv.Itoa(len(fresh)-surfaceMaxListed)+")")
				break
			}
			listed = append(listed, s.Method+" "+s.Path)
		}
		out = append(out, alerting.Event{
			Trigger: alerting.TriggerSurfaceSuggestion, Severity: alerting.SevInfo, NodeName: node, Domain: px.Host, Component: "edge", FiredAt: now,
			Detail: map[string]any{
				"proxy": route, "domain": px.Host, "count": len(fresh), "suggestions": strings.Join(listed, ", "), "low_confidence": low,
			},
		})
	}
	return out
}
