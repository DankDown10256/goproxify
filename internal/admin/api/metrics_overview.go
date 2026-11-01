// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// evalsWindow : durée sur laquelle on lisse le débit des évaluations des flux à condition.
const evalsWindow = 2 * time.Minute

// adminLocal : métriques Prometheus du processus Admin (Seuils multi-passerelles, CrowdSec, flux d'automatisation).
type adminLocal struct {
	fleetBans, fleetScans          float64
	csNew, csDeleted            float64
	evalsTotal                  float64
	evalSumS, evalCount         float64
	activeRules, actionsTotal   float64
	hasFleet, hasCS, hasRulesEval bool
}

func readAdminLocal() adminLocal {
	var a adminLocal
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return a
	}
	for _, mf := range mfs {
		name := mf.GetName()
		if !strings.HasPrefix(name, "gpx_fleet_") && !strings.HasPrefix(name, "gpx_crowdsec_") && !strings.HasPrefix(name, "gpx_automation_") {
			continue
		}
		for _, m := range mf.GetMetric() {
			switch name {
			case "gpx_fleet_bans_total":
				a.fleetBans, a.hasFleet = m.GetCounter().GetValue(), true
			case "gpx_fleet_scans_total":
				a.fleetScans, a.hasFleet = m.GetCounter().GetValue(), true
			case "gpx_crowdsec_decisions_total":
				a.hasCS = true
				for _, l := range m.GetLabel() {
					if l.GetName() != "action" {
						continue
					}
					switch l.GetValue() {
					case "new":
						a.csNew += m.GetCounter().GetValue()
					case "deleted":
						a.csDeleted += m.GetCounter().GetValue()
					}
				}
			case "gpx_automation_evals_total":
				a.evalsTotal, a.hasRulesEval = m.GetCounter().GetValue(), true
			case "gpx_automation_eval_duration_seconds":
				a.evalSumS += m.GetHistogram().GetSampleSum()
				a.evalCount += float64(m.GetHistogram().GetSampleCount())
			case "gpx_automation_active_flows":
				a.activeRules += m.GetGauge().GetValue()
			case "gpx_automation_actions_total":
				a.actionsTotal += m.GetCounter().GetValue()
			}
		}
	}
	return a
}

// recordEvals mémorise le compteur de cycles du moteur de règles (appelé à chaque relevé).
func (s *ProxyMetricsSampler) recordEvals(now time.Time, total float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evals = append(s.evals, evalPoint{now, total})
	for len(s.evals) > 1 && now.Sub(s.evals[0].t) > evalsWindow {
		s.evals = s.evals[1:]
	}
}

// evalsPerMinute : cycles par minute sur la fenêtre mémorisée (nil tant qu'il y a moins de 2 points).
func (s *ProxyMetricsSampler) evalsPerMinute() any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.evals) < 2 {
		return nil
	}
	first, last := s.evals[0], s.evals[len(s.evals)-1]
	dt := last.t.Sub(first.t).Minutes()
	if dt <= 0 || last.v < first.v {
		return nil
	}
	return (last.v - first.v) / dt
}

// Summary assemble la synthèse lue par les pages Dashboard, Prism, Domaines/TLS, Infrastructure,
// Portail et Sécurité : agrégats des passerelles (dernier relevé) et métriques du processus Admin.
func (s *ProxyMetricsSampler) Summary() map[string]any {
	global, edges, certs := s.Overview()

	s.mu.RLock()
	var wsAdmin, wsAgent, oneShot, multi, wafProfiles float64
	pipe := map[string]float64{}
	type tlsAgg struct{ p95, conns float64 }
	tlsHosts := map[string]tlsAgg{}
	for _, sum := range s.summ {
		wsAdmin += sum.WS.AdminConnections
		wsAgent += sum.WS.AgentConnections
		oneShot += sum.Portal.Sessions.OneShot
		multi += sum.Portal.Sessions.Multi
		wafProfiles += sum.WAF.ProfilesActive
		for _, p := range sum.Pipeline {
			pipe[p.Stage] += p.Count
		}
		for _, h := range sum.TLSHosts {
			a := tlsHosts[strings.ToLower(h.Host)]
			a.p95 = max(a.p95, h.HandshakeP95ms) // le pire des passerelles
			a.conns += h.ActiveConnections
			tlsHosts[strings.ToLower(h.Host)] = a
		}
	}
	var peerSyncMs float64
	for _, ms := range s.peerSyncMs {
		peerSyncMs += ms
	}
	peerEdges := len(s.peerSyncMs)
	s.mu.RUnlock()

	certList := make([]map[string]any, 0, len(certs))
	for _, c := range certs {
		e := map[string]any{"domain": c.Domain, "expires_in_seconds": c.ExpiresInSeconds}
		if a, ok := tlsHosts[strings.ToLower(c.Domain)]; ok {
			e["handshake_p95_ms"] = a.p95
			e["active_connections"] = a.conns
		}
		certList = append(certList, e)
	}
	pipeline := make([]map[string]any, 0, len(pipe))
	for stage, n := range pipe {
		pipeline = append(pipeline, map[string]any{"stage": stage, "blocked_total": n})
	}
	sort.Slice(pipeline, func(i, j int) bool { return pipeline[i]["stage"].(string) < pipeline[j]["stage"].(string) })

	out := map[string]any{
		"global":   global,
		"edges":    edges,
		"ws":       map[string]any{"admin_connections": wsAdmin, "agent_connections": wsAgent},
		"portal":   map[string]any{"sessions": map[string]any{"one_shot": oneShot, "multi": multi}},
		"waf":      map[string]any{"profiles_active": wafProfiles},
		"pipeline": pipeline,
		"tls":      map[string]any{"certs": certList},
	}
	if peerEdges > 0 {
		out["peers"] = map[string]any{"avg_sync_ms": peerSyncMs / float64(peerEdges)}
	}

	a := readAdminLocal()
	if a.hasFleet {
		out["fleet"] = map[string]any{"bans_total": a.fleetBans, "scans_total": a.fleetScans}
	}
	if a.hasCS {
		out["crowdsec"] = map[string]any{"decisions_new": a.csNew, "decisions_deleted": a.csDeleted}
	}
	if a.hasRulesEval {
		re := map[string]any{"active_flows": a.activeRules, "actions_total": a.actionsTotal, "evals_per_minute": s.evalsPerMinute()}
		if a.evalCount > 0 {
			re["avg_duration_ms"] = a.evalSumS / a.evalCount * 1000
		}
		out["automation"] = re
	}
	return out
}

// ServeSummary : GET /api/v1/metrics/summary — voir Summary.
func (s *ProxyMetricsSampler) ServeSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
		return
	}
	jsonOK(w, s.Summary())
}
