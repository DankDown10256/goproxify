// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/vincamok/goproxify/internal/admin/automation"
)

// MetricPoint est une valeur courante proposée aux flux d'automatisation (condition metric_threshold).
type MetricPoint struct {
	Key    string
	Entity string
	Value  float64
}

// AutomationMetrics décrit les métriques que le relevé des passerelles et l'Admin savent fournir.
var AutomationMetrics = []automation.MetricDef{
	{Key: "proxy.rps", Label: "Requêtes par seconde d'un proxy", Unit: "req/s", Scope: "host", Kind: "gauge"},
	{Key: "proxy.error_rate_pct", Label: "Taux d'erreurs 5xx d'un proxy", Unit: "%", Scope: "host", Kind: "gauge"},
	{Key: "proxy.p95_ms", Label: "Latence P95 d'un proxy", Unit: "ms", Scope: "host", Kind: "gauge"},
	{Key: "edge.rps", Label: "Requêtes par seconde d'une passerelle", Unit: "req/s", Scope: "edge", Kind: "gauge"},
	{Key: "edge.error_rate_pct", Label: "Taux d'erreurs 5xx d'une passerelle", Unit: "%", Scope: "edge", Kind: "gauge"},
	{Key: "edge.p95_ms", Label: "Latence P95 d'une passerelle", Unit: "ms", Scope: "edge", Kind: "gauge"},
	{Key: "global.rps", Label: "Requêtes par seconde (toutes passerelles)", Unit: "req/s", Scope: "global", Kind: "gauge"},
	{Key: "global.error_rate_pct", Label: "Taux d'erreurs 5xx (toutes passerelles)", Unit: "%", Scope: "global", Kind: "gauge"},
	{Key: "tls.cert_expires_days", Label: "Jours avant expiration d'un certificat servi", Unit: "jours", Scope: "domain", Kind: "gauge"},
	{Key: "tls.handshake_p95_ms", Label: "Latence P95 de la poignée de main TLS", Unit: "ms", Scope: "host", Kind: "gauge"},
	{Key: "tls.active_connections", Label: "Connexions TLS actives", Scope: "host", Kind: "gauge"},
	{Key: "ws.agent_connections", Label: "Agents connectés aux passerelles", Scope: "global", Kind: "gauge"},
	{Key: "portal.sessions", Label: "Sessions du portail Access", Scope: "global", Kind: "gauge"},
	{Key: "waf.profiles_active", Label: "Profils WAF actifs", Scope: "global", Kind: "gauge"},
	{Key: "pipeline.blocked_total", Label: "Requêtes arrêtées par étape du pipeline", Scope: "stage", Kind: "counter"},
	{Key: "fleet.bans_total", Label: "Bans des Seuils multi-passerelles (Admin)", Scope: "global", Kind: "counter"},
	{Key: "crowdsec.decisions_total", Label: "Décisions CrowdSec reçues (Admin)", Scope: "global", Kind: "counter"},
	{Key: "vulnscan.cves_total", Label: "CVE détectées par le scanner", Scope: "global", Kind: "counter"},
	{Key: "admin.http_requests_total", Label: "Requêtes reçues par l'Admin", Scope: "global", Kind: "counter"},
}

// AutomationSamples retourne les dernières valeurs relevées. Une série n'est fournie que si le dernier
// relevé l'a vue : une valeur figée ne doit pas déclencher de flux.
func (s *ProxyMetricsSampler) AutomationSamples() []MetricPoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []MetricPoint
	add := func(key, entity string, v float64) {
		out = append(out, MetricPoint{Key: key, Entity: entity, Value: v})
	}
	if s.sampledAt.IsZero() {
		return nil
	}
	for host, ser := range s.series {
		if len(ser) == 0 || !ser[len(ser)-1].T.Equal(s.sampledAt) {
			continue
		}
		last := ser[len(ser)-1]
		add("proxy.rps", host, last.RPS)
		add("proxy.error_rate_pct", host, last.ErrRate*100)
		add("proxy.p95_ms", host, last.P95ms)
	}
	for edge, w := range s.edgeLast {
		add("edge.rps", edge, w.RPS)
		add("edge.error_rate_pct", edge, w.ErrRate*100)
		add("edge.p95_ms", edge, w.P95ms)
	}
	add("global.rps", "", s.global.RPS)
	add("global.error_rate_pct", "", s.global.ErrRate*100)
	certDays := map[string]float64{}
	var agents, sessions, waf float64
	stages := map[string]float64{}
	for edge, sum := range s.summ {
		for _, c := range s.certs[edge] {
			if d, ok := certDays[c.Domain]; !ok || c.ExpSecs/86400 < d {
				certDays[c.Domain] = c.ExpSecs / 86400
			}
		}
		for _, h := range sum.TLSHosts {
			add("tls.handshake_p95_ms", h.Host, h.HandshakeP95ms)
			add("tls.active_connections", h.Host, h.ActiveConnections)
		}
		for _, p := range sum.Pipeline {
			stages[p.Stage] += p.Count
		}
		agents += sum.WS.AgentConnections
		sessions += sum.Portal.Sessions.OneShot + sum.Portal.Sessions.Multi
		waf = max(waf, sum.WAF.ProfilesActive)
	}
	for d, v := range certDays {
		add("tls.cert_expires_days", d, v)
	}
	for st, v := range stages {
		add("pipeline.blocked_total", st, v)
	}
	if len(s.summ) > 0 {
		add("ws.agent_connections", "", agents)
		add("portal.sessions", "", sessions)
		add("waf.profiles_active", "", waf)
	}
	return out
}

// AdminMetricSamples lit les compteurs Prometheus de l'Admin proposés aux flux.
func AdminMetricSamples() []MetricPoint {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return nil
	}
	keys := map[string]string{
		"gpx_fleet_bans_total":             "fleet.bans_total",
		"gpx_crowdsec_decisions_total":     "crowdsec.decisions_total",
		"gpx_vulnscan_cves_detected_total": "vulnscan.cves_total",
		"gpx_admin_http_requests_total":    "admin.http_requests_total",
	}
	sums := map[string]float64{}
	for _, mf := range mfs {
		key, ok := keys[mf.GetName()]
		if !ok {
			continue
		}
		for _, m := range mf.GetMetric() {
			sums[key] += m.GetCounter().GetValue()
		}
	}
	var out []MetricPoint
	for k, v := range sums {
		out = append(out, MetricPoint{Key: k, Value: v})
	}
	return out
}
