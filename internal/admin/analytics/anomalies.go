// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

import (
	"context"
	"database/sql"
	"math"
	"sort"
	"time"
)

// BackendError taux d'erreurs d'un proxy (et de son backend) sur la période.
type BackendError struct {
	Name       string  `json:"name"`
	Domain     string  `json:"domain"`
	BackendURL string  `json:"backend_url"`
	Total      int64   `json:"total"`
	Errors     int64   `json:"errors"`
	ErrorRate  float64 `json:"error_rate"`
	AvgLatMs   float64 `json:"avg_lat_ms"`
}

// GetBackendErrors retourne les 20 proxys actifs les plus en erreur sur la période.
func GetBackendErrors(ctx context.Context, db *sql.DB, p Params) ([]BackendError, error) {
	// Placeholders JOIN : from, to, [node_name] — puis WHERE : [proxy]
	args := []any{p.From.UTC().Format(time.RFC3339), p.To.UTC().Format(time.RFC3339)}
	nodeJoin := ""
	if p.NodeName != "" {
		nodeJoin = " AND l.node_name = ?"
		args = append(args, p.NodeName)
	}
	proxyFilter := ""
	if p.Proxy != "" {
		proxyFilter = " AND json_extract(p.config,'$.host') = ?"
		args = append(args, p.Proxy)
	}
	rows, err := db.QueryContext(ctx,
		`SELECT
		   p.name,
		   json_extract(p.config,'$.host') AS domain,
		   json_extract(p.config,'$.backend') AS backend_url,
		   COUNT(l.id)                          AS total,
		   SUM(CASE WHEN l.status>=400 THEN 1 ELSE 0 END) AS errors,
		   ROUND(100.0*SUM(CASE WHEN l.status>=400 THEN 1 ELSE 0 END)/NULLIF(COUNT(l.id),0),1) AS error_rate,
		   ROUND(AVG(l.latency_ms),0)            AS avg_lat_ms
		 FROM proxies p
		 LEFT JOIN logs l ON l.domain = json_extract(p.config,'$.host')
		                 AND l.ts >= ?
		                 AND l.ts <= ?
		                 AND l.status > 0`+nodeJoin+`
		 WHERE p.enabled=1`+proxyFilter+`
		 GROUP BY p.id
		 HAVING COUNT(l.id) > 0
		 ORDER BY error_rate DESC, total DESC
		 LIMIT 20`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BackendError{}
	for rows.Next() {
		var r BackendError
		var backendURL, domain *string
		var errRate sql.NullFloat64
		if rows.Scan(&r.Name, &domain, &backendURL, &r.Total, &r.Errors, &errRate, &r.AvgLatMs) != nil {
			continue
		}
		if domain != nil {
			r.Domain = *domain
		}
		if backendURL != nil {
			r.BackendURL = *backendURL
		}
		if errRate.Valid {
			r.ErrorRate = errRate.Float64
		}
		out = append(out, r)
	}
	return out, nil
}

// Anomaly écart notable détecté sur la période. Le texte affiché est construit côté UI
// (traduit) à partir de Kind et des valeurs.
type Anomaly struct {
	Kind     string  `json:"kind"`     // error_spike | dominant_ip | country_errors | backend_errors | bot_share
	Level    string  `json:"level"`    // critical | warning
	Subject  string  `json:"subject"`  // bucket, IP, code pays ou domaine
	Label    string  `json:"label"`    // nom lisible (pays, backend)
	Value    float64 `json:"value"`    // valeur mesurée (erreurs, part %, taux %)
	Baseline float64 `json:"baseline"` // valeur habituelle (moyenne) quand elle a un sens
	Count    int64   `json:"count"`    // volume de requêtes concerné
	Banned   bool    `json:"banned,omitempty"`
}

// DetectAnomalies applique des règles simples sur la période (pas de modèle appris).
// Résultat trié : critiques d'abord, puis par ordre de détection.
func DetectAnomalies(ctx context.Context, db *sql.DB, p Params) []Anomaly {
	out := []Anomaly{}

	// Pic d'erreurs : point de la courbe > moyenne + 2,5 écarts-types (au moins 10 erreurs).
	bucket := "hour"
	if p.To.Sub(p.From) <= 6*time.Hour {
		bucket = "minute"
	}
	if tl := GetTimeline(db, p, bucket); len(tl) >= 4 {
		var sum float64
		for _, pt := range tl {
			sum += float64(pt.Errors)
		}
		mean := sum / float64(len(tl))
		var sq float64
		for _, pt := range tl {
			sq += math.Pow(float64(pt.Errors)-mean, 2)
		}
		sd := math.Sqrt(sq / float64(len(tl)))
		peak := tl[0]
		for _, pt := range tl {
			if pt.Errors > peak.Errors {
				peak = pt
			}
		}
		if peak.Errors >= 10 && float64(peak.Errors) > mean+2.5*sd {
			out = append(out, Anomaly{Kind: "error_spike", Level: "critical", Subject: peak.Bucket,
				Value: float64(peak.Errors), Baseline: mean, Count: peak.Requests})
		}
	}

	reqs, _, _, bots, _ := rawKPIs(db, p)

	// IP dominante : ≥ 20 % des requêtes de la période (et au moins 50).
	if ips := GetTopIPs(db, p, 1); len(ips) == 1 && reqs > 0 {
		if share := float64(ips[0].Requests) / float64(reqs); share >= 0.2 && ips[0].Requests >= 50 {
			out = append(out, Anomaly{Kind: "dominant_ip", Level: "warning", Subject: ips[0].IP,
				Value: share * 100, Count: ips[0].Requests, Banned: activeBannedIPSet(db)[ips[0].IP]})
		}
	}

	// Pays en erreur : ≥ 10 % d'erreurs sur au moins 50 requêtes (2 maximum).
	n := 0
	for _, g := range GetGeoBreakdown(db, p) {
		if g.Requests >= 50 && g.ErrorRate >= 10 && n < 2 {
			out = append(out, Anomaly{Kind: "country_errors", Level: "warning", Subject: g.CountryCode,
				Label: g.CountryName, Value: g.ErrorRate, Count: g.Requests})
			n++
		}
	}

	// Backends en difficulté : > 10 % d'erreurs sur au moins 20 requêtes (2 maximum).
	if rows, err := GetBackendErrors(ctx, db, p); err == nil {
		n = 0
		for _, r := range rows {
			if r.Total >= 20 && r.ErrorRate > 10 && n < 2 {
				out = append(out, Anomaly{Kind: "backend_errors", Level: "critical", Subject: r.Domain,
					Label: r.Name, Value: r.ErrorRate, Count: r.Total})
				n++
			}
		}
	}

	// Part de bots ≥ 30 %.
	if reqs > 0 {
		if share := float64(bots) / float64(reqs) * 100; share >= 30 {
			out = append(out, Anomaly{Kind: "bot_share", Level: "warning", Value: share, Count: bots})
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Level == "critical" && out[j].Level != "critical" })
	return out
}
