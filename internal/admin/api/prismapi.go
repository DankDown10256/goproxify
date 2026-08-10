// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/analytics"
)

// PrismHandler sert les endpoints d'analyse Prism.
type PrismHandler struct {
	DB *sql.DB
}

func (h *PrismHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/prism")
	path = strings.TrimPrefix(path, "/")

	switch {
	case r.Method == http.MethodGet && path == "kpis":
		h.kpis(w, r)
	case r.Method == http.MethodGet && path == "unique-ips":
		h.uniqueIPs(w, r)
	case r.Method == http.MethodGet && path == "timeline":
		h.timeline(w, r)
	case r.Method == http.MethodGet && path == "status":
		h.status(w, r)
	case r.Method == http.MethodGet && path == "paths":
		h.paths(w, r)
	case r.Method == http.MethodGet && path == "ips":
		h.ips(w, r)
	case r.Method == http.MethodGet && path == "agents":
		h.agents(w, r)
	case r.Method == http.MethodGet && path == "geo":
		h.geo(w, r)
	case r.Method == http.MethodGet && path == "referrers":
		h.referrers(w, r)
	case r.Method == http.MethodGet && path == "compare":
		h.compare(w, r)
	case r.Method == http.MethodGet && path == "proxies":
		h.proxies(w, r)
	case r.Method == http.MethodGet && path == "export":
		h.export(w, r)
	case r.Method == http.MethodGet && path == "backend-errors":
		h.backendErrors(w, r)
	default:
		http.NotFound(w, r)
	}
}

func prismParams(r *http.Request) analytics.Params {
	q := r.URL.Query()
	p := analytics.Params{
		Proxy:    q.Get("proxy"),
		NodeName: q.Get("node_name"),
		IP:       q.Get("ip"),
		Path:     q.Get("path"),
	}
	if f := q.Get("from"); f != "" {
		if t, err := time.Parse(time.RFC3339, f); err == nil {
			p.From = t
		} else if t, err := time.Parse("2006-01-02", f); err == nil {
			p.From = t
		}
	}
	if t := q.Get("to"); t != "" {
		if tt, err := time.Parse(time.RFC3339, t); err == nil {
			p.To = tt
		} else if tt, err := time.Parse("2006-01-02", t); err == nil {
			p.To = tt.Add(24*time.Hour - time.Second)
		}
	}
	// Défaut : dernières 24 h
	if p.From.IsZero() && p.To.IsZero() {
		p.To = time.Now()
		p.From = p.To.Add(-24 * time.Hour)
	} else if p.From.IsZero() {
		p.From = p.To.Add(-24 * time.Hour)
	} else if p.To.IsZero() {
		p.To = time.Now()
	}
	return p
}

func (h *PrismHandler) kpis(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	includeUnique := r.URL.Query().Get("unique_ips") == "1"
	kpis := analytics.GetKPIs(h.DB, p, includeUnique)
	jsonOK(w, kpis)
}

func (h *PrismHandler) uniqueIPs(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	jsonOK(w, map[string]int64{"unique_ips": analytics.GetUniqueIPs(h.DB, p)})
}

func (h *PrismHandler) timeline(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	bucket := r.URL.Query().Get("bucket")
	if bucket == "" {
		bucket = "hour"
	}
	pts := analytics.GetTimeline(h.DB, p, bucket)
	jsonOK(w, pts)
}

func (h *PrismHandler) status(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	groups := analytics.GetStatusGroups(h.DB, p)
	jsonOK(w, groups)
}

func (h *PrismHandler) paths(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	q := r.URL.Query()
	search := q.Get("search")
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	if limit <= 0 {
		limit = 20
	}
	paths, hasMore := analytics.GetTopPaths(h.DB, p, search, limit, offset)
	jsonOK(w, map[string]any{
		"paths":    paths,
		"has_more": hasMore,
		"limit":    limit,
		"offset":   offset,
	})
}

func (h *PrismHandler) ips(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	ips := analytics.GetTopIPs(h.DB, p, limit)
	jsonOK(w, ips)
}

func (h *PrismHandler) agents(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	agents := analytics.GetTopAgents(h.DB, p, limit)
	jsonOK(w, agents)
}

func (h *PrismHandler) proxies(w http.ResponseWriter, r *http.Request) {
	opts := analytics.GetProxies(h.DB, r.URL.Query().Get("node_name"))
	jsonOK(w, opts)
}

func (h *PrismHandler) geo(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	entries := analytics.GetGeoBreakdown(h.DB, p)
	jsonOK(w, entries)
}

func (h *PrismHandler) referrers(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	refs := analytics.GetTopReferrers(h.DB, p, limit)
	jsonOK(w, refs)
}

// compare retourne les KPIs de deux périodes côte à côte.
func (h *PrismHandler) compare(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	parse := func(key string) time.Time {
		v := q.Get(key)
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			return t
		}
		if t, err := time.Parse("2006-01-02", v); err == nil {
			return t
		}
		return time.Time{}
	}
	p1 := analytics.Params{
		Proxy:    q.Get("proxy"),
		NodeName: q.Get("node_name"),
		From:     parse("from1"),
		To:       parse("to1"),
	}
	p2 := analytics.Params{
		Proxy:    q.Get("proxy"),
		NodeName: q.Get("node_name"),
		From:     parse("from2"),
		To:       parse("to2"),
	}
	if p1.From.IsZero() {
		p1.From = time.Now().Add(-48 * time.Hour)
	}
	if p1.To.IsZero() {
		p1.To = time.Now().Add(-24 * time.Hour)
	}
	if p2.From.IsZero() {
		p2.From = time.Now().Add(-24 * time.Hour)
	}
	if p2.To.IsZero() {
		p2.To = time.Now()
	}
	k1 := analytics.GetKPIs(h.DB, p1, true)
	k2 := analytics.GetKPIs(h.DB, p2, true)
	tl1 := analytics.GetTimeline(h.DB, p1, "hour")
	tl2 := analytics.GetTimeline(h.DB, p2, "hour")
	jsonOK(w, map[string]any{
		"period1": map[string]any{"from": p1.From, "to": p1.To, "kpis": k1, "timeline": tl1},
		"period2": map[string]any{"from": p2.From, "to": p2.To, "kpis": k2, "timeline": tl2},
	})
}

func (h *PrismHandler) export(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	format := r.URL.Query().Get("format")
	ts := time.Now().Format("20060102-150405")

	switch format {
	case "json":
		data, err := analytics.ExportJSON(h.DB, p)
		if err != nil {
			prismJSONErr(w, err, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=prism-export-"+ts+".json")
		w.Write(data) //nolint:errcheck
	case "html":
		data, err := analytics.ExportHTML(h.DB, p)
		if err != nil {
			prismJSONErr(w, err, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=prism-report-"+ts+".html")
		w.Write(data) //nolint:errcheck
	default: // csv
		data, err := analytics.ExportCSV(h.DB, p)
		if err != nil {
			prismJSONErr(w, err, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=prism-export-"+ts+".csv")
		w.Write(data) //nolint:errcheck
	}
}

// backendErrors retourne le taux d'erreurs par proxy/backend sur la fenêtre Prism (from/to).
func (h *PrismHandler) backendErrors(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	from := p.From.UTC().Format(time.RFC3339)
	to := p.To.UTC().Format(time.RFC3339)

	// Placeholders JOIN : from, to, [node_name] — puis WHERE : [proxy]
	args := []any{from, to}
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

	rows, err := h.DB.QueryContext(r.Context(),
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
		prismJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type row struct {
		Name       string  `json:"name"`
		Domain     string  `json:"domain"`
		BackendURL string  `json:"backend_url"`
		Total      int64   `json:"total"`
		Errors     int64   `json:"errors"`
		ErrorRate  float64 `json:"error_rate"`
		AvgLatMs   float64 `json:"avg_lat_ms"`
	}
	var out []row
	for rows.Next() {
		var rr row
		var backendURL, domain *string
		var errRate sql.NullFloat64
		if rows.Scan(&rr.Name, &domain, &backendURL, &rr.Total, &rr.Errors, &errRate, &rr.AvgLatMs) != nil {
			continue
		}
		if domain != nil {
			rr.Domain = *domain
		}
		if backendURL != nil {
			rr.BackendURL = *backendURL
		}
		if errRate.Valid {
			rr.ErrorRate = errRate.Float64
		}
		out = append(out, rr)
	}
	if out == nil {
		out = []row{}
	}
	jsonOK(w, out)
}

func prismJSONErr(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
}
