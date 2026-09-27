// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/analytics"
	"github.com/vincamok/goproxify/internal/admin/rbac"
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
	case r.Method == http.MethodGet && path == "geo/points":
		h.geoPoints(w, r)
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
	case r.Method == http.MethodGet && path == "slo":
		h.slo(w, r)
	case r.Method == http.MethodGet && path == "slo/config":
		h.getSLOConfig(w, r)
	case r.Method == http.MethodPut && path == "slo/config":
		rbac.RequireAdmin(h.DB)(http.HandlerFunc(h.putSLOConfig)).ServeHTTP(w, r)
	case r.Method == http.MethodDelete && path == "slo/config":
		rbac.RequireAdmin(h.DB)(http.HandlerFunc(h.deleteSLOConfig)).ServeHTTP(w, r)
	case r.Method == http.MethodGet && path == "anomalies":
		h.anomalies(w, r)
	case r.Method == http.MethodGet && path == "deploys":
		h.deploys(w, r)
	case r.Method == http.MethodGet && path == "bans/timeline":
		h.bansTimeline(w, r)
	case r.Method == http.MethodGet && path == "bans/by-source":
		h.bansBySource(w, r)
	case r.Method == http.MethodGet && path == "bans/breakdown":
		h.bansBreakdown(w, r)
	case r.Method == http.MethodGet && path == "ip-scan":
		h.ipScan(w, r)
	case r.Method == http.MethodGet && path == "bans/top-ips":
		h.bansTopIPs(w, r)
	case r.Method == http.MethodGet && path == "live-ips":
		h.liveIPs(w, r)
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

func (h *PrismHandler) liveIPs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since := time.Now().Add(-10 * time.Second)
	if s := q.Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		} else if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			since = t
		}
	}
	limit := 100
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
		limit = l
	}
	events := analytics.GetLiveIPs(h.DB, since, q.Get("proxy"), q.Get("node_name"), limit)
	if events == nil {
		events = []analytics.LiveIPEvent{}
	}
	jsonOK(w, events)
}

func (h *PrismHandler) geo(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	entries := analytics.GetGeoBreakdown(h.DB, p)
	jsonOK(w, entries)
}

func (h *PrismHandler) geoPoints(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	jsonOK(w, analytics.GetGeoPoints(h.DB, p, limit))
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
	rows, err := analytics.GetBackendErrors(r.Context(), h.DB, prismParams(r))
	if err != nil {
		prismJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, rows)
}

// getSLOConfig : objectif SLO résolu pour ?node_name= (repli sur le global), avec is_override et,
// pour une passerelle, global_target (utile à l'écran pour proposer « revenir au global »).
func (h *PrismHandler) getSLOConfig(w http.ResponseWriter, r *http.Request) {
	node := r.URL.Query().Get("node_name")
	out := map[string]any{"target": analytics.LoadSLOTarget(r.Context(), h.DB, node)}
	if node != "" {
		out["is_override"] = analytics.HasSLOTargetOverride(r.Context(), h.DB, node)
		out["global_target"] = analytics.LoadSLOTarget(r.Context(), h.DB)
	}
	jsonOK(w, out)
}

// putSLOConfig enregistre l'objectif SLO (%) : global, ou propre à une passerelle avec ?node_name=.
// Partagé par l'écran, l'API, le MCP et l'alerte slo_burn.
func (h *PrismHandler) putSLOConfig(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Target float64 `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !analytics.ValidSLOTarget(body.Target) {
		prismJSONErr(w, errors.New("target doit être compris entre 90 et 99.999"), http.StatusBadRequest)
		return
	}
	node := r.URL.Query().Get("node_name")
	if err := analytics.SaveSLOTarget(r.Context(), h.DB, body.Target, node); err != nil {
		prismJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]float64{"target": body.Target})
}

// deleteSLOConfig retire l'objectif propre à une passerelle (?node_name=, requis) : retour au global.
func (h *PrismHandler) deleteSLOConfig(w http.ResponseWriter, r *http.Request) {
	node := r.URL.Query().Get("node_name")
	if node == "" {
		prismJSONErr(w, errors.New("node_name requis"), http.StatusBadRequest)
		return
	}
	if err := analytics.ClearSLOTarget(r.Context(), h.DB, node); err != nil {
		prismJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]float64{"target": analytics.LoadSLOTarget(r.Context(), h.DB)})
}

// slo retourne l'SLO de disponibilité (5xx) sur une fenêtre glissante : target (%, défaut : objectif enregistré), days (défaut 30), proxy, node_name.
func (h *PrismHandler) slo(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	target, _ := strconv.ParseFloat(q.Get("target"), 64)
	days, _ := strconv.Atoi(q.Get("days"))
	p := analytics.Params{Proxy: q.Get("proxy"), NodeName: q.Get("node_name")}
	jsonOK(w, analytics.GetSLO(r.Context(), h.DB, p, target, days))
}

// anomalies retourne les écarts détectés sur la fenêtre Prism (pic d'erreurs, IP dominante, pays, backends, bots).
func (h *PrismHandler) anomalies(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, analytics.DetectAnomalies(r.Context(), h.DB, prismParams(r)))
}

// deploys : changements de configuration de proxy sur la fenêtre Prism (annotations de courbe).
func (h *PrismHandler) deploys(w http.ResponseWriter, r *http.Request) {
	out, err := analytics.GetDeployMarkers(r.Context(), h.DB, prismParams(r))
	if err != nil {
		prismJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, out)
}

func prismJSONErr(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
}

// ── Bans analytics ───────────────────────────────────────────────────────────

func (h *PrismHandler) bansTimeline(w http.ResponseWriter, r *http.Request) {
	p := prismParams(r)
	bucket := r.URL.Query().Get("bucket")
	if bucket != "day" {
		bucket = "hour"
	}
	var groupFmt string
	if bucket == "day" {
		groupFmt = "%Y-%m-%d"
	} else {
		groupFmt = "%Y-%m-%dT%H:00:00Z"
	}
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT strftime(?, created_at) AS ts, COUNT(*) AS cnt
		FROM security_ban_history
		WHERE action = 'banned'
		  AND created_at >= ? AND created_at <= ?
		GROUP BY ts ORDER BY ts ASC`,
		groupFmt,
		p.From.UTC().Format("2006-01-02T15:04:05Z"),
		p.To.UTC().Format("2006-01-02T15:04:05Z"),
	)
	if err != nil {
		prismJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type pt struct {
		TS    string `json:"ts"`
		Count int    `json:"count"`
	}
	var out []pt
	for rows.Next() {
		var p pt
		if rows.Scan(&p.TS, &p.Count) == nil {
			out = append(out, p)
		}
	}
	if out == nil {
		out = []pt{}
	}
	jsonOK(w, out)
}

func (h *PrismHandler) bansBySource(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT source, COUNT(*) AS cnt
		FROM security_bans
		WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP
		GROUP BY source ORDER BY cnt DESC`)
	if err != nil {
		prismJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type row struct {
		Source string `json:"source"`
		Count  int    `json:"count"`
	}
	var out []row
	for rows.Next() {
		var rr row
		if rows.Scan(&rr.Source, &rr.Count) == nil {
			out = append(out, rr)
		}
	}
	if out == nil {
		out = []row{}
	}
	jsonOK(w, out)
}

func (h *PrismHandler) bansTopIPs(w http.ResponseWriter, r *http.Request) {
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 100 {
			limit = n
		}
	}
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT ip, COUNT(*) AS cnt, MAX(created_at) AS last_seen
		FROM security_ban_history
		WHERE action = 'banned'
		GROUP BY ip ORDER BY cnt DESC LIMIT ?`, limit)
	if err != nil {
		prismJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type row struct {
		IP       string `json:"ip"`
		Count    int    `json:"count"`
		LastSeen string `json:"last_seen"`
	}
	var out []row
	for rows.Next() {
		var rr row
		if rows.Scan(&rr.IP, &rr.Count, &rr.LastSeen) == nil {
			out = append(out, rr)
		}
	}
	if out == nil {
		out = []row{}
	}
	jsonOK(w, out)
}
