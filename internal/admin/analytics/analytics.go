// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package analytics agrège les données de la table logs pour Prism.
package analytics

import (
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Params filtre commun à toutes les requêtes.
type Params struct {
	Proxy    string // domaine ou "" pour tous
	NodeName string // nœud Core ou "" pour tous
	IP       string // IP client ou "" pour tous
	Path     string // préfixe/égalité chemin ou "" pour tous
	From     time.Time
	To       time.Time
}

// KPIs métriques globales pour la période.
type KPIs struct {
	Requests       int64   `json:"requests"`
	RequestsDelta  float64 `json:"requests_delta"`  // % vs période précédente
	Bandwidth      int64   `json:"bandwidth"`        // bytes
	BandwidthDelta float64 `json:"bandwidth_delta"`
	ErrorRate      float64 `json:"error_rate"` // % 4xx+5xx
	ErrorRateDelta float64 `json:"error_rate_delta"`
	UniqueIPs      int64   `json:"unique_ips"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
	BotShare       float64 `json:"bot_share"` // % requests from known bots
}

// TimePoint point de la courbe temporelle.
type TimePoint struct {
	Bucket   string `json:"bucket"`
	Requests int64  `json:"requests"`
	Errors   int64  `json:"errors"`
	Bytes    int64  `json:"bytes"`
}

// StatusGroup répartition par famille de codes HTTP.
type StatusGroup struct {
	Group    string         `json:"group"`    // "2xx" / "3xx" / "4xx" / "5xx"
	Count    int64          `json:"count"`
	Pct      float64        `json:"pct"`
	Breakdown []StatusEntry `json:"breakdown"`
}

// StatusEntry détail d'un code HTTP précis.
type StatusEntry struct {
	Code  int     `json:"code"`
	Count int64   `json:"count"`
	Pct   float64 `json:"pct"`
}

// PathEntry top chemin.
type PathEntry struct {
	Path      string  `json:"path"`
	Requests  int64   `json:"requests"`
	Errors    int64   `json:"errors"`
	AvgLatMs  float64 `json:"avg_lat_ms"`
	Bytes     int64   `json:"bytes"`
}

// IPEntry top IP.
type IPEntry struct {
	IP       string `json:"ip"`
	Requests int64  `json:"requests"`
	Errors   int64  `json:"errors"`
	Bytes    int64  `json:"bytes"`
}

// AgentEntry navigateur ou bot.
type AgentEntry struct {
	Name     string  `json:"name"`
	Requests int64   `json:"requests"`
	Pct      float64 `json:"pct"`
	IsBot    bool    `json:"is_bot"`
}

// ProxyOption proxy disponible pour le filtre.
type ProxyOption struct {
	Domain string `json:"domain"`
	Name   string `json:"name"`
}

func where(p Params) (string, []any) {
	var conds []string
	var args []any
	if !p.From.IsZero() {
		conds = append(conds, "ts >= ?")
		args = append(args, p.From.UTC().Format(time.RFC3339))
	}
	if !p.To.IsZero() {
		conds = append(conds, "ts <= ?")
		args = append(args, p.To.UTC().Format(time.RFC3339))
	}
	if p.Proxy != "" {
		conds = append(conds, "domain = ?")
		args = append(args, p.Proxy)
	}
	if p.NodeName != "" {
		conds = append(conds, "node_name = ?")
		args = append(args, p.NodeName)
	}
	if p.IP != "" {
		conds = append(conds, "ip = ?")
		args = append(args, p.IP)
	}
	if p.Path != "" {
		conds = append(conds, "path LIKE ?")
		args = append(args, p.Path+"%")
	}
	// Filtre uniquement les logs d'accès HTTP (status > 0)
	conds = append(conds, "status > 0")
	if len(conds) == 0 {
		return "", args
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// rawKPIs fait un seul scan pour extraire les métriques agrégées de la période.
// Pas de COUNT(DISTINCT ip) ici — trop coûteux ; voir GetUniqueIPs.
func rawKPIs(db *sql.DB, p Params) (reqs, bw, errs, bots int64, avgLat float64) {
	w, args := where(p)
	db.QueryRow( //nolint:errcheck
		`SELECT
		   COUNT(*),
		   COALESCE(SUM(bytes), 0),
		   COALESCE(AVG(latency_ms), 0),
		   SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END),
		   SUM(CASE WHEN lower(component) LIKE '%bot%' OR lower(message) LIKE '%bot%' THEN 1 ELSE 0 END)
		 FROM logs `+w, args...,
	).Scan(&reqs, &bw, &avgLat, &errs, &bots)
	return
}

// GetUniqueIPs compte les IPs distinctes (requête séparée, chargée en différé côté UI).
func GetUniqueIPs(db *sql.DB, p Params) int64 {
	w, args := where(p)
	var n int64
	db.QueryRow(`SELECT COUNT(DISTINCT ip) FROM logs `+w, args...).Scan(&n) //nolint:errcheck
	return n
}

// GetKPIs retourne les KPIs pour la période + delta vs période précédente.
// 2 scans au total (période courante + précédente). UniqueIPs reste à 0
// sauf si includeUnique est true (évite de bloquer le above-the-fold).
func GetKPIs(db *sql.DB, p Params, includeUnique bool) KPIs {
	reqs, bw, errs, bots, avgLat := rawKPIs(db, p)

	dur := p.To.Sub(p.From)
	prev := Params{Proxy: p.Proxy, NodeName: p.NodeName, From: p.From.Add(-dur), To: p.From}
	preReqs, preBW, preErrs, _, _ := rawKPIs(db, prev)

	errRate, preErrRate := 0.0, 0.0
	if reqs > 0 {
		errRate = float64(errs) / float64(reqs) * 100
	}
	if preReqs > 0 {
		preErrRate = float64(preErrs) / float64(preReqs) * 100
	}

	pct := func(cur, pre int64) float64 {
		if pre == 0 {
			return 0
		}
		return float64(cur-pre) / float64(pre) * 100
	}
	pctF := func(cur, pre float64) float64 {
		if pre == 0 {
			return 0
		}
		return (cur - pre) / pre * 100
	}

	botShare := 0.0
	if reqs > 0 {
		botShare = float64(bots) / float64(reqs) * 100
	}

	var uIPs int64
	if includeUnique {
		uIPs = GetUniqueIPs(db, p)
	}

	return KPIs{
		Requests:       reqs,
		RequestsDelta:  pct(reqs, preReqs),
		Bandwidth:      bw,
		BandwidthDelta: pct(bw, preBW),
		ErrorRate:      errRate,
		ErrorRateDelta: pctF(errRate, preErrRate),
		UniqueIPs:      uIPs,
		AvgLatencyMs:   avgLat,
		BotShare:       botShare,
	}
}

// GetTimeline retourne les requêtes agrégées par bucket temporel.
func GetTimeline(db *sql.DB, p Params, bucket string) []TimePoint {
	// bucket: "hour" | "day" | "minute"
	var tfmt string
	switch bucket {
	case "minute":
		tfmt = "%Y-%m-%dT%H:%M"
	case "day":
		tfmt = "%Y-%m-%d"
	default:
		tfmt = "%Y-%m-%dT%H:00"
	}
	w, args := where(p)
	rows, err := db.Query(
		`SELECT strftime('`+tfmt+`', ts, 'localtime') as b, COUNT(*), SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END), COALESCE(SUM(bytes),0)
		 FROM logs `+w+` GROUP BY b ORDER BY b`, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []TimePoint
	for rows.Next() {
		var tp TimePoint
		rows.Scan(&tp.Bucket, &tp.Requests, &tp.Errors, &tp.Bytes) //nolint:errcheck
		out = append(out, tp)
	}
	return out
}

// GetStatusGroups retourne la répartition par famille de codes HTTP.
func GetStatusGroups(db *sql.DB, p Params) []StatusGroup {
	w, args := where(p)
	rows, err := db.Query(
		`SELECT status, COUNT(*) FROM logs `+w+` GROUP BY status ORDER BY status`, args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	type codeCnt struct{ code int; count int64 }
	groups := map[string][]codeCnt{
		"2xx": {}, "3xx": {}, "4xx": {}, "5xx": {},
	}
	var total int64
	for rows.Next() {
		var code int
		var cnt int64
		rows.Scan(&code, &cnt) //nolint:errcheck
		total += cnt
		switch {
		case code >= 200 && code < 300:
			groups["2xx"] = append(groups["2xx"], codeCnt{code, cnt})
		case code >= 300 && code < 400:
			groups["3xx"] = append(groups["3xx"], codeCnt{code, cnt})
		case code >= 400 && code < 500:
			groups["4xx"] = append(groups["4xx"], codeCnt{code, cnt})
		case code >= 500:
			groups["5xx"] = append(groups["5xx"], codeCnt{code, cnt})
		}
	}

	order := []string{"2xx", "3xx", "4xx", "5xx"}
	var out []StatusGroup
	for _, g := range order {
		codes := groups[g]
		var gTotal int64
		for _, c := range codes {
			gTotal += c.count
		}
		sg := StatusGroup{
			Group: g,
			Count: gTotal,
		}
		if total > 0 {
			sg.Pct = float64(gTotal) / float64(total) * 100
		}
		for _, c := range codes {
			pct := 0.0
			if gTotal > 0 {
				pct = float64(c.count) / float64(gTotal) * 100
			}
			sg.Breakdown = append(sg.Breakdown, StatusEntry{Code: c.code, Count: c.count, Pct: pct})
		}
		out = append(out, sg)
	}
	return out
}

// GetTopPaths retourne les chemins les plus fréquents.
// Pas de COUNT(DISTINCT path) : on lit limit+1 pour savoir s'il y a une page suivante.
func GetTopPaths(db *sql.DB, p Params, search string, limit, offset int) (paths []PathEntry, hasMore bool) {
	if limit <= 0 {
		limit = 20
	}
	w, args := where(p)
	if search != "" {
		if w == "" {
			w = "WHERE status > 0 AND path LIKE ?"
		} else {
			w += " AND path LIKE ?"
		}
		args = append(args, "%"+search+"%")
	}

	rows, err := db.Query(
		`SELECT path, COUNT(*) as n,
		        SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END),
		        COALESCE(AVG(latency_ms),0),
		        COALESCE(SUM(bytes),0)
		 FROM logs `+w+` GROUP BY path ORDER BY n DESC LIMIT ? OFFSET ?`,
		append(args, limit+1, offset)...)
	if err != nil {
		return nil, false
	}
	defer rows.Close()
	var out []PathEntry
	for rows.Next() {
		var e PathEntry
		rows.Scan(&e.Path, &e.Requests, &e.Errors, &e.AvgLatMs, &e.Bytes) //nolint:errcheck
		out = append(out, e)
	}
	if len(out) > limit {
		return out[:limit], true
	}
	return out, false
}

// GetTopIPs retourne les IPs les plus actives.
func GetTopIPs(db *sql.DB, p Params, limit int) []IPEntry {
	if limit <= 0 {
		limit = 50
	}
	w, args := where(p)
	rows, err := db.Query(
		`SELECT ip, COUNT(*) as n,
		        SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END),
		        COALESCE(SUM(bytes),0)
		 FROM logs `+w+` GROUP BY ip ORDER BY n DESC LIMIT ?`,
		append(args, limit)...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []IPEntry
	for rows.Next() {
		var e IPEntry
		rows.Scan(&e.IP, &e.Requests, &e.Errors, &e.Bytes) //nolint:errcheck
		out = append(out, e)
	}
	return out
}

var botKeywords = []string{
	"bot", "crawler", "spider", "scraper", "wget", "curl", "python-requests",
	"go-http-client", "libwww", "httpclient", "nmap", "masscan", "zgrab",
	"nikto", "nuclei", "sqlmap", "dirbuster", "gobuster", "ffuf",
}

func isBot(agent string) bool {
	low := strings.ToLower(agent)
	for _, kw := range botKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

// GetTopAgents retourne les user-agents les plus fréquents (déduit du composant ou du message).
// En l'absence de colonne user_agent, on parse le champ message si format "METHOD PATH agent=…"
// sinon on utilise component comme proxy.
func GetTopAgents(db *sql.DB, p Params, limit int) []AgentEntry {
	if limit <= 0 {
		limit = 30
	}
	w, args := where(p)
	rows, err := db.Query(
		`SELECT component, COUNT(*) as n FROM logs `+w+` GROUP BY component ORDER BY n DESC LIMIT ?`,
		append(args, limit)...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var total int64
	var entries []struct {
		name  string
		count int64
	}
	for rows.Next() {
		var name string
		var cnt int64
		rows.Scan(&name, &cnt) //nolint:errcheck
		if name == "" {
			name = "unknown"
		}
		entries = append(entries, struct {
			name  string
			count int64
		}{name, cnt})
		total += cnt
	}
	var out []AgentEntry
	for _, e := range entries {
		pct := 0.0
		if total > 0 {
			pct = float64(e.count) / float64(total) * 100
		}
		out = append(out, AgentEntry{
			Name:     e.name,
			Requests: e.count,
			Pct:      pct,
			IsBot:    isBot(e.name),
		})
	}
	return out
}

// GetProxies retourne les domaines configurés (table proxies), sans scanner logs.
// Si nodeName est non vide, ne retourne que les domaines vus dans les logs d'accès de ce Core.
func GetProxies(db *sql.DB, nodeName string) []ProxyOption {
	var (
		rows *sql.Rows
		err  error
	)
	if nodeName != "" {
		rows, err = db.Query(
			`SELECT DISTINCT domain, domain
			 FROM logs
			 WHERE status > 0
			   AND node_name = ?
			   AND domain IS NOT NULL AND domain != ''
			 ORDER BY domain`, nodeName)
	} else {
		rows, err = db.Query(
			`SELECT json_extract(config,'$.host') AS domain, name
			 FROM proxies
			 WHERE enabled = 1
			   AND json_extract(config,'$.host') IS NOT NULL
			   AND json_extract(config,'$.host') != ''
			 ORDER BY name`)
	}
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []ProxyOption
	seen := map[string]bool{}
	for rows.Next() {
		var opt ProxyOption
		rows.Scan(&opt.Domain, &opt.Name) //nolint:errcheck
		if opt.Domain == "" || seen[opt.Domain] {
			continue
		}
		seen[opt.Domain] = true
		out = append(out, opt)
	}
	return out
}

// ReferrerEntry top référent.
type ReferrerEntry struct {
	Referrer string  `json:"referrer"`
	Requests int64   `json:"requests"`
	Pct      float64 `json:"pct"`
}

// GetTopReferrers retourne les référents les plus fréquents.
func GetTopReferrers(db *sql.DB, p Params, limit int) []ReferrerEntry {
	if limit <= 0 {
		limit = 30
	}
	w, args := where(p)
	// Remplace "WHERE status > 0" par condition sur referrer non vide
	w2 := strings.Replace(w, "status > 0", "status > 0 AND referrer != ''", 1)
	rows, err := db.Query(
		`SELECT referrer, COUNT(*) as n FROM logs `+w2+` GROUP BY referrer ORDER BY n DESC LIMIT ?`,
		append(args, limit)...)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []ReferrerEntry
	var total int64
	for rows.Next() {
		var e ReferrerEntry
		rows.Scan(&e.Referrer, &e.Requests) //nolint:errcheck
		total += e.Requests
		out = append(out, e)
	}
	for i := range out {
		if total > 0 {
			out[i].Pct = float64(out[i].Requests) / float64(total) * 100
		}
	}
	return out
}

// ExportCSV exporte les données brutes filtrées en CSV.
func ExportCSV(db *sql.DB, p Params) ([]byte, error) {
	w, args := where(p)
	rows, err := db.Query(
		`SELECT ts, domain, method, path, status, ip, latency_ms, bytes, message
		 FROM logs `+w+` ORDER BY ts DESC LIMIT 50000`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sb strings.Builder
	cw := csv.NewWriter(&sb)
	cw.Write([]string{"ts", "domain", "method", "path", "status", "ip", "latency_ms", "bytes", "message"}) //nolint:errcheck
	for rows.Next() {
		var ts, domain, method, path, ip, msg string
		var status int
		var lat, byt int64
		rows.Scan(&ts, &domain, &method, &path, &status, &ip, &lat, &byt, &msg) //nolint:errcheck
		cw.Write([]string{ts, domain, method, path, fmt.Sprintf("%d", status), ip, fmt.Sprintf("%d", lat), fmt.Sprintf("%d", byt), msg}) //nolint:errcheck
	}
	cw.Flush()
	return []byte(sb.String()), nil
}

// ExportJSON exporte les données brutes filtrées en JSON.
func ExportJSON(db *sql.DB, p Params) ([]byte, error) {
	w, args := where(p)
	rows, err := db.Query(
		`SELECT ts, domain, method, path, status, ip, latency_ms, bytes, message
		 FROM logs `+w+` ORDER BY ts DESC LIMIT 50000`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type Row struct {
		Ts       string `json:"ts"`
		Domain   string `json:"domain"`
		Method   string `json:"method"`
		Path     string `json:"path"`
		Status   int    `json:"status"`
		IP       string `json:"ip"`
		LatencyMs int64 `json:"latency_ms"`
		Bytes    int64  `json:"bytes"`
		Message  string `json:"message,omitempty"`
	}
	var out []Row
	for rows.Next() {
		var r Row
		rows.Scan(&r.Ts, &r.Domain, &r.Method, &r.Path, &r.Status, &r.IP, &r.LatencyMs, &r.Bytes, &r.Message) //nolint:errcheck
		out = append(out, r)
	}
	return json.MarshalIndent(out, "", "  ")
}

// ExportHTML génère un rapport HTML statique autonome.
func ExportHTML(db *sql.DB, p Params) ([]byte, error) {
	kpis := GetKPIs(db, p, true)
	timeline := GetTimeline(db, p, "hour")
	statusGroups := GetStatusGroups(db, p)
	paths, _ := GetTopPaths(db, p, "", 20, 0)
	ips := GetTopIPs(db, p, 20)

	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Prism Report — Goproxify</title>
<style>body{font-family:system-ui,sans-serif;background:#0f1117;color:#e2e8f0;margin:0;padding:24px}
h1{font-size:22px;margin-bottom:4px}.sub{color:#64748b;font-size:13px;margin-bottom:24px}
.kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;margin-bottom:24px}
.kpi{background:#1e2433;border:1px solid #2d3748;border-radius:8px;padding:14px}
.kpi-val{font-size:22px;font-weight:700;margin-bottom:2px}.kpi-lbl{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px}
table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:24px}
th{color:#64748b;font-weight:500;text-align:left;padding:6px 10px;border-bottom:1px solid #2d3748}
td{padding:5px 10px;border-bottom:1px solid #1e2433}
h2{font-size:15px;margin:24px 0 10px;color:#94a3b8}
.bb{display:inline-block;width:80px;height:6px;background:#2d3748;border-radius:3px;vertical-align:middle}
.bf{display:inline-block;height:100%;border-radius:3px;background:#6366f1;vertical-align:top}
.bfe{background:#ef4444}</style></head><body>`)

	proxy := p.Proxy
	if proxy == "" {
		proxy = "tous les proxies"
	}
	fmt.Fprintf(&sb, `<h1>Rapport Prism — Goproxify</h1><div class="sub">%s → %s &nbsp;|&nbsp; %s &nbsp;|&nbsp; Généré le %s</div>`,
		htmlEsc(p.From.Format("2006-01-02 15:04")), htmlEsc(p.To.Format("2006-01-02 15:04")),
		htmlEsc(proxy), time.Now().Format("2006-01-02 15:04:05"))

	// KPIs
	sb.WriteString(`<div class="kpis">`)
	fmt.Fprintf(&sb, `<div class="kpi"><div class="kpi-lbl">Requêtes</div><div class="kpi-val">%d</div></div>`, kpis.Requests)
	fmt.Fprintf(&sb, `<div class="kpi"><div class="kpi-lbl">Bande passante</div><div class="kpi-val">%s</div></div>`, htmlFmtBytes(kpis.Bandwidth))
	fmt.Fprintf(&sb, `<div class="kpi"><div class="kpi-lbl">Taux erreur</div><div class="kpi-val">%.1f%%</div></div>`, kpis.ErrorRate)
	fmt.Fprintf(&sb, `<div class="kpi"><div class="kpi-lbl">IPs uniques</div><div class="kpi-val">%d</div></div>`, kpis.UniqueIPs)
	fmt.Fprintf(&sb, `<div class="kpi"><div class="kpi-lbl">Latence moy.</div><div class="kpi-val">%.0f ms</div></div>`, kpis.AvgLatencyMs)
	sb.WriteString(`</div>`)

	// Timeline SVG
	if len(timeline) > 0 {
		maxR := int64(1)
		for _, pt := range timeline {
			if pt.Requests > maxR {
				maxR = pt.Requests
			}
		}
		W, H := 600.0, 80.0
		n := len(timeline)
		xStep := W / float64(n-1+1)
		if n > 1 { xStep = W / float64(n-1) }
		toY := func(v int64) float64 { return H - (float64(v)/float64(maxR))*(H-4) }
		var pathStr strings.Builder
		for i, pt := range timeline {
			if i == 0 {
				fmt.Fprintf(&pathStr, "M%.1f,%.1f", float64(i)*xStep, toY(pt.Requests))
			} else {
				fmt.Fprintf(&pathStr, " L%.1f,%.1f", float64(i)*xStep, toY(pt.Requests))
			}
		}
		fmt.Fprintf(&sb, `<h2>Requêtes / heure</h2><svg viewBox="0 0 %.0f %.0f" style="width:100%%;max-width:700px;height:%.0fpx;background:#1e2433;border-radius:8px;display:block;margin-bottom:16px"><path d="%s" fill="none" stroke="#6366f1" stroke-width="2"/></svg>`,
			W, H, H, pathStr.String())
	}

	// Status groups
	sb.WriteString(`<h2>Codes HTTP</h2><table><thead><tr><th>Famille</th><th>Requêtes</th><th>%</th></tr></thead><tbody>`)
	for _, g := range statusGroups {
		fmt.Fprintf(&sb, `<tr><td>%s</td><td>%d</td><td>%.1f%%</td></tr>`, g.Group, g.Count, g.Pct)
	}
	sb.WriteString(`</tbody></table>`)

	// Top paths
	maxP := int64(1)
	for _, p2 := range paths {
		if p2.Requests > maxP { maxP = p2.Requests }
	}
	sb.WriteString(`<h2>Top chemins</h2><table><thead><tr><th>Chemin</th><th>Req.</th><th>Err.</th><th>Lat.</th></tr></thead><tbody>`)
	for _, p2 := range paths {
		fmt.Fprintf(&sb, `<tr><td style="font-family:monospace;font-size:11px">%s</td><td>%d</td><td>%d</td><td>%.0f ms</td></tr>`,
			htmlEsc(p2.Path), p2.Requests, p2.Errors, p2.AvgLatMs)
	}
	sb.WriteString(`</tbody></table>`)

	// Top IPs
	sb.WriteString(`<h2>Top IPs</h2><table><thead><tr><th>IP</th><th>Req.</th><th>Err.</th></tr></thead><tbody>`)
	for _, i2 := range ips {
		fmt.Fprintf(&sb, `<tr><td style="font-family:monospace">%s</td><td>%d</td><td>%d</td></tr>`,
			htmlEsc(i2.IP), i2.Requests, i2.Errors)
	}
	sb.WriteString(`</tbody></table></body></html>`)
	return []byte(sb.String()), nil
}

func htmlEsc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func htmlFmtBytes(b int64) string {
	switch {
	case b >= 1e9: return fmt.Sprintf("%.1f GB", float64(b)/1e9)
	case b >= 1e6: return fmt.Sprintf("%.1f MB", float64(b)/1e6)
	case b >= 1e3: return fmt.Sprintf("%.1f KB", float64(b)/1e3)
	default:       return fmt.Sprintf("%d B", b)
	}
}
