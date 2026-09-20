// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

// GeoEntry répartition du trafic par pays.
type GeoEntry struct {
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	Requests    int64   `json:"requests"`
	Pct         float64 `json:"pct"`
	Errors      int64   `json:"errors"`
	ErrorRate   float64 `json:"error_rate"`
	BannedIPs   int64   `json:"banned_ips"`
}

// GeoResolver résout les IPs en pays via ip-api.com et met en cache dans SQLite.
type GeoResolver struct {
	DB  *sql.DB
	Log *slog.Logger
}

type ipAPIResult struct {
	Query       string `json:"query"`
	CountryCode string `json:"countryCode"`
	Country     string `json:"country"`
	Status      string `json:"status"`
}

var privateNets []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
		"::1/128", "fc00::/7", "fe80::/10",
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			privateNets = append(privateNets, network)
		}
	}
}

// Start lance la résolution en arrière-plan toutes les 60 secondes.
func (g *GeoResolver) Start(ctx context.Context) {
	go func() {
		g.resolve(ctx)
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				g.resolve(ctx)
			}
		}
	}()
}

// normalizeIP extrait l'adresse IP d'une valeur logs.ip (IPv4, IPv4:port, IPv6, [IPv6]:port).
func normalizeIP(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		return host
	}
	// IPv6 sans port (contient ':') ou IPv4 nue.
	if ip := net.ParseIP(raw); ip != nil {
		return ip.String()
	}
	// Fallback : strip host:port IPv4 naïf.
	if i := strings.LastIndex(raw, ":"); i > 0 && strings.Count(raw, ":") == 1 {
		if ip := net.ParseIP(raw[:i]); ip != nil {
			return ip.String()
		}
	}
	return ""
}

func isPrivate(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true
	}
	for _, network := range privateNets {
		if network.Contains(parsed) {
			return true
		}
	}
	return false
}

func (g *GeoResolver) log() *slog.Logger {
	if g.Log != nil {
		return g.Log
	}
	return slog.Default()
}

func (g *GeoResolver) cacheEntry(ip, cc, cn string) {
	_, _ = g.DB.Exec(
		`INSERT OR IGNORE INTO geoip_cache (ip, country_code, country_name) VALUES (?,?,?)`,
		ip, cc, cn)
}

func (g *GeoResolver) resolve(ctx context.Context) {
	rows, err := g.DB.QueryContext(ctx,
		`SELECT DISTINCT ip FROM logs
		 WHERE ip != '' AND status > 0
		   AND ip NOT IN (SELECT ip FROM geoip_cache)
		 LIMIT 100`)
	if err != nil {
		g.log().Warn("geoip: lecture IPs échouée", "err", err)
		return
	}

	// Clé cache = IP telle que stockée dans logs (pour JOIN exact).
	// queryIP = forme normalisée envoyée à l'API.
	type pending struct {
		logIP   string
		queryIP string
	}
	var toResolve []pending
	queryToLog := map[string][]string{} // queryIP → log IPs

	for rows.Next() {
		var raw string
		if rows.Scan(&raw) != nil || raw == "" {
			continue
		}
		queryIP := normalizeIP(raw)
		if queryIP == "" || isPrivate(queryIP) {
			// Ne pas re-tenter : privée, loopback, Docker, invalide.
			g.cacheEntry(raw, "LO", "Local / Private")
			continue
		}
		toResolve = append(toResolve, pending{logIP: raw, queryIP: queryIP})
		queryToLog[queryIP] = append(queryToLog[queryIP], raw)
	}
	rows.Close()

	if len(toResolve) == 0 {
		return
	}

	// Dédupliquer les query IP pour le batch API.
	seen := make(map[string]struct{}, len(queryToLog))
	payload := make([]map[string]string, 0, len(queryToLog))
	for _, p := range toResolve {
		if _, ok := seen[p.queryIP]; ok {
			continue
		}
		seen[p.queryIP] = struct{}{}
		payload = append(payload, map[string]string{"query": p.queryIP})
	}
	body, err := json.Marshal(payload)
	if err != nil {
		g.log().Warn("geoip: marshal batch échoué", "err", err)
		return
	}

	// ip-api.com batch (HTTP free, ≤100 IPs, 45 req/min). Ne pas cacher
	// en cas d'échec réseau : on réessaiera au prochain tick.
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"http://ip-api.com/batch?fields=query,countryCode,country,status", bytes.NewReader(body))
	if err != nil {
		g.log().Warn("geoip: requête batch impossible", "err", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		g.log().Warn("geoip: appel ip-api.com échoué (réessai au prochain cycle)", "err", err, "n", len(payload))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		g.log().Warn("geoip: ip-api.com status non-OK", "status", resp.StatusCode)
		return
	}

	var results []ipAPIResult
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		g.log().Warn("geoip: décodage réponse échoué", "err", err)
		return
	}

	cached := 0
	for _, r := range results {
		cc, cn := r.CountryCode, r.Country
		if r.Status != "success" || cc == "" {
			cc, cn = "XX", "Unknown"
		}
		logIPs := queryToLog[r.Query]
		if len(logIPs) == 0 {
			// API peut renvoyer une forme canonique différente.
			logIPs = queryToLog[normalizeIP(r.Query)]
		}
		if len(logIPs) == 0 {
			g.cacheEntry(r.Query, cc, cn)
			cached++
			continue
		}
		for _, logIP := range logIPs {
			g.cacheEntry(logIP, cc, cn)
			cached++
		}
	}
	g.log().Debug("geoip: cache mis à jour", "resolved", cached, "queried", len(payload))
}

// GetGeoBreakdown retourne la répartition du trafic par pays,
// incluant le taux d'erreurs et le nombre d'IPs bannies actives.
func GetGeoBreakdown(db *sql.DB, p Params) []GeoEntry {
	w, args := where(p)
	rows, err := db.Query(fmt.Sprintf(
		`SELECT COALESCE(g.country_code,'?') as cc,
		        COALESCE(g.country_name,'Unknown') as cn,
		        COUNT(*) as n,
		        SUM(CASE WHEN l.status >= 400 THEN 1 ELSE 0 END) as errors
		 FROM logs l
		 LEFT JOIN geoip_cache g ON g.ip = l.ip
		 %s GROUP BY cc, cn ORDER BY n DESC LIMIT 50`, w), args...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []GeoEntry
	var total int64
	for rows.Next() {
		var e GeoEntry
		_ = rows.Scan(&e.CountryCode, &e.CountryName, &e.Requests, &e.Errors)
		if e.Requests > 0 {
			e.ErrorRate = float64(e.Errors) / float64(e.Requests) * 100
		}
		total += e.Requests
		out = append(out, e)
	}
	for i := range out {
		if total > 0 {
			out[i].Pct = float64(out[i].Requests) / float64(total) * 100
		}
	}

	// Bans actifs par pays (query séparée, sans filtre temporel)
	bansPerCC := geoBannedIPs(db)
	for i := range out {
		out[i].BannedIPs = bansPerCC[out[i].CountryCode]
	}
	return out
}

// LiveIPEvent représente un événement IP récent pour la vue live de la carte.
type LiveIPEvent struct {
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	Kind        string `json:"kind"` // "visit" | "error" | "banned"
	Status      int    `json:"status"`
	Domain      string `json:"domain"`
	Ts          string `json:"ts"`
}

// GetLiveIPs retourne les événements IP récents pour la vue live de la carte.
// since : timestamp ISO8601 depuis lequel récupérer ; limit : max 200.
func GetLiveIPs(db *sql.DB, since time.Time, proxy, nodeName string, limit int) []LiveIPEvent {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	sinceStr := since.UTC().Format(time.RFC3339)

	var conds []string
	var args []any
	conds = append(conds, "l.ts >= ?")
	args = append(args, sinceStr)
	conds = append(conds, "l.status > 0")
	if proxy != "" {
		conds = append(conds, "l.domain = ?")
		args = append(args, proxy)
	}
	if nodeName != "" {
		conds = append(conds, "l.node_name = ?")
		args = append(args, nodeName)
	}

	w := "WHERE " + strings.Join(conds, " AND ")

	// Charge les IPs bannies actives pour annoter kind=banned
	bannedIPs := activeBannedIPSet(db)

	rows, err := db.Query(fmt.Sprintf(
		`SELECT l.ip,
		        COALESCE(g.country_code,'?') AS cc,
		        COALESCE(g.country_name,'Unknown') AS cn,
		        l.status,
		        l.domain,
		        l.ts
		 FROM logs l
		 LEFT JOIN geoip_cache g ON g.ip = l.ip
		 %s
		 ORDER BY l.ts DESC
		 LIMIT ?`, w), append(args, limit)...)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var out []LiveIPEvent
	for rows.Next() {
		var ev LiveIPEvent
		_ = rows.Scan(&ev.IP, &ev.CountryCode, &ev.CountryName, &ev.Status, &ev.Domain, &ev.Ts)
		switch {
		case bannedIPs[ev.IP]:
			ev.Kind = "banned"
		case ev.Status >= 400:
			ev.Kind = "error"
		default:
			ev.Kind = "visit"
		}
		out = append(out, ev)
	}
	return out
}

// activeBannedIPSet retourne l'ensemble des IPs actives dans security_bans.
func activeBannedIPSet(db *sql.DB) map[string]bool {
	rows, err := db.Query(
		`SELECT ip FROM security_bans
		 WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	m := map[string]bool{}
	for rows.Next() {
		var ip string
		_ = rows.Scan(&ip)
		m[ip] = true
	}
	return m
}

// geoBannedIPs retourne le nombre d'IPs bannies actives par country_code.
func geoBannedIPs(db *sql.DB) map[string]int64 {
	rows, err := db.Query(
		`SELECT COALESCE(g.country_code,'?') as cc, COUNT(DISTINCT sb.ip)
		 FROM security_bans sb
		 LEFT JOIN geoip_cache g ON g.ip = sb.ip
		 WHERE (sb.expires_at IS NULL OR sb.expires_at > CURRENT_TIMESTAMP)
		 GROUP BY cc`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	m := map[string]int64{}
	for rows.Next() {
		var cc string
		var n int64
		_ = rows.Scan(&cc, &n)
		m[cc] = n
	}
	return m
}
