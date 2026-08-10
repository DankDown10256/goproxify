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
		"10.0.0.0/8", "172.16.0.0/12", "203.0.113.10/16",
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

// GetGeoBreakdown retourne la répartition du trafic par pays.
func GetGeoBreakdown(db *sql.DB, p Params) []GeoEntry {
	w, args := where(p)
	rows, err := db.Query(fmt.Sprintf(
		`SELECT COALESCE(g.country_code,'?') as cc,
		        COALESCE(g.country_name,'Unknown') as cn,
		        COUNT(*) as n
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
		_ = rows.Scan(&e.CountryCode, &e.CountryName, &e.Requests)
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
