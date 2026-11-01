// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package fleet fait tourner les Seuils multi-passerelles : un moteur de l'Admin qui bannit une IP dont les erreurs client, comptées par chaque
// passerelle puis additionnées ici, dépassent un seuil. Une IP dont les erreurs se répartissent sur plusieurs passerelles ne dépasse le seuil d'aucune
// d'elles : seule l'Admin les voit toutes. Les Seuils d'Ephor font le même travail passerelle par passerelle.
package fleet

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/adminmetrics"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/engines"
)

// Config paramètre le moteur (voir engines.FleetConfig).
type Config = engines.FleetConfig

func DefaultConfig() Config {
	return Config{
		Enabled:        true,
		WindowSec:      300,
		MaxErrors:      50,
		BanDurationSec: 0, // permanent
	}
}

// Engine surveille la table logs et crée des bans automatiques.
type Engine struct {
	db  *sql.DB
	log *slog.Logger
	mu  sync.RWMutex
	cfg Config

	// OnBan est appelé après chaque nouveau ban (push passerelle / alertes).
	OnBan func(ip, reason string)

	lastActivity   time.Time
	lastActivityMu sync.RWMutex
}

// LastActivity retourne l'heure du dernier scan des Seuils multi-passerelles.
func (e *Engine) LastActivity() time.Time {
	e.lastActivityMu.RLock()
	defer e.lastActivityMu.RUnlock()
	return e.lastActivity
}

// New crée un Engine en chargeant la config depuis la DB.
func New(db *sql.DB, log *slog.Logger) *Engine {
	e := &Engine{db: db, log: log, cfg: DefaultConfig()}
	e.loadConfig()
	return e
}

// Start lance la boucle de surveillance en arrière-plan.
func (e *Engine) Start(ctx context.Context) {
	go func() {
		e.scan()
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				e.loadConfig()
				e.scan()
			}
		}
	}()
}

func (e *Engine) loadConfig() {
	var raw string
	err := e.db.QueryRow(`SELECT value FROM fleet_config WHERE key='config'`).Scan(&raw)
	if err != nil {
		return
	}
	var cfg Config
	if json.Unmarshal([]byte(raw), &cfg) == nil {
		e.mu.Lock()
		e.cfg = cfg
		e.mu.Unlock()
	}
}

// GetConfig retourne la config courante.
func (e *Engine) GetConfig() Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg
}

// SaveConfig persiste la config et recharge.
func (e *Engine) SaveConfig(cfg Config) error {
	b, _ := json.Marshal(cfg)
	_, err := e.db.Exec(
		`INSERT OR REPLACE INTO fleet_config (key, value) VALUES ('config', ?)`, string(b))
	if err == nil {
		e.mu.Lock()
		e.cfg = cfg
		e.mu.Unlock()
	}
	return err
}

func (e *Engine) scan() {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	if !cfg.Enabled {
		return
	}
	e.lastActivityMu.Lock()
	e.lastActivity = time.Now()
	e.lastActivityMu.Unlock()
	adminmetrics.Fleet.ScansTotal.Inc()
	if ipProtectionPushed(e.db) {
		return
	}

	window := cfg.WindowSec
	if window <= 0 {
		window = 300
	}
	maxErr := cfg.MaxErrors
	if maxErr <= 0 {
		maxErr = 20
	}
	banDur := cfg.BanDurationSec // 0 = ban permanent (expires_at NULL)

	// logs.ts est en RFC3339 : la borne doit l'être aussi (datetime('now') compare mal, 'T' > ' ').
	cutoff := time.Now().Add(-time.Duration(window) * time.Second).UTC()
	for key, count := range e.errorCounts(cutoff, maxErr, cfg.Whitelist) {
		if count < maxErr {
			continue
		}
		// Les 403 servis pendant un ban levé depuis (déban ou expiration) viennent du ban lui-même :
		// ils ne comptent pas, sinon l'IP est rebannie dès sa levée.
		if end := e.lastBanEnd(key); end.After(cutoff) {
			if count = e.errorCounts(end, maxErr, cfg.Whitelist)[key]; count < maxErr {
				continue
			}
		}
		// Vérifie si déjà banni
		var existing int
		e.db.QueryRow(
			`SELECT COUNT(*) FROM security_bans WHERE ip=? AND (expires_at IS NULL OR datetime(expires_at) > CURRENT_TIMESTAMP)`,
			key).Scan(&existing) //nolint:errcheck
		if existing > 0 {
			continue
		}
		var expiresAt any
		if banDur > 0 {
			expiresAt = time.Now().Add(time.Duration(banDur) * time.Second).UTC().Format(time.RFC3339)
		}
		banID := uuid.New().String()
		reason := fmt.Sprintf("Seuils multi-passerelles : %d erreurs en %ds", count, window)
		res, err := e.db.Exec(
			`INSERT OR IGNORE INTO security_bans (id, ip, domain, reason, source, expires_at) VALUES (?,?,?,?,?,?)`,
			banID, key, "", reason, "fleet", expiresAt)
		if err == nil {
			if rows, _ := res.RowsAffected(); rows > 0 {
				e.db.Exec( //nolint:errcheck
					`INSERT INTO security_ban_history (ip, domain, action, reason, source, ban_id) VALUES (?,?,'banned',?,?,?)`,
					key, "", reason, "fleet", banID)
				adminmetrics.Fleet.BansTotal.Inc()
				e.log.Info("fleet: IP bannie automatiquement", "ip", key, "errors", count)
				if e.OnBan != nil {
					e.OnBan(key, reason)
				}
			}
		}
	}
}

// ipProtectionPushed indique si l'Admin pousse l'anonymisation ou la pseudonymisation des IP : toutes
// les IP reçues sont alors tronquées ou « [pseudonymisé] ». Les passerelles antérieures à Edge 0.17.12
// n'envoient pas ip_truncated, leurs IP tronquées passeraient pour des IP réelles. Chaque passerelle
// bannit de toute façon sur l'IP réelle (ses Seuils d'Ephor la reçoivent avant troncature).
func ipProtectionPushed(db *sql.DB) bool {
	for _, key := range []string{"logs.ip_anonymize", "logs.ip_pseudonymize"} {
		if admindb.GetSetting(db, key, "false") == "true" {
			return true
		}
	}
	return false
}

// errorCounts compte, depuis since, les erreurs client par cible de ban (voir banKey). Seules les
// erreurs CLIENT (4xx hors 404) comptent — les 5xx (502, 503…) sont des erreurs backend, pas de
// l'abus utilisateur. En SQL, le seuil n'écarte que les IPv4 seules : les autres valeurs (IPv6,
// IP:port) sont regroupées ici et c'est le groupe qui doit l'atteindre. Les IP tronquées par la
// passerelle sont écartées : x.x.x.0 ne bannirait personne, un /48 tronqué bannirait son premier /64.
func (e *Engine) errorCounts(since time.Time, maxErr int, whitelist []string) map[string]int {
	counts := map[string]int{}
	add := func(ip string, n int) {
		// Écarte aussi ce qui n'est pas une IP (« [pseudonymisé] »).
		addr, ok := clientAddr(ip)
		if !ok || isPrivateIP(addr) || whitelisted(netip.PrefixFrom(addr, addr.BitLen()), whitelist) {
			return
		}
		counts[banKey(addr, whitelist)] += n
	}

	// Chaque passerelle compte elle-même les erreurs client de ses IP : un compteur par minute, donc on ne retient que les minutes entières
	// qui suivent le début de la fenêtre. La fenêtre effective perd jusqu'à une minute au début, et la minute
	// d'un déban n'est jamais comptée : du côté prudent, il y a moins de bans, jamais plus.
	if rows, err := e.db.Query(`SELECT ip, SUM(errors) FROM edge_ip_errors WHERE minute > ? GROUP BY ip`,
		since.UTC().Format("2006-01-02T15:04")); err == nil {
		for rows.Next() {
			var ip string
			var n int
			if rows.Scan(&ip, &n) == nil {
				add(ip, n)
			}
		}
		rows.Close()
	}
	return counts
}

// lastBanEnd retourne la fin du dernier ban levé de l'IP — déban manuel ou expiration — ou le zéro.
func (e *Engine) lastBanEnd(ip string) time.Time {
	var end time.Time
	var unbanned sql.NullString
	e.db.QueryRow( //nolint:errcheck
		`SELECT MAX(created_at) FROM security_ban_history WHERE ip=? AND action='unbanned'`, ip).Scan(&unbanned)
	if t := parseDBTime(unbanned.String); t.After(end) {
		end = t
	}
	rows, err := e.db.Query(
		`SELECT expires_at FROM security_bans WHERE ip=? AND expires_at IS NOT NULL AND expires_at != ''`, ip)
	if err != nil {
		return end
	}
	defer rows.Close()
	now := time.Now()
	for rows.Next() {
		var exp string
		if rows.Scan(&exp) != nil {
			continue
		}
		if t := parseDBTime(exp); t.Before(now) && t.After(end) {
			end = t
		}
	}
	return end
}

// parseDBTime lit une date SQLite : CURRENT_TIMESTAMP ou RFC3339 (dates venues des passerelles).
func parseDBTime(s string) time.Time {
	for _, layout := range []string{"2006-01-02 15:04:05", time.RFC3339Nano} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// clientAddr lit une IP seule, « IP:port » ou « [IPv6]:port ». Faux pour tout ce qui n'est pas une IP.
func clientAddr(s string) (netip.Addr, bool) {
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

// toPrefix lit une IP (préfixe /32 ou /128) ou un CIDR.
func toPrefix(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p, true
	}
	a, ok := clientAddr(s)
	return netip.PrefixFrom(a, a.BitLen()), ok
}

// banKey est la clé de comptage et la cible du ban : l'adresse pour une IPv4, son /64 pour une IPv6
// (même agrégation que les compteurs Ephor et que les Seuils d'Ephor). Un /64 revient en général
// à un seul abonné, qui y change d'adresse à volonté : compté adresse par adresse, il resterait
// toujours sous le seuil. Si la liste blanche recoupe le /64, on s'en tient à l'adresse pour ne pas
// bloquer l'IP exemptée.
func banKey(a netip.Addr, whitelist []string) string {
	if a.Is4() {
		return a.String()
	}
	p, _ := a.Prefix(64)
	if whitelisted(p, whitelist) {
		return a.String()
	}
	return p.String()
}

// whitelisted indique si p recoupe une entrée de la liste blanche (IP ou CIDR).
func whitelisted(p netip.Prefix, whitelist []string) bool {
	for _, entry := range whitelist {
		if w, ok := toPrefix(entry); ok && w.Overlaps(p) {
			return true
		}
	}
	return false
}

// cloudflareRanges contient les plages IP officielles de Cloudflare.
// Ces IPs ne doivent jamais être bannies car elles portent tout le trafic
// des utilisateurs finaux lorsque Cloudflare est en amont.
var cloudflareRanges = []string{
	"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"104.16.0.0/13", "104.24.0.0/14",
	"108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
	"162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20",
	"188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22",
	"198.41.128.0/17",
	// IPv6
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
	"2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

var exemptNets = func() []netip.Prefix {
	var out []netip.Prefix
	for _, cidr := range append([]string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "::1/128", "fc00::/7",
	}, cloudflareRanges...) {
		out = append(out, netip.MustParsePrefix(cidr))
	}
	return out
}()

func isPrivateIP(a netip.Addr) bool {
	for _, p := range exemptNets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
