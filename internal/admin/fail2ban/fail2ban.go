// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package fail2ban surveille les logs et bannit automatiquement les IPs abusives.
package fail2ban

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Config paramètre le moteur Fail2Ban.
type Config struct {
	Enabled           bool     `json:"enabled"`
	WindowSec         int      `json:"window_sec"`          // fenêtre glissante (défaut 300)
	MaxErrors         int      `json:"max_errors"`          // seuil déclenchant le ban (défaut 20)
	BanDurationSec    int      `json:"ban_duration_sec"`    // durée du ban en secondes (0 = permanent)
	TrustForwardedFor bool     `json:"trust_forwarded_for"` // utilise X-Forwarded-For
	Whitelist         []string `json:"whitelist"`           // IPs/CIDRs exemptées
}

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

	// OnBan est appelé après chaque nouveau ban (push Core / alertes).
	OnBan func(ip, reason string)
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
	err := e.db.QueryRow(`SELECT value FROM fail2ban_config WHERE key='config'`).Scan(&raw)
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
		`INSERT OR REPLACE INTO fail2ban_config (key, value) VALUES ('config', ?)`, string(b))
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

	window := cfg.WindowSec
	if window <= 0 {
		window = 300
	}
	maxErr := cfg.MaxErrors
	if maxErr <= 0 {
		maxErr = 20
	}
	banDur := cfg.BanDurationSec // 0 = ban permanent (expires_at NULL)

	// Seules les erreurs CLIENT (4xx hors 404) comptent — les 5xx (502, 503…)
	// sont des erreurs backend, pas de l'abus utilisateur.
	rows, err := e.db.Query(fmt.Sprintf(
		`SELECT ip, COUNT(*) as n FROM logs
		 WHERE ts > datetime('now','-%d seconds')
		   AND status >= 400 AND status < 500 AND status != 404
		   AND ip != '' AND component = 'core'
		 GROUP BY ip HAVING n >= %d`, window, maxErr))
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var ip string
		var count int
		if rows.Scan(&ip, &count) != nil {
			continue
		}
		// Nettoie le port éventuel
		rawIP := strings.Split(ip, ":")[0]
		if isPrivateIP(rawIP) || e.isWhitelisted(rawIP, cfg.Whitelist) {
			continue
		}
		// Vérifie si déjà banni
		var existing int
		e.db.QueryRow(
			`SELECT COUNT(*) FROM security_bans WHERE ip=? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`,
			rawIP).Scan(&existing) //nolint:errcheck
		if existing > 0 {
			continue
		}
		var expiresAt any
		if banDur > 0 {
			expiresAt = time.Now().Add(time.Duration(banDur) * time.Second).UTC().Format(time.RFC3339)
		}
		res, err := e.db.Exec(
			`INSERT OR IGNORE INTO security_bans (id, ip, domain, reason, source, expires_at) VALUES (?,?,?,?,?,?)`,
			uuid.New().String(), rawIP, "",
			fmt.Sprintf("Fail2Ban : %d erreurs en %ds", count, window),
			"native", expiresAt)
		if err == nil {
			if rows, _ := res.RowsAffected(); rows > 0 {
				reason := fmt.Sprintf("Fail2Ban : %d erreurs en %ds", count, window)
				e.log.Info("fail2ban: IP bannie automatiquement", "ip", rawIP, "errors", count)
				if e.OnBan != nil {
					e.OnBan(rawIP, reason)
				}
			}
		}
	}
}

func (e *Engine) isWhitelisted(ip string, whitelist []string) bool {
	parsed := net.ParseIP(ip)
	for _, entry := range whitelist {
		if entry == ip {
			return true
		}
		_, cidr, err := net.ParseCIDR(entry)
		if err == nil && cidr != nil && parsed != nil && cidr.Contains(parsed) {
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

func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true
	}
	for _, cidr := range append([]string{
		"10.0.0.0/8", "172.16.0.0/12", "203.0.113.10/16",
		"127.0.0.0/8", "::1/128", "fc00::/7",
	}, cloudflareRanges...) {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(parsed) {
			return true
		}
	}
	return false
}
