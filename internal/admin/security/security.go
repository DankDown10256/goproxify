// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package security fournit les types et la logique du Dashboard Sécurité.
package security

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
)

// Ban représente un bannissement IP (Fail2Ban, CrowdSec ou natif).
type Ban struct {
	ID        string    `json:"id"`
	IP        string    `json:"ip"`
	Domain    string    `json:"domain"`
	Reason    string    `json:"reason"`
	Source    string    `json:"source"` // fail2ban | crowdsec | native
	ExpiresAt *string   `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// Threat représente une décision CrowdSec.
type Threat struct {
	ID        int64     `json:"id"`
	IP        string    `json:"ip"`
	Scenario  string    `json:"scenario"`
	Origin    string    `json:"origin"`
	Type      string    `json:"type"`
	Duration  string    `json:"duration"`
	CreatedAt time.Time `json:"created_at"`
}

// CVE représente une vulnérabilité détectée sur un backend.
type CVE struct {
	ID          int64     `json:"id"`
	BackendURL  string    `json:"backend_url"`
	CVEID       string    `json:"cve_id"`
	CVSSScore   float64   `json:"cvss_score"`
	Description string    `json:"description"`
	Status      string    `json:"status"` // open | ignored | fixed
	DetectedAt  time.Time `json:"detected_at"`
}

// HeaderCheck est le résultat de l'analyse des en-têtes de sécurité d'un proxy.
type HeaderCheck struct {
	ProxyID   string  `json:"proxy_id"`
	ProxyName string  `json:"proxy_name"`
	Domain    string  `json:"domain"`
	Score     int     `json:"score"` // 0-100
	Grade     string  `json:"grade"` // A+ | A | B | C | D | E | F
	Checks    []Check `json:"checks"`
}

// Check décrit un contrôle individuel.
type Check struct {
	Name    string `json:"name"`
	Present bool   `json:"present"`
	Points  int    `json:"points"`
}

// Overview est le résumé du dashboard sécurité.
type Overview struct {
	ActiveBans    int           `json:"active_bans"`
	ActiveThreats int           `json:"active_threats"`
	OpenCVEs      int           `json:"open_cves"`
	CriticalCVEs  int           `json:"critical_cves"`
	CertsExpiring int           `json:"certs_expiring"`    // expirant dans 30 jours
	CertsExpired  int           `json:"certs_expired"`
	AvgHeaderScore float64      `json:"avg_header_score"`
	Headers       []HeaderCheck `json:"headers"`
}

// Store centralise les requêtes de sécurité.
type Store struct {
	db *sql.DB
}

func New(db *sql.DB) *Store { return &Store{db: db} }

// GetOverview calcule le résumé complet.
func (s *Store) GetOverview(proxies []proxyRow) Overview {
	var ov Overview
	s.db.QueryRow(`SELECT COUNT(*) FROM security_bans WHERE (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`).Scan(&ov.ActiveBans)                   //nolint:errcheck
	s.db.QueryRow(`SELECT COUNT(*) FROM security_threats`).Scan(&ov.ActiveThreats)                                                                          //nolint:errcheck
	s.db.QueryRow(`SELECT COUNT(*) FROM security_cves WHERE status='open'`).Scan(&ov.OpenCVEs)                                                              //nolint:errcheck
	s.db.QueryRow(`SELECT COUNT(*) FROM security_cves WHERE status='open' AND cvss_score>=7`).Scan(&ov.CriticalCVEs)                                        //nolint:errcheck
	s.db.QueryRow(`SELECT COUNT(*) FROM certs WHERE expires_at > CURRENT_TIMESTAMP AND expires_at <= datetime('now','+30 days')`).Scan(&ov.CertsExpiring)   //nolint:errcheck
	s.db.QueryRow(`SELECT COUNT(*) FROM certs WHERE expires_at <= CURRENT_TIMESTAMP`).Scan(&ov.CertsExpired)                                                //nolint:errcheck

	scores := make([]HeaderCheck, 0, len(proxies))
	var total float64
	for _, p := range proxies {
		hc := ComputeHeaderScore(p.ID, p.Name, p.Host, p.Config)
		scores = append(scores, hc)
		total += float64(hc.Score)
	}
	if len(proxies) > 0 {
		ov.AvgHeaderScore = total / float64(len(proxies))
	}
	ov.Headers = scores
	return ov
}

// proxyRow est une vue minimale d'un proxy (pour éviter l'import de api/).
type proxyRow struct {
	ID     string
	Name   string
	Host   string
	Config router.Route
}

// LoadProxies charge les proxies actifs depuis la DB.
func (s *Store) LoadProxies() []proxyRow {
	rows, err := s.db.Query(`SELECT id, name, config FROM proxies WHERE enabled=1`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []proxyRow
	for rows.Next() {
		var p proxyRow
		var cfgJSON string
		if err := rows.Scan(&p.ID, &p.Name, &cfgJSON); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(cfgJSON), &p.Config)
		p.Host = p.Config.Host
		out = append(out, p)
	}
	return out
}

// hasIPFiltering indique un contrôle d'accès réseau : CIDR et/ou GeoIP.
func hasIPFiltering(cfg router.Route) bool {
	if cfg.IPFilter != nil && len(cfg.IPFilter.CIDRs) > 0 {
		return true
	}
	if cfg.GeoIP != nil && len(cfg.GeoIP.Countries) > 0 {
		return true
	}
	return false
}

// ComputeHeaderScore calcule le score de sécurité d'un proxy.
func ComputeHeaderScore(id, name, host string, cfg router.Route) HeaderCheck {
	h := cfg.Headers

	checks := []Check{
		{Name: "TLS activé",           Present: cfg.TLSEnabled,                                        Points: 20},
		{Name: "HSTS",                 Present: h != nil && h.HSTS,                                    Points: 15},
		{Name: "X-Frame-Options",      Present: h != nil && h.XFrameOptions != "",                     Points: 12},
		{Name: "Masquer Server",       Present: h != nil && h.HideServer,                              Points: 8},
		{Name: "Rate Limiting",        Present: cfg.RateLimit != nil,                                  Points: 10},
		{Name: "WAF activé",           Present: cfg.WAF != nil && cfg.WAF.Enabled,                    Points: 15},
		{Name: "Protection bot",       Present: cfg.Bot != nil && cfg.Bot.Enabled,                    Points: 10},
		{Name: "Filtrage IP",          Present: hasIPFiltering(cfg),                                   Points: 5},
		{Name: "Authentification",     Present: (cfg.JWT != nil && cfg.JWT.Enabled) || (cfg.SSO != nil && cfg.SSO.Enabled) || (cfg.MTLS != nil && cfg.MTLS.Enabled), Points: 5},
	}

	score := 0
	for _, c := range checks {
		if c.Present {
			score += c.Points
		}
	}
	if score > 100 {
		score = 100
	}

	return HeaderCheck{
		ProxyID:   id,
		ProxyName: name,
		Domain:    host,
		Score:     score,
		Grade:     scoreToGrade(score),
		Checks:    checks,
	}
}

func scoreToGrade(s int) string {
	switch {
	case s >= 95:
		return "A+"
	case s >= 85:
		return "A"
	case s >= 70:
		return "B"
	case s >= 55:
		return "C"
	case s >= 40:
		return "D"
	case s >= 25:
		return "E"
	default:
		return "F"
	}
}
