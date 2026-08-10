// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package crowdsec synchronise les décisions CrowdSec LAPI vers security_threats / security_bans.
package crowdsec

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config paramètre l'intégration CrowdSec.
type Config struct {
	Enabled bool   `json:"enabled"`
	APIURL  string `json:"api_url"` // ex: http://localhost:8080
	APIKey  string `json:"api_key"`
}

func DefaultConfig() Config {
	return Config{
		Enabled: false,
		APIURL:  "http://localhost:8080",
	}
}

// Decision est une décision CrowdSec (stream LAPI).
type Decision struct {
	Value    string `json:"value"`
	Scenario string `json:"scenario"`
	Origin   string `json:"origin"`
	Type     string `json:"type"`
	Duration string `json:"duration"`
	Scope    string `json:"scope"`
}

// Bouncer consomme la LAPI CrowdSec (stream) et synchronise les décisions en DB.
type Bouncer struct {
	db     *sql.DB
	log    *slog.Logger
	client *http.Client

	mu      sync.Mutex
	startup bool // true → GET stream?startup=true (snapshot complet)

	// OnChange est appelé après toute sync qui modifie les bans (push Core).
	OnChange func()
	// OnNewDecision est appelé pour chaque nouvelle décision de type ban.
	OnNewDecision func(d Decision)
}

// New crée un Bouncer.
func New(db *sql.DB, log *slog.Logger) *Bouncer {
	return &Bouncer{
		db:      db,
		log:     log,
		client:  &http.Client{Timeout: 15 * time.Second},
		startup: true,
	}
}

// Start lance la boucle de synchronisation (toutes les 60s).
func (b *Bouncer) Start(ctx context.Context) {
	go func() {
		cfg := b.loadConfig()
		if cfg.Enabled {
			b.sync(ctx, cfg)
		}
		t := time.NewTicker(60 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				cfg := b.loadConfig()
				if cfg.Enabled {
					b.sync(ctx, cfg)
				}
			}
		}
	}()
}

// GetConfig retourne la config courante.
func (b *Bouncer) GetConfig() Config {
	return b.loadConfig()
}

// SaveConfig persiste la config CrowdSec et force un resync startup si activé.
func (b *Bouncer) SaveConfig(cfg Config) error {
	bs, _ := json.Marshal(cfg)
	_, err := b.db.Exec(
		`INSERT OR REPLACE INTO crowdsec_config (key, value) VALUES ('config', ?)`, string(bs))
	if err != nil {
		return err
	}
	b.mu.Lock()
	b.startup = cfg.Enabled // true → prochain sync = snapshot ; false → ready for re-enable
	b.mu.Unlock()
	return nil
}

// SyncNow déclenche immédiatement une synchronisation LAPI.
// Si CrowdSec est désactivé, purge les menaces/bans CrowdSec et notifie le Core.
func (b *Bouncer) SyncNow(ctx context.Context) {
	cfg := b.loadConfig()
	if cfg.Enabled {
		b.sync(ctx, cfg)
		return
	}
	if err := b.clearState(ctx); err != nil {
		b.log.Warn("crowdsec: purge après désactivation", "err", err)
		return
	}
	b.notifyChange()
}

func (b *Bouncer) clearState(ctx context.Context) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, `DELETE FROM security_bans WHERE source='crowdsec'`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM security_threats`); err != nil {
		return err
	}
	return tx.Commit()
}

func (b *Bouncer) loadConfig() Config {
	var raw string
	b.db.QueryRow(`SELECT value FROM crowdsec_config WHERE key='config'`).Scan(&raw) //nolint:errcheck
	cfg := DefaultConfig()
	json.Unmarshal([]byte(raw), &cfg) //nolint:errcheck
	return cfg
}

func (b *Bouncer) sync(ctx context.Context, cfg Config) {
	b.mu.Lock()
	startup := b.startup
	b.mu.Unlock()

	base := strings.TrimRight(cfg.APIURL, "/")
	url := fmt.Sprintf("%s/v1/decisions/stream?startup=%t", base, startup)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		b.log.Warn("crowdsec: création requête échouée", "err", err)
		return
	}
	req.Header.Set("X-Api-Key", cfg.APIKey)

	resp, err := b.client.Do(req)
	if err != nil {
		b.log.Warn("crowdsec: connexion LAPI échouée", "err", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		if startup {
			b.mu.Lock()
			b.startup = false
			b.mu.Unlock()
			if err := b.replaceThreats(ctx, nil); err != nil {
				b.log.Warn("crowdsec: reset menaces", "err", err)
				return
			}
			if err := b.rebuildBans(ctx); err != nil {
				b.log.Warn("crowdsec: rebuild bans", "err", err)
				return
			}
			b.notifyChange()
		}
		return
	}
	if resp.StatusCode != http.StatusOK {
		b.log.Warn("crowdsec: réponse inattendue", "status", resp.StatusCode)
		return
	}

	var stream struct {
		New     []Decision `json:"new"`
		Deleted []Decision `json:"deleted"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&stream); err != nil {
		b.log.Warn("crowdsec: décodage stream échoué", "err", err)
		return
	}

	changed := false
	if startup {
		if err := b.replaceThreats(ctx, stream.New); err != nil {
			b.log.Warn("crowdsec: replace menaces", "err", err)
			return
		}
		for _, d := range stream.New {
			if isBanDecision(d) && b.OnNewDecision != nil {
				b.OnNewDecision(d)
			}
		}
		changed = true
		b.mu.Lock()
		b.startup = false
		b.mu.Unlock()
		b.log.Info("crowdsec: snapshot LAPI appliqué", "decisions", len(stream.New))
	} else {
		nNew, nDel, inserted, err := b.applyDelta(ctx, stream.New, stream.Deleted)
		if err != nil {
			b.log.Warn("crowdsec: apply delta", "err", err)
			return
		}
		if nNew > 0 || nDel > 0 {
			changed = true
			b.log.Info("crowdsec: delta synchronisé", "new", nNew, "deleted", nDel)
		}
		if b.OnNewDecision != nil {
			for _, d := range inserted {
				if isBanDecision(d) {
					b.OnNewDecision(d)
				}
			}
		}
	}

	if changed {
		if err := b.rebuildBans(ctx); err != nil {
			b.log.Warn("crowdsec: rebuild bans", "err", err)
			return
		}
		b.notifyChange()
	}
}

func (b *Bouncer) notifyChange() {
	if b.OnChange != nil {
		b.OnChange()
	}
}

func isBanDecision(d Decision) bool {
	t := strings.ToLower(strings.TrimSpace(d.Type))
	return t == "" || t == "ban"
}

func (b *Bouncer) replaceThreats(ctx context.Context, decisions []Decision) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(ctx, `DELETE FROM security_threats`); err != nil {
		return err
	}
	for _, d := range decisions {
		if d.Value == "" {
			continue
		}
		typ := d.Type
		if typ == "" {
			typ = "ban"
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO security_threats (ip, scenario, origin, type, duration) VALUES (?,?,?,?,?)`,
			d.Value, d.Scenario, d.Origin, typ, d.Duration); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (b *Bouncer) applyDelta(ctx context.Context, added, deleted []Decision) (int, int, []Decision, error) {
	nNew, nDel := 0, 0
	var inserted []Decision
	for _, d := range added {
		if d.Value == "" {
			continue
		}
		typ := d.Type
		if typ == "" {
			typ = "ban"
		}
		res, err := b.db.ExecContext(ctx,
			`INSERT OR IGNORE INTO security_threats (ip, scenario, origin, type, duration) VALUES (?,?,?,?,?)`,
			d.Value, d.Scenario, d.Origin, typ, d.Duration)
		if err != nil {
			return nNew, nDel, inserted, err
		}
		if rows, _ := res.RowsAffected(); rows > 0 {
			nNew++
			inserted = append(inserted, d)
		}
	}
	for _, d := range deleted {
		if d.Value == "" {
			continue
		}
		res, err := b.db.ExecContext(ctx,
			`DELETE FROM security_threats WHERE ip=? AND scenario=?`,
			d.Value, d.Scenario)
		if err != nil {
			res, err = b.db.ExecContext(ctx, `DELETE FROM security_threats WHERE ip=?`, d.Value)
			if err != nil {
				return nNew, nDel, inserted, err
			}
		}
		if rows, _ := res.RowsAffected(); rows > 0 {
			nDel += int(rows)
		}
	}
	return nNew, nDel, inserted, nil
}

func (b *Bouncer) rebuildBans(ctx context.Context) error {
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(ctx, `DELETE FROM security_bans WHERE source='crowdsec'`); err != nil {
		return err
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT ip, scenario, duration FROM security_threats
		WHERE lower(type)='ban' OR type='' OR type IS NULL
		ORDER BY created_at DESC`)
	if err != nil {
		return err
	}
	defer rows.Close()

	seen := map[string]bool{}
	for rows.Next() {
		var ip, scenario, duration string
		if err := rows.Scan(&ip, &scenario, &duration); err != nil {
			continue
		}
		if ip == "" || seen[ip] {
			continue
		}
		seen[ip] = true
		id := "crowdsec:" + ip
		reason := scenario
		if reason == "" {
			reason = "CrowdSec ban"
		}
		expires := parseExpires(duration)
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO security_bans (id, ip, domain, reason, source, expires_at) VALUES (?,?,?,?,?,?)`,
			id, ip, "", reason, "crowdsec", expires); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func parseExpires(duration string) any {
	d := strings.TrimSpace(duration)
	if d == "" || d == "-1" || d == "0" {
		return nil
	}
	parsed, err := time.ParseDuration(d)
	if err != nil || parsed <= 0 {
		return nil
	}
	return time.Now().Add(parsed).UTC().Format(time.RFC3339)
}
