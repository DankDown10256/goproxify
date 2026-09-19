// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package crowdsec synchronise les décisions CrowdSec LAPI directement dans le Core.
// Le Bouncer tourne dans le Core — autonome, sans Admin.
package crowdsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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

// Ban est un ban dérivé des décisions CrowdSec.
type Ban struct {
	ID        string
	IP        string
	Reason    string
	ExpiresAt *time.Time // nil = permanent
}

// Snapshot est la vue persistée sur disque.
type Snapshot struct {
	Threats []Decision `json:"threats"`
}

// Bouncer consomme la LAPI CrowdSec (stream) et applique les décisions dans le Core.
type Bouncer struct {
	mu      sync.Mutex
	cfg     Config
	startup bool // true → GET stream?startup=true (snapshot complet)
	threats []Decision

	client *http.Client
	log    interface {
		Info(msg string, args ...any)
		Warn(msg string, args ...any)
	}

	// OnBansChanged est appelé après chaque sync modifiant les bans.
	// Le callback reçoit la liste complète des bans CrowdSec actifs.
	OnBansChanged func(bans []Ban)

	// OnDecisions est appelé pour notifier l'Admin des nouvelles/supprimées décisions.
	OnDecisions func(added, deleted []Decision)

	lastSyncMu sync.RWMutex
	lastSync   time.Time

	stop chan struct{}
	done chan struct{}
}

// New crée un Bouncer.
func New(log interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
}) *Bouncer {
	return &Bouncer{
		cfg:     DefaultConfig(),
		startup: true,
		client:  &http.Client{Timeout: 15 * time.Second},
		log:     log,
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
}

// LastSync retourne l'heure de la dernière synchronisation réussie.
func (b *Bouncer) LastSync() time.Time {
	b.lastSyncMu.RLock()
	defer b.lastSyncMu.RUnlock()
	return b.lastSync
}

// UpdateConfig remplace la config à chaud et force un resync startup.
func (b *Bouncer) UpdateConfig(cfg Config) {
	b.mu.Lock()
	b.cfg = cfg
	if cfg.Enabled {
		b.startup = true
	}
	b.mu.Unlock()
}

// GetConfig retourne la config courante.
func (b *Bouncer) GetConfig() Config {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cfg
}

// Start lance la boucle de synchronisation (toutes les 60s).
func (b *Bouncer) Start(ctx context.Context) {
	// Charger le snapshot disque pour avoir des bans immédiats au démarrage.
	if snap := loadSnapshot(""); len(snap.Threats) > 0 {
		b.mu.Lock()
		b.threats = snap.Threats
		b.startup = false // snapshot déjà là, pas de full-resync immédiat
		b.mu.Unlock()
		b.rebuildAndNotify()
	}

	go b.loop(ctx)
}

// Stop arrête proprement le bouncer.
func (b *Bouncer) Stop() {
	close(b.stop)
	<-b.done
}

func (b *Bouncer) loop(ctx context.Context) {
	defer close(b.done)
	b.mu.Lock()
	cfg := b.cfg
	b.mu.Unlock()
	if cfg.Enabled {
		b.sync(ctx, cfg)
	}
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-b.stop:
			return
		case <-ctx.Done():
			return
		case <-t.C:
			b.mu.Lock()
			cfg = b.cfg
			b.mu.Unlock()
			if cfg.Enabled {
				b.sync(ctx, cfg)
			}
		}
	}
}

// SyncNow déclenche une synchronisation immédiate.
func (b *Bouncer) SyncNow(ctx context.Context) {
	b.mu.Lock()
	cfg := b.cfg
	b.mu.Unlock()
	if cfg.Enabled {
		b.sync(ctx, cfg)
		return
	}
	// Désactivé → purge
	b.mu.Lock()
	b.threats = nil
	b.mu.Unlock()
	_ = saveSnapshot("", Snapshot{})
	b.rebuildAndNotify()
}

func (b *Bouncer) sync(ctx context.Context, cfg Config) {
	b.lastSyncMu.Lock()
	b.lastSync = time.Now()
	b.lastSyncMu.Unlock()

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
			b.threats = nil
			b.startup = false
			b.mu.Unlock()
			_ = saveSnapshot("", Snapshot{})
			b.rebuildAndNotify()
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
	b.mu.Lock()
	if startup {
		b.threats = stream.New
		b.startup = false
		changed = true
		b.log.Info("crowdsec: snapshot LAPI appliqué", "decisions", len(stream.New))
	} else {
		nNew, nDel := b.applyDelta(stream.New, stream.Deleted)
		if nNew > 0 || nDel > 0 {
			changed = true
			b.log.Info("crowdsec: delta synchronisé", "new", nNew, "deleted", nDel)
		}
	}
	threats := b.threats
	b.mu.Unlock()

	if changed {
		_ = saveSnapshot("", Snapshot{Threats: threats})
		b.rebuildAndNotify()
		if b.OnDecisions != nil {
			b.OnDecisions(stream.New, stream.Deleted)
		}
	}
}

// applyDelta ajoute / supprime des décisions. Doit être appelé sous b.mu.
func (b *Bouncer) applyDelta(added, deleted []Decision) (nNew, nDel int) {
	// Index ip→scenario pour la suppression rapide.
	for _, d := range deleted {
		if d.Value == "" {
			continue
		}
		before := len(b.threats)
		filtered := b.threats[:0]
		for _, t := range b.threats {
			if t.Value == d.Value && (d.Scenario == "" || t.Scenario == d.Scenario) {
				continue
			}
			filtered = append(filtered, t)
		}
		b.threats = filtered
		nDel += before - len(filtered)
	}
	seen := make(map[string]bool, len(b.threats))
	for _, t := range b.threats {
		seen[t.Value+"|"+t.Scenario] = true
	}
	for _, d := range added {
		if d.Value == "" {
			continue
		}
		key := d.Value + "|" + d.Scenario
		if !seen[key] {
			b.threats = append(b.threats, d)
			seen[key] = true
			nNew++
		}
	}
	return
}

// rebuildAndNotify reconstruit la liste de bans depuis les menaces et appelle OnBansChanged.
func (b *Bouncer) rebuildAndNotify() {
	b.mu.Lock()
	threats := b.threats
	b.mu.Unlock()

	seen := make(map[string]bool, len(threats))
	var bans []Ban
	for _, d := range threats {
		ip := d.Value
		if ip == "" || seen[ip] {
			continue
		}
		t := strings.ToLower(strings.TrimSpace(d.Type))
		if t != "" && t != "ban" {
			continue
		}
		seen[ip] = true
		ban := Ban{
			ID:     "crowdsec:" + ip,
			IP:     ip,
			Reason: d.Scenario,
		}
		if ban.Reason == "" {
			ban.Reason = "CrowdSec ban"
		}
		if exp := parseExpires(d.Duration); exp != nil {
			ban.ExpiresAt = exp
		}
		bans = append(bans, ban)
	}

	if b.OnBansChanged != nil {
		b.OnBansChanged(bans)
	}
}

func parseExpires(duration string) *time.Time {
	d := strings.TrimSpace(duration)
	if d == "" || d == "-1" || d == "0" {
		return nil
	}
	parsed, err := time.ParseDuration(d)
	if err != nil || parsed <= 0 {
		return nil
	}
	t := time.Now().Add(parsed)
	return &t
}

// --- Persistance JSON sur le volume Core ---

const (
	defaultDir    = "/etc/goproxify/crowdsec"
	snapshotFile  = "threats.json"
	configFile    = "config.json"
	envDirKey     = "GPX_CROWDSEC_PATH"
)

func Dir() string {
	if p := os.Getenv(envDirKey); p != "" {
		return p
	}
	return defaultDir
}

func loadSnapshot(dir string) Snapshot {
	if dir == "" {
		dir = Dir()
	}
	data, err := os.ReadFile(filepath.Join(dir, snapshotFile))
	if err != nil {
		return Snapshot{}
	}
	var s Snapshot
	_ = json.Unmarshal(data, &s)
	return s
}

func saveSnapshot(dir string, s Snapshot) error {
	if dir == "" {
		dir = Dir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(s, "", "  ")
	tmp, err := os.CreateTemp(dir, "cs-snap-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	_ = tmp.Sync()
	_ = tmp.Close()
	return os.Rename(name, filepath.Join(dir, snapshotFile))
}

// LoadConfig lit la config depuis le disque.
func LoadConfig(dir string) Config {
	if dir == "" {
		dir = Dir()
	}
	data, err := os.ReadFile(filepath.Join(dir, configFile))
	if err != nil {
		return DefaultConfig()
	}
	var cfg Config
	if json.Unmarshal(data, &cfg) != nil {
		return DefaultConfig()
	}
	return cfg
}

// SaveConfig persiste la config (atomic write).
func SaveConfig(dir string, cfg Config) error {
	if dir == "" {
		dir = Dir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	id := uuid.New().String()[:8]
	tmp, err := os.CreateTemp(dir, "cs-cfg-"+id+"-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	_ = tmp.Sync()
	_ = tmp.Close()
	return os.Rename(name, filepath.Join(dir, configFile))
}
