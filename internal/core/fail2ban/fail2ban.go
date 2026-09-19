// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package fail2ban surveille le flux d'access logs du Core et banne automatiquement
// les IPs abusives. Le moteur tourne entièrement dans le Core — indépendant de l'Admin.
package fail2ban

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Config paramètre le moteur Fail2Ban Core.
type Config struct {
	Enabled           bool     `json:"enabled"`
	WindowSec         int      `json:"window_sec"`          // fenêtre glissante (défaut 300)
	MaxErrors         int      `json:"max_errors"`          // seuil déclenchant le ban (défaut 50)
	BanDurationSec    int      `json:"ban_duration_sec"`    // 0 = permanent
	TrustForwardedFor bool     `json:"trust_forwarded_for"`
	Whitelist         []string `json:"whitelist"`
}

func DefaultConfig() Config {
	return Config{
		Enabled:        true,
		WindowSec:      300,
		MaxErrors:      50,
		BanDurationSec: 0,
	}
}

// Ban est un ban produit par le moteur.
type Ban struct {
	ID        string
	IP        string
	Reason    string
	ExpiresAt *time.Time // nil = permanent
}

// Engine maintient une fenêtre glissante d'erreurs par IP et crée des bans autonomes.
// Il est alimenté via Feed() depuis le middleware AccessLogger.
type Engine struct {
	mu  sync.RWMutex
	cfg Config

	// counters : ip → timestamps des requêtes 4xx (hors 404)
	counters map[string][]time.Time
	// banned : ips déjà bannies en mémoire (évite les doublons)
	banned map[string]struct{}

	bansMu  sync.RWMutex

	// OnBan est appelé dès qu'un nouveau ban est créé.
	// Le callback est responsable de persister et de notifier l'Admin.
	OnBan func(b Ban)

	lastBanMu sync.RWMutex
	lastBanAt time.Time

	stop chan struct{}
	done chan struct{}
}

// New crée un Engine. Appeler Start() pour lancer le nettoyage périodique.
func New() *Engine {
	return &Engine{
		cfg:      DefaultConfig(),
		counters: make(map[string][]time.Time),
		banned:   make(map[string]struct{}),
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
}

// Start lance la goroutine de nettoyage des compteurs expirés.
func (e *Engine) Start(_ context.Context) {
	go e.sweep()
}

// Stop arrête proprement le moteur.
func (e *Engine) Stop() {
	close(e.stop)
	<-e.done
}

// UpdateConfig remplace la configuration à chaud.
func (e *Engine) UpdateConfig(cfg Config) {
	e.mu.Lock()
	e.cfg = cfg
	e.mu.Unlock()
}

// LastBan retourne l'heure du dernier ban déclenché (zéro si aucun).
func (e *Engine) LastBan() time.Time {
	e.lastBanMu.RLock()
	defer e.lastBanMu.RUnlock()
	return e.lastBanAt
}

// GetConfig retourne la config courante.
func (e *Engine) GetConfig() Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg
}

// Feed enregistre une requête. Appelé depuis le middleware AccessLogger pour chaque entrée.
// status et ip sont extraits du log d'accès.
func (e *Engine) Feed(ip string, status int) {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()

	if !cfg.Enabled {
		return
	}
	// Seules les erreurs 4xx hors 404 comptent (abus client, pas erreurs légitimes).
	if status < 400 || status >= 500 || status == 404 {
		return
	}

	rawIP := strings.Split(ip, ":")[0]
	if rawIP == "" || isPrivateIP(rawIP) || e.isWhitelisted(rawIP, cfg.Whitelist) {
		return
	}

	window := time.Duration(cfg.WindowSec) * time.Second
	if window <= 0 {
		window = 300 * time.Second
	}
	maxErr := cfg.MaxErrors
	if maxErr <= 0 {
		maxErr = 50
	}

	now := time.Now()
	cutoff := now.Add(-window)

	e.mu.Lock()
	// Nettoyage de la fenêtre pour cette IP.
	ts := e.counters[rawIP]
	filtered := ts[:0]
	for _, t := range ts {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}
	filtered = append(filtered, now)
	e.counters[rawIP] = filtered
	count := len(filtered)
	e.mu.Unlock()

	if count < maxErr {
		return
	}

	// Vérification doublon en mémoire.
	e.bansMu.RLock()
	_, already := e.banned[rawIP]
	e.bansMu.RUnlock()
	if already {
		return
	}

	e.bansMu.Lock()
	e.banned[rawIP] = struct{}{}
	e.mu.Lock()
	delete(e.counters, rawIP)
	e.mu.Unlock()
	e.bansMu.Unlock()

	ban := Ban{
		ID:     uuid.New().String(),
		IP:     rawIP,
		Reason: "Fail2Ban: trop d'erreurs",
	}
	if cfg.BanDurationSec > 0 {
		exp := now.Add(time.Duration(cfg.BanDurationSec) * time.Second)
		ban.ExpiresAt = &exp
	}

	e.lastBanMu.Lock()
	e.lastBanAt = time.Now()
	e.lastBanMu.Unlock()
	if e.OnBan != nil {
		e.OnBan(ban)
	}
}

// UnbanIP retire une IP de la liste en mémoire (suite à un unban Admin).
func (e *Engine) UnbanIP(ip string) {
	e.bansMu.Lock()
	delete(e.banned, ip)
	e.bansMu.Unlock()
}

// sweep nettoie périodiquement les compteurs pour les IPs inactives.
func (e *Engine) sweep() {
	defer close(e.done)
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-e.stop:
			return
		case <-t.C:
			e.mu.RLock()
			cfg := e.cfg
			e.mu.RUnlock()
			window := time.Duration(cfg.WindowSec) * time.Second
			if window <= 0 {
				window = 300 * time.Second
			}
			cutoff := time.Now().Add(-window)

			e.mu.Lock()
			for ip, ts := range e.counters {
				filtered := ts[:0]
				for _, t := range ts {
					if t.After(cutoff) {
						filtered = append(filtered, t)
					}
				}
				if len(filtered) == 0 {
					delete(e.counters, ip)
				} else {
					e.counters[ip] = filtered
				}
			}
			e.mu.Unlock()
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

// cloudflareRanges : ces IPs portent le trafic de tous les utilisateurs finaux
// quand Cloudflare est en amont — ne jamais bannir.
var cloudflareRanges = []string{
	"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"104.16.0.0/13", "104.24.0.0/14",
	"108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
	"162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20",
	"188.114.96.0/20", "190.93.240.0/20", "197.234.240.0/22",
	"198.41.128.0/17",
	"2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
	"2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

func isPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true
	}
	for _, cidr := range append([]string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "::1/128", "fc00::/7",
	}, cloudflareRanges...) {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(parsed) {
			return true
		}
	}
	return false
}

// --- Persistance de la config sur le volume Core ---

const (
	defaultCfgDir  = "/etc/goproxify/fail2ban"
	cfgFileName    = "config.json"
	envCfgPathKey  = "GPX_F2B_CONFIG_PATH"
)

// CfgDir retourne le répertoire de configuration (env GPX_F2B_CONFIG_PATH ou défaut).
func CfgDir() string {
	if p := os.Getenv(envCfgPathKey); p != "" {
		return p
	}
	return defaultCfgDir
}

// LoadConfig lit la config depuis le disque. Retourne DefaultConfig() si absent.
func LoadConfig(dir string) Config {
	if dir == "" {
		dir = CfgDir()
	}
	data, err := os.ReadFile(filepath.Join(dir, cfgFileName))
	if err != nil {
		return DefaultConfig()
	}
	var cfg Config
	if json.Unmarshal(data, &cfg) != nil {
		return DefaultConfig()
	}
	return cfg
}

// SaveConfig persiste la config sur le disque (atomic write).
func SaveConfig(dir string, cfg Config) error {
	if dir == "" {
		dir = CfgDir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "f2b-cfg-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	_ = tmp.Close()
	return os.Rename(tmpName, filepath.Join(dir, cfgFileName))
}
