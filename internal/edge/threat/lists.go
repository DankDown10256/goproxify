// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

//go:embed defaults/ua.txt
var defaultUA []byte

//go:embed defaults/paths.txt
var defaultPaths []byte

//go:embed defaults/ips.txt
var defaultIPs []byte

const listsDir = "/etc/goproxify/threat-lists"
const listsEnvKey = "GPX_THREAT_LISTS_PATH"

func listsPath() string {
	if p := os.Getenv(listsEnvKey); p != "" {
		return p
	}
	return listsDir
}

// listsMeta est stocké sur disque pour la sync HA (timestamp par liste).
type listsMeta struct {
	UAUpdatedAt   time.Time `json:"ua_updated_at,omitempty"`
	PathUpdatedAt time.Time `json:"path_updated_at,omitempty"`
	IPUpdatedAt   time.Time `json:"ip_updated_at,omitempty"`
}

// Lists contient les listes compilées prêtes à l'emploi.
type Lists struct {
	mu sync.RWMutex

	// UA : sous-chaînes en minuscules.
	ua []string
	// Paths : préfixes exacts en minuscules.
	paths []string
	// IPs : réseaux compilés.
	nets []*net.IPNet

	meta listsMeta
	log  *slog.Logger
}

func newLists(log *slog.Logger) *Lists {
	return &Lists{log: log}
}

// MatchUA retourne true si l'User-Agent correspond à une entrée de la liste.
func (l *Lists) MatchUA(ua string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	uaLow := strings.ToLower(ua)
	for _, s := range l.ua {
		if strings.Contains(uaLow, s) {
			return true
		}
	}
	return false
}

// MatchPath retourne true si le path correspond à un préfixe de la liste.
func (l *Lists) MatchPath(path string) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	pathLow := strings.ToLower(path)
	for _, p := range l.paths {
		if strings.HasPrefix(pathLow, p) {
			return true
		}
	}
	return false
}

// MatchIP retourne true si l'IP figure dans une liste de réseaux bannis.
func (l *Lists) MatchIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	for _, n := range l.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// Meta retourne les timestamps des dernières mises à jour (pour sync HA).
func (l *Lists) Meta() listsMeta {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.meta
}

// refresh télécharge et recharge les listes selon la config.
func (l *Lists) refresh(ctx context.Context, cfg ListsConfig) {
	dir := listsPath()
	_ = os.MkdirAll(dir, 0o755)

	if cfg.UAEnabled && len(cfg.UASources) > 0 {
		if data, updated := l.fetchAndCache(ctx, dir, "ua.txt", cfg.UASources); updated {
			entries := parseLines(data)
			l.mu.Lock()
			l.ua = entries
			l.meta.UAUpdatedAt = time.Now()
			l.mu.Unlock()
			l.log.Info("threat: liste UA mise à jour", "count", len(entries))
		}
	}

	if cfg.PathEnabled && len(cfg.PathSources) > 0 {
		if data, updated := l.fetchAndCache(ctx, dir, "paths.txt", cfg.PathSources); updated {
			entries := parseLines(data)
			l.mu.Lock()
			l.paths = entries
			l.meta.PathUpdatedAt = time.Now()
			l.mu.Unlock()
			l.log.Info("threat: liste paths mise à jour", "count", len(entries))
		}
	}

	if cfg.IPEnabled && len(cfg.IPSources) > 0 {
		if data, updated := l.fetchAndCache(ctx, dir, "ips.txt", cfg.IPSources); updated {
			nets := parseNets(data)
			l.mu.Lock()
			l.nets = nets
			l.meta.IPUpdatedAt = time.Now()
			l.mu.Unlock()
			l.log.Info("threat: liste IPs mise à jour", "count", len(nets))
		}
	}

	l.saveMeta(dir)
}

// loadFromDisk charge les listes depuis le disque au démarrage.
// Si un fichier n'existe pas encore, il est initialisé depuis les defaults embarqués.
func (l *Lists) loadFromDisk(cfg ListsConfig) {
	dir := listsPath()
	_ = os.MkdirAll(dir, 0o755)
	l.loadMeta(dir)

	if cfg.UAEnabled {
		data := l.seedIfMissing(dir, "ua.txt", defaultUA)
		if len(data) > 0 {
			entries := parseLines(data)
			l.mu.Lock()
			l.ua = entries
			l.mu.Unlock()
		}
	}
	if cfg.PathEnabled {
		data := l.seedIfMissing(dir, "paths.txt", defaultPaths)
		if len(data) > 0 {
			entries := parseLines(data)
			l.mu.Lock()
			l.paths = entries
			l.mu.Unlock()
		}
	}
	if cfg.IPEnabled {
		data := l.seedIfMissing(dir, "ips.txt", defaultIPs)
		if len(data) > 0 {
			nets := parseNets(data)
			l.mu.Lock()
			l.nets = nets
			l.mu.Unlock()
		}
	}
}

// seedDefaults s'assure que les 3 fichiers de listes existent dans le volume.
// Appelé au démarrage du moteur, indépendamment de la config.
func (l *Lists) seedDefaults() {
	dir := listsPath()
	_ = os.MkdirAll(dir, 0o755)
	l.seedIfMissing(dir, "ua.txt", defaultUA)
	l.seedIfMissing(dir, "paths.txt", defaultPaths)
	l.seedIfMissing(dir, "ips.txt", defaultIPs)
}

// seedIfMissing retourne le contenu du fichier sur disque.
// Si le fichier est absent, il est créé à partir du contenu embarqué.
func (l *Lists) seedIfMissing(dir, filename string, embedded []byte) []byte {
	path := filepath.Join(dir, filename)
	data, err := os.ReadFile(path)
	if err == nil {
		return data
	}
	l.log.Info("threat: liste absente, initialisation depuis les defaults embarqués", "file", filename)
	_ = os.WriteFile(path, embedded, 0o644)
	return embedded
}

// fetchAndCache télécharge depuis les sources et met en cache sur disque.
// Retourne (contenu, true) si téléchargé avec succès, ou (contenu cache, false) si déjà à jour / échec.
func (l *Lists) fetchAndCache(ctx context.Context, dir, filename string, sources []string) ([]byte, bool) {
	path := filepath.Join(dir, filename)

	var combined []byte
	ok := false
	for _, src := range sources {
		data, err := fetchURL(ctx, src)
		if err != nil {
			l.log.Warn("threat: téléchargement échoué", "src", src, "err", err)
			continue
		}
		combined = append(combined, data...)
		combined = append(combined, '\n')
		ok = true
	}

	if !ok {
		// Fallback : lire depuis le disque (y compris si voisin HA a copié un fichier plus récent).
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, false
		}
		return data, false
	}

	// Écriture atomique.
	tmp, err := os.CreateTemp(dir, filename+"-*.tmp")
	if err != nil {
		return combined, true
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(combined); err != nil || tmp.Close() != nil {
		return combined, true
	}
	_ = os.Rename(tmp.Name(), path)
	return combined, true
}

func fetchURL(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "goproxify-threat/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 32<<20)) // max 32 MiB
}

func parseLines(data []byte) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.ToLower(line))
	}
	return out
}

func parseNets(data []byte) []*net.IPNet {
	var out []*net.IPNet
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		// Supporte IP seule ou CIDR.
		if !strings.Contains(line, "/") {
			line += "/32"
		}
		_, n, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		out = append(out, n)
	}
	return out
}

func (l *Lists) saveMeta(dir string) {
	l.mu.RLock()
	m := l.meta
	l.mu.RUnlock()
	data, _ := json.Marshal(m)
	_ = os.WriteFile(filepath.Join(dir, "meta.json"), data, 0o644)
}

func (l *Lists) loadMeta(dir string) {
	data, err := os.ReadFile(filepath.Join(dir, "meta.json"))
	if err != nil {
		return
	}
	var m listsMeta
	if json.Unmarshal(data, &m) == nil {
		l.mu.Lock()
		l.meta = m
		l.mu.Unlock()
	}
}

// HASync accepte des fichiers plus récents d'un peer HA.
// Le peer envoie les fichiers + meta via /internal/v1/threat-lists/sync.
type HAPayload struct {
	UAData      []byte    `json:"ua_data,omitempty"`
	UAUpdatedAt time.Time `json:"ua_updated_at,omitempty"`

	PathData      []byte    `json:"path_data,omitempty"`
	PathUpdatedAt time.Time `json:"path_updated_at,omitempty"`

	IPData      []byte    `json:"ip_data,omitempty"`
	IPUpdatedAt time.Time `json:"ip_updated_at,omitempty"`
}

// ApplyHAPayload remplace les listes locales si le peer a des données plus récentes.
func (l *Lists) ApplyHAPayload(p HAPayload, cfg ListsConfig) {
	dir := listsPath()
	changed := false

	l.mu.Lock()
	if !p.UAUpdatedAt.IsZero() && p.UAUpdatedAt.After(l.meta.UAUpdatedAt) && len(p.UAData) > 0 {
		l.ua = parseLines(p.UAData)
		l.meta.UAUpdatedAt = p.UAUpdatedAt
		_ = os.WriteFile(filepath.Join(dir, "ua.txt"), p.UAData, 0o644)
		changed = true
		l.log.Info("threat: liste UA reçue d'un peer HA", "updated_at", p.UAUpdatedAt)
	}
	if !p.PathUpdatedAt.IsZero() && p.PathUpdatedAt.After(l.meta.PathUpdatedAt) && len(p.PathData) > 0 {
		l.paths = parseLines(p.PathData)
		l.meta.PathUpdatedAt = p.PathUpdatedAt
		_ = os.WriteFile(filepath.Join(dir, "paths.txt"), p.PathData, 0o644)
		changed = true
		l.log.Info("threat: liste paths reçue d'un peer HA", "updated_at", p.PathUpdatedAt)
	}
	if !p.IPUpdatedAt.IsZero() && p.IPUpdatedAt.After(l.meta.IPUpdatedAt) && len(p.IPData) > 0 {
		l.nets = parseNets(p.IPData)
		l.meta.IPUpdatedAt = p.IPUpdatedAt
		_ = os.WriteFile(filepath.Join(dir, "ips.txt"), p.IPData, 0o644)
		changed = true
		l.log.Info("threat: liste IPs reçue d'un peer HA", "updated_at", p.IPUpdatedAt)
	}
	l.mu.Unlock()

	if changed {
		l.saveMeta(dir)
	}
}

// BuildHAPayload construit le payload à envoyer à un peer HA (uniquement ce qu'on a).
func (l *Lists) BuildHAPayload() HAPayload {
	dir := listsPath()
	var p HAPayload

	l.mu.RLock()
	m := l.meta
	l.mu.RUnlock()

	if !m.UAUpdatedAt.IsZero() {
		p.UAData, _ = os.ReadFile(filepath.Join(dir, "ua.txt"))
		p.UAUpdatedAt = m.UAUpdatedAt
	}
	if !m.PathUpdatedAt.IsZero() {
		p.PathData, _ = os.ReadFile(filepath.Join(dir, "paths.txt"))
		p.PathUpdatedAt = m.PathUpdatedAt
	}
	if !m.IPUpdatedAt.IsZero() {
		p.IPData, _ = os.ReadFile(filepath.Join(dir, "ips.txt"))
		p.IPUpdatedAt = m.IPUpdatedAt
	}
	return p
}
