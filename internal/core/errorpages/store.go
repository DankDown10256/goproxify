// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package errorpages

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

const (
	defaultDir     = "/etc/goproxify/error-pages"
	envDirKey      = "GPX_ERROR_PAGES_DIR"
	indexFileName  = "index.html"
	PublicPathPref = "/_goproxify/error-pages/"
)

var uuidFileRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// Asset est un fichier associé à un template (image, CSS, etc.).
type Asset struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Content     []byte `json:"content"`
}

// Template est un snapshot poussé par Admin (HTML + assets).
type Template struct {
	ID          string  `json:"id"`
	Name        string  `json:"name,omitempty"`
	Description string  `json:"description,omitempty"`
	Body        string  `json:"body"`
	ScopeType   string  `json:"scope_type,omitempty"`
	ScopeID     string  `json:"scope_id,omitempty"`
	Assets      []Asset `json:"assets,omitempty"`
}

// Store tient en mémoire le contenu des templates et le miroir sur disque.
type Store struct {
	mu   sync.RWMutex
	dir  string
	html map[string]string            // id → body
	meta map[string]map[string][]byte // id → filename → content
	ctype map[string]map[string]string // id → filename → content-type
}

var defaultStore = NewStore("")

// DefaultStore retourne le store global du Core.
func DefaultStore() *Store { return defaultStore }

// NewStore crée un store (dir vide = défaut / env).
func NewStore(dir string) *Store {
	if dir == "" {
		dir = Dir()
	}
	return &Store{
		dir:   dir,
		html:  make(map[string]string),
		meta:  make(map[string]map[string][]byte),
		ctype: make(map[string]map[string]string),
	}
}

// Dir retourne le répertoire de persistance.
func Dir() string {
	if p := os.Getenv(envDirKey); p != "" {
		return p
	}
	return defaultDir
}

// ValidTemplateID accepte uniquement des UUID.
func ValidTemplateID(id string) bool {
	return uuidFileRe.MatchString(id)
}

// SanitizeFilename refuse path traversal et caractères dangereux.
func SanitizeFilename(name string) (string, bool) {
	name = filepath.Base(strings.TrimSpace(name))
	if name == "" || name == "." || name == ".." || name == indexFileName {
		return "", false
	}
	if strings.ContainsAny(name, `/\`) {
		return "", false
	}
	for _, r := range name {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_'
		if !ok {
			return "", false
		}
	}
	return name, true
}

// GetHTML retourne le corps HTML d'un template (mémoire, puis disque si besoin).
func (s *Store) GetHTML(id string) (string, bool) {
	if !ValidTemplateID(id) {
		return "", false
	}
	s.mu.RLock()
	body, ok := s.html[id]
	s.mu.RUnlock()
	if ok && body != "" {
		return body, true
	}
	// Fallback disque : utile si la route arrive avant le push mémoire, ou après redémarrage partiel.
	b, err := os.ReadFile(filepath.Join(s.dir, id, indexFileName))
	if err != nil || len(b) == 0 {
		return "", false
	}
	body = string(b)
	s.mu.Lock()
	if s.html == nil {
		s.html = make(map[string]string)
	}
	s.html[id] = body
	s.mu.Unlock()
	return body, true
}

// GetAsset retourne un asset (mémoire, puis disque si besoin).
func (s *Store) GetAsset(id, filename string) (content []byte, contentType string, ok bool) {
	if !ValidTemplateID(id) {
		return nil, "", false
	}
	fn, ok := SanitizeFilename(filename)
	if !ok {
		return nil, "", false
	}
	s.mu.RLock()
	files := s.meta[id]
	if files != nil {
		if b, found := files[fn]; found {
			ct := "application/octet-stream"
			if s.ctype[id] != nil && s.ctype[id][fn] != "" {
				ct = s.ctype[id][fn]
			}
			out := make([]byte, len(b))
			copy(out, b)
			s.mu.RUnlock()
			return out, ct, true
		}
	}
	s.mu.RUnlock()

	path := filepath.Join(s.dir, id, fn)
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, "", false
	}
	ct := guessContentType(fn)
	s.mu.Lock()
	if s.meta[id] == nil {
		s.meta[id] = make(map[string][]byte)
	}
	if s.ctype[id] == nil {
		s.ctype[id] = make(map[string]string)
	}
	s.meta[id][fn] = append([]byte(nil), b...)
	s.ctype[id][fn] = ct
	s.mu.Unlock()
	out := make([]byte, len(b))
	copy(out, b)
	return out, ct, true
}

// ReplaceAll remplace atomiquement tous les templates (mémoire + disque) et purge les orphelins.
func (s *Store) ReplaceAll(templates []Template) error {
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return fmt.Errorf("errorpages: mkdir: %w", err)
	}

	keep := make(map[string]struct{}, len(templates))
	newHTML := make(map[string]string, len(templates))
	newMeta := make(map[string]map[string][]byte, len(templates))
	newCType := make(map[string]map[string]string, len(templates))

	for _, t := range templates {
		if !ValidTemplateID(t.ID) {
			continue
		}
		keep[t.ID] = struct{}{}
		tplDir := filepath.Join(s.dir, t.ID)
		if err := os.MkdirAll(tplDir, 0o755); err != nil {
			return fmt.Errorf("errorpages: mkdir %s: %w", t.ID, err)
		}
		if err := writeAtomic(filepath.Join(tplDir, indexFileName), []byte(t.Body)); err != nil {
			return err
		}
		newHTML[t.ID] = t.Body
		files := make(map[string][]byte)
		ctypes := make(map[string]string)
		wantFiles := map[string]struct{}{indexFileName: {}}
		for _, a := range t.Assets {
			fn, ok := SanitizeFilename(a.Filename)
			if !ok {
				continue
			}
			wantFiles[fn] = struct{}{}
			ct := a.ContentType
			if ct == "" {
				ct = "application/octet-stream"
			}
			if err := writeAtomic(filepath.Join(tplDir, fn), a.Content); err != nil {
				return err
			}
			files[fn] = append([]byte(nil), a.Content...)
			ctypes[fn] = ct
		}
		// Purge fichiers orphelins dans le dossier du template
		entries, _ := os.ReadDir(tplDir)
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if _, ok := wantFiles[e.Name()]; !ok {
				_ = os.Remove(filepath.Join(tplDir, e.Name()))
			}
		}
		newMeta[t.ID] = files
		newCType[t.ID] = ctypes
	}

	// Purge dossiers templates orphelins
	entries, err := os.ReadDir(s.dir)
	if err == nil {
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			if _, ok := keep[e.Name()]; !ok {
				_ = os.RemoveAll(filepath.Join(s.dir, e.Name()))
			}
		}
	}

	s.mu.Lock()
	s.html = newHTML
	s.meta = newMeta
	s.ctype = newCType
	s.mu.Unlock()
	return nil
}

// LoadFromDisk charge tous les templates présents sur le volume (boot / Admin HS).
func (s *Store) LoadFromDisk() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("errorpages: readdir: %w", err)
	}
	newHTML := make(map[string]string)
	newMeta := make(map[string]map[string][]byte)
	newCType := make(map[string]map[string]string)
	for _, e := range entries {
		if !e.IsDir() || !ValidTemplateID(e.Name()) {
			continue
		}
		id := e.Name()
		tplDir := filepath.Join(s.dir, id)
		body, err := os.ReadFile(filepath.Join(tplDir, indexFileName))
		if err != nil {
			continue
		}
		newHTML[id] = string(body)
		files := make(map[string][]byte)
		ctypes := make(map[string]string)
		subs, _ := os.ReadDir(tplDir)
		for _, f := range subs {
			if f.IsDir() || f.Name() == indexFileName {
				continue
			}
			fn, ok := SanitizeFilename(f.Name())
			if !ok {
				continue
			}
			b, err := os.ReadFile(filepath.Join(tplDir, fn))
			if err != nil {
				continue
			}
			files[fn] = b
			ctypes[fn] = guessContentType(fn)
		}
		newMeta[id] = files
		newCType[id] = ctypes
	}
	s.mu.Lock()
	s.html = newHTML
	s.meta = newMeta
	s.ctype = newCType
	s.mu.Unlock()
	return nil
}

func writeAtomic(dest string, data []byte) error {
	dir := filepath.Dir(dest)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("errorpages: temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("errorpages: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, dest); err != nil {
		return fmt.Errorf("errorpages: rename: %w", err)
	}
	return nil
}

func guessContentType(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".svg":
		return "image/svg+xml"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "application/javascript"
	case ".woff":
		return "font/woff"
	case ".woff2":
		return "font/woff2"
	case ".ico":
		return "image/x-icon"
	default:
		return "application/octet-stream"
	}
}

// AssetPublicURL construit l'URL publique d'un asset sur le Core.
func AssetPublicURL(templateID, filename string) string {
	return PublicPathPref + templateID + "/" + filename
}
