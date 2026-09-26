// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package archstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	versionsDirName = "architecture.versions"
	maxVersions     = 50
	versionPrefix   = "architecture-"
	versionSuffix   = ".json"
)

// versionNameRe borne les noms acceptés à la restauration (pas de séparateur de chemin).
var versionNameRe = regexp.MustCompile(`^architecture-[0-9]{8}T[0-9]{15}Z\.json$`)

// VersionInfo décrit une version conservée du fichier d'architecture.
type VersionInfo struct {
	Name    string    `json:"name"`
	SavedAt time.Time `json:"saved_at"`
	Size    int64     `json:"size"`
}

func (s *Store) versionsDir() string {
	return filepath.Join(filepath.Dir(s.path), versionsDirName)
}

// snapshotLocked conserve le fichier courant avant qu'il soit remplacé par next.
// Sans effet si le fichier n'existe pas encore ou si son contenu est identique.
func (s *Store) snapshotLocked(next []byte) error {
	cur, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("archstore: snapshot read: %w", err)
	}
	if bytes.Equal(cur, next) {
		return nil
	}
	dir := s.versionsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("archstore: snapshot mkdir: %w", err)
	}
	t := time.Now().UTC()
	name := versionPrefix + t.Format("20060102T150405") + fmt.Sprintf("%09d", t.Nanosecond()) + "Z" + versionSuffix
	if err := os.WriteFile(filepath.Join(dir, name), cur, 0o600); err != nil {
		return fmt.Errorf("archstore: snapshot write: %w", err)
	}
	s.pruneVersionsLocked()
	return nil
}

func (s *Store) pruneVersionsLocked() {
	infos, err := s.listVersions()
	if err != nil || len(infos) <= maxVersions {
		return
	}
	for _, v := range infos[maxVersions:] {
		_ = os.Remove(filepath.Join(s.versionsDir(), v.Name))
	}
}

// listVersions retourne les versions, la plus récente d'abord.
func (s *Store) listVersions() ([]VersionInfo, error) {
	entries, err := os.ReadDir(s.versionsDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []VersionInfo
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasPrefix(name, versionPrefix) || !strings.HasSuffix(name, versionSuffix) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, VersionInfo{Name: name, SavedAt: info.ModTime().UTC(), Size: info.Size()})
	}
	// Les noms embarquent l'horodatage UTC : l'ordre lexicographique est l'ordre chronologique.
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// Versions retourne les versions conservées, la plus récente d'abord.
func (s *Store) Versions() ([]VersionInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listVersions()
}

// Restore remet en place une version conservée. Le fichier courant est lui-même
// conservé avant d'être remplacé : une restauration est réversible.
func (s *Store) Restore(name string) error {
	if !versionNameRe.MatchString(name) {
		return fmt.Errorf("archstore: nom de version invalide %q", name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(filepath.Join(s.versionsDir(), name))
	if err != nil {
		return fmt.Errorf("archstore: version %q introuvable: %w", name, err)
	}
	var arch Architecture
	if err := json.Unmarshal(data, &arch); err != nil {
		return fmt.Errorf("archstore: version %q illisible: %w", name, err)
	}
	if arch.Nodes == nil {
		arch.Nodes = []NodeEntry{}
	}
	return s.writeLocked(&arch)
}
