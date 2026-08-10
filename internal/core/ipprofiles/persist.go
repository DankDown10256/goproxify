// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package ipprofiles persiste le snapshot runtime des profils IP sur le volume Core.
package ipprofiles

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vincamok/goproxify/internal/core/router"
)

const (
	defaultDir  = "/etc/goproxify/ip-profiles"
	fileName    = "profiles.json"
	envPathKey  = "GPX_IP_PROFILES_PATH"
)

// Dir retourne le répertoire de persistance (env GPX_IP_PROFILES_PATH ou défaut).
func Dir() string {
	if p := os.Getenv(envPathKey); p != "" {
		return p
	}
	return defaultDir
}

func filePath(dir string) string {
	return filepath.Join(dir, fileName)
}

// Save écrit atomiquement la liste de profils (temp + rename).
func Save(dir string, profiles []*router.IPProfile) error {
	if dir == "" {
		dir = Dir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("ipprofiles: mkdir: %w", err)
	}
	if profiles == nil {
		profiles = []*router.IPProfile{}
	}
	// Ne sérialiser que les champs JSON publics (pas nets).
	out := make([]*router.IPProfile, 0, len(profiles))
	for _, p := range profiles {
		if p == nil {
			continue
		}
		out = append(out, &router.IPProfile{
			ID:    p.ID,
			Name:  p.Name,
			Mode:  p.Mode,
			CIDRs: append([]string(nil), p.CIDRs...),
		})
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("ipprofiles: marshal: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "profiles-*.tmp")
	if err != nil {
		return fmt.Errorf("ipprofiles: temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("ipprofiles: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("ipprofiles: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("ipprofiles: close: %w", err)
	}
	dest := filePath(dir)
	if err := os.Rename(tmpName, dest); err != nil {
		return fmt.Errorf("ipprofiles: rename: %w", err)
	}
	return nil
}

// Load lit profiles.json. Retourne (nil, nil) si le fichier est absent.
func Load(dir string) ([]*router.IPProfile, error) {
	if dir == "" {
		dir = Dir()
	}
	data, err := os.ReadFile(filePath(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("ipprofiles: read: %w", err)
	}
	var profiles []*router.IPProfile
	if err := json.Unmarshal(data, &profiles); err != nil {
		return nil, fmt.Errorf("ipprofiles: unmarshal: %w", err)
	}
	if profiles == nil {
		profiles = []*router.IPProfile{}
	}
	return profiles, nil
}
