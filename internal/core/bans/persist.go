// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package bans persiste le snapshot runtime des bans IP sur le volume Core.
package bans

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
)

const (
	defaultDir = "/etc/goproxify/bans"
	fileName   = "bans.json"
	envPathKey = "GPX_BANS_PATH"
)

// Dir retourne le répertoire de persistance (env GPX_BANS_PATH ou défaut).
func Dir() string {
	if p := os.Getenv(envPathKey); p != "" {
		return p
	}
	return defaultDir
}

func filePath(dir string) string {
	return filepath.Join(dir, fileName)
}

type banDTO struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	Reason    string `json:"reason,omitempty"`
	Source    string `json:"source,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// Save écrit atomiquement la liste de bans (temp + rename).
func Save(dir string, bans []*router.RuntimeBan) error {
	if dir == "" {
		dir = Dir()
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("bans: mkdir: %w", err)
	}
	out := make([]banDTO, 0, len(bans))
	for _, b := range bans {
		if b == nil || b.IP == "" {
			continue
		}
		dto := banDTO{ID: b.ID, IP: b.IP, Reason: b.Reason, Source: b.Source}
		if b.ExpiresAt != nil && !b.ExpiresAt.IsZero() {
			dto.ExpiresAt = b.ExpiresAt.UTC().Format(time.RFC3339)
		}
		out = append(out, dto)
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("bans: marshal: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "bans-*.tmp")
	if err != nil {
		return fmt.Errorf("bans: temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("bans: write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("bans: sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("bans: close: %w", err)
	}
	if err := os.Rename(tmpName, filePath(dir)); err != nil {
		return fmt.Errorf("bans: rename: %w", err)
	}
	return nil
}

// Load lit bans.json. Retourne (nil, nil) si le fichier est absent.
func Load(dir string) ([]*router.RuntimeBan, error) {
	if dir == "" {
		dir = Dir()
	}
	data, err := os.ReadFile(filePath(dir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("bans: read: %w", err)
	}
	var dtos []banDTO
	if err := json.Unmarshal(data, &dtos); err != nil {
		return nil, fmt.Errorf("bans: unmarshal: %w", err)
	}
	out := make([]*router.RuntimeBan, 0, len(dtos))
	for _, d := range dtos {
		b := &router.RuntimeBan{ID: d.ID, IP: d.IP, Reason: d.Reason, Source: d.Source}
		if d.ExpiresAt != "" {
			if t, err := time.Parse(time.RFC3339, d.ExpiresAt); err == nil {
				b.ExpiresAt = &t
			}
		}
		out = append(out, b)
	}
	return out, nil
}
