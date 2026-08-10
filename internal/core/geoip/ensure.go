// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package geoip assure la disponibilité de la base MaxMind GeoLite2 sur le Core.
package geoip

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/oschwald/maxminddb-golang"
	"github.com/vincamok/goproxify/internal/ssrf"
)

const (
	// DefaultDBPath est le chemin recommandé (volume /etc/goproxify).
	DefaultDBPath = "/etc/goproxify/geoip/GeoLite2-Country.mmdb"
	// DefaultDBURL miroir public GeoLite2-Country (P3TERX) — sans compte MaxMind.
	DefaultDBURL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb"

	minDBBytes  = 1024
	httpTimeout = 90 * time.Second
)

// openMMDB valide qu'un fichier est une base MaxMind lisible (injectable en test).
var openMMDB = func(path string) error {
	db, err := maxminddb.Open(path)
	if err != nil {
		return err
	}
	return db.Close()
}

// Bootstrap télécharge la base si absente, selon la config Core (geoip.*).
// Non bloquant côté appelant : les erreurs sont retournées pour log WARN.
func Bootstrap(autoDownload bool, dbPath, dbURL string, log *slog.Logger) error {
	if !autoDownload {
		if log != nil {
			log.Debug("geoip: téléchargement auto désactivé")
		}
		return nil
	}
	if dbPath == "" {
		dbPath = DefaultDBPath
	}
	if dbURL == "" {
		dbURL = DefaultDBURL
	}
	return Ensure(dbPath, dbURL, log)
}

// Ensure télécharge url vers path si le fichier n'existe pas déjà.
func Ensure(path, url string, log *slog.Logger) error {
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("geoip: stat %s: %w", path, err)
	}

	if url == "" {
		return fmt.Errorf("geoip: base absente et URL vide (%s)", path)
	}
	if log != nil {
		log.Info("geoip: base absente, téléchargement", "path", path, "url", url)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("geoip: mkdir: %w", err)
	}

	tmp := path + ".tmp"
	defer os.Remove(tmp) //nolint:errcheck

	if err := download(tmp, url); err != nil {
		return err
	}
	if err := openMMDB(tmp); err != nil {
		return fmt.Errorf("geoip: fichier téléchargé invalide: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("geoip: rename: %w", err)
	}
	if log != nil {
		log.Info("geoip: base prête", "path", path)
	}
	return nil
}

func download(dest, rawURL string) error {
	// GeoIP : sources publiques attendues ; bloquer loopback/metadata (privé OK via opt-in).
	if err := ssrf.ValidateHTTPURL(rawURL, ssrf.AllowPrivateEnv("GPX_GEOIP_ALLOW_PRIVATE")); err != nil {
		return fmt.Errorf("geoip: URL refusée: %w", err)
	}
	client := &http.Client{Timeout: httpTimeout}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return fmt.Errorf("geoip: requête: %w", err)
	}
	req.Header.Set("User-Agent", "goproxify-core/geoip")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("geoip: téléchargement: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("geoip: téléchargement HTTP %d", resp.StatusCode)
	}

	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("geoip: écriture: %w", err)
	}
	defer f.Close()

	n, err := io.Copy(f, resp.Body)
	if err != nil {
		return fmt.Errorf("geoip: copie: %w", err)
	}
	if n < minDBBytes {
		return fmt.Errorf("geoip: fichier trop petit (%d octets)", n)
	}
	return nil
}
