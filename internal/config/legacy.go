// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/viper"
)

// Compatibilité avec les déploiements créés avant le renommage Core → Edge :
// clés de config, variables d'environnement et fichiers du volume de données.

var (
	legacyCoreKey = regexp.MustCompile(`(^|[._])core(s?)($|[._])`)
	legacyCoreEnv = regexp.MustCompile(`(^|_)CORE(S?)($|_)`)
)

// legacyEdgeKey renvoie la clé de config actuelle pour une clé « core_* » (identique si rien à changer).
func legacyEdgeKey(key string) string {
	return legacyCoreKey.ReplaceAllString(key, "${1}edge${2}${3}")
}

// migrateLegacyKeys recopie les clés « core_* » d'un ancien fichier JSON vers leur nom « edge_* »
// lorsque la nouvelle clé est absente.
func migrateLegacyKeys(v *viper.Viper) {
	for _, k := range v.AllKeys() {
		if nk := legacyEdgeKey(k); nk != k && !v.IsSet(nk) {
			v.Set(nk, v.Get(k))
		}
	}
}

// AliasLegacyEnv reporte les variables d'environnement « …CORE… » sur leur nom « …EDGE… »
// quand la nouvelle variable n'est pas définie.
func AliasLegacyEnv() {
	warned := false
	for _, kv := range os.Environ() {
		name, val, ok := strings.Cut(kv, "=")
		if !ok || !legacyCoreEnv.MatchString(name) {
			continue
		}
		nn := legacyCoreEnv.ReplaceAllString(name, "${1}EDGE${2}${3}")
		if os.Getenv(nn) != "" {
			continue
		}
		os.Setenv(nn, val)
		if !warned {
			slog.Warn("variable d'environnement « CORE » obsolète : utilisez le nom « EDGE » (ex. " + name + " → " + nn + ")")
			warned = true
		}
	}
}

// legacyEdgeFiles associe les anciens fichiers du volume de données de la passerelle à leur nom actuel.
var legacyEdgeFiles = map[string]string{
	"core.json":      "edge.json",
	"core-cache.gpx": "edge-cache.gpx",
	"core-tokens.db": "edge-tokens.db",
}

// MigrateLegacyEdgeFiles renomme, dans dir, les fichiers « core-* » en « edge-* » (sans écraser un fichier existant).
func MigrateLegacyEdgeFiles(dir string) {
	for oldName, newName := range legacyEdgeFiles {
		oldPath, newPath := filepath.Join(dir, oldName), filepath.Join(dir, newName)
		if _, err := os.Stat(oldPath); err != nil {
			continue
		}
		if _, err := os.Stat(newPath); err == nil {
			continue
		}
		if err := os.Rename(oldPath, newPath); err != nil {
			slog.Warn("migration fichier Core → Edge impossible", "from", oldPath, "to", newPath, "err", err)
			continue
		}
		slog.Info("fichier renommé (Core → Edge)", "from", oldPath, "to", newPath)
	}
}
