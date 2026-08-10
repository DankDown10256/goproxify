// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

type geoRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
}

// Cache process-wide des readers MaxMind (évite Open à chaque requête via dispatch — revue P0 #2).
var geoReaders sync.Map // path -> *maxminddb.Reader

func openGeoDB(path string) (*maxminddb.Reader, error) {
	if v, ok := geoReaders.Load(path); ok {
		return v.(*maxminddb.Reader), nil
	}
	db, err := maxminddb.Open(path)
	if err != nil {
		return nil, err
	}
	actual, loaded := geoReaders.LoadOrStore(path, db)
	if loaded {
		_ = db.Close()
		return actual.(*maxminddb.Reader), nil
	}
	return db, nil
}

// GeoIP retourne un middleware de filtrage géographique.
// Si dbPath est vide ou le fichier absent, le middleware est un no-op.
// Chemin recommandé (volume Core) : /etc/goproxify/geoip/GeoLite2-Country.mmdb
// (téléchargement auto au démarrage du Core si absent — voir package geoip)
// mode "allow" : bloque si le pays n'est PAS dans countries → 403
// mode "deny"  : bloque si le pays EST dans countries → 403
func GeoIP(dbPath string, mode string, countries []string) func(http.Handler) http.Handler {
	if dbPath == "" {
		return noopMiddleware
	}
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		slog.Warn("geoip: fichier .mmdb absent, middleware désactivé", "path", dbPath)
		return noopMiddleware
	}

	db, err := openGeoDB(dbPath)
	if err != nil {
		slog.Warn("geoip: impossible d'ouvrir la base", "path", dbPath, "err", err)
		return noopMiddleware
	}

	set := make(map[string]struct{}, len(countries))
	for _, c := range countries {
		set[c] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := net.ParseIP(clientIP(r))

			var record geoRecord
			if ip != nil {
				_ = db.Lookup(ip, &record)
			}
			country := record.Country.ISOCode

			_, inList := set[country]
			blocked := false
			switch mode {
			case "allow":
				blocked = !inList
			case "deny":
				blocked = inList
			}

			if blocked {
				http.Error(w, "403 Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func noopMiddleware(next http.Handler) http.Handler { return next }
