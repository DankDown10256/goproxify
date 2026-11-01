// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang"
	"github.com/vincamok/goproxify/internal/edge/metrics"
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

// CountryLookup rend la fonction IP → code pays de la base MaxMind de dbPath (le même lecteur que le filtre GeoIP). Erreur
// tant que la base manque : l'appelant réessaie plus tard.
func CountryLookup(dbPath string) (func(net.IP) string, error) {
	if _, err := os.Stat(dbPath); err != nil {
		return nil, err
	}
	db, err := openGeoDB(dbPath)
	if err != nil {
		return nil, err
	}
	return func(ip net.IP) string {
		var record geoRecord
		_ = db.Lookup(ip, &record)
		return record.Country.ISOCode
	}, nil
}

// GeoIP retourne un middleware de filtrage géographique.
// dbPath vide = pas de filtre (route sans configuration géographique).
// Chemin recommandé (volume passerelle) : /etc/goproxify/geoip/GeoLite2-Country.mmdb
// (téléchargement auto au démarrage de la passerelle si absent — voir package geoip)
// mode "allow" : bloque si le pays n'est PAS dans countries → 403
// mode "deny"  : bloque si le pays EST dans countries → 403
//
// La base est ouverte à la première requête qui la trouve : un fichier téléchargé après la
// construction de la chaîne est pris en compte sans attendre une invalidation. Tant qu'elle manque,
// « allow » refuse (503, fail-closed : le pays est inconnu) et « deny » laisse passer (rien à
// refuser sans pays) en le signalant. Un mode inconnu avec des pays configurés refuse tout.
func GeoIP(dbPath string, mode string, countries []string) func(http.Handler) http.Handler {
	if dbPath == "" {
		return noopMiddleware
	}
	return geoIPFilter(mode, countries, func() (func(net.IP) string, error) {
		if _, err := os.Stat(dbPath); err != nil {
			return nil, err
		}
		db, err := openGeoDB(dbPath)
		if err != nil {
			return nil, err
		}
		return func(ip net.IP) string {
			var record geoRecord
			_ = db.Lookup(ip, &record)
			return record.Country.ISOCode
		}, nil
	})
}

func geoIPFilter(mode string, countries []string, open func() (func(net.IP) string, error)) func(http.Handler) http.Handler {
	mode = strings.ToLower(strings.TrimSpace(mode))
	set := make(map[string]struct{}, len(countries))
	for _, c := range countries {
		set[strings.ToUpper(strings.TrimSpace(c))] = struct{}{}
	}
	validMode := mode == "allow" || mode == "deny"
	if !validMode && len(set) > 0 {
		slog.Error("geoip: mode inconnu, accès refusé", "mode", mode)
	}
	return func(next http.Handler) http.Handler {
		if !validMode && len(set) == 0 {
			return next // aucune restriction demandée
		}
		var lastWarn atomic.Int64
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !validMode {
				metrics.Pipeline.BlockedTotal.WithLabelValues(metrics.HostOf(r), "geoip", "invalid_mode").Inc()
				http.Error(w, "403 Forbidden", http.StatusForbidden)
				return
			}
			lookup, err := open()
			if err != nil {
				if now := time.Now().Unix(); now-lastWarn.Load() > 60 {
					lastWarn.Store(now)
					slog.Warn("geoip: base indisponible", "mode", mode, "err", err)
				}
				if mode == "allow" {
					metrics.Pipeline.BlockedTotal.WithLabelValues(metrics.HostOf(r), "geoip", "db_unavailable").Inc()
					http.Error(w, "503 Service Unavailable", http.StatusServiceUnavailable)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			country := ""
			if ip := net.ParseIP(clientIP(r)); ip != nil {
				country = strings.ToUpper(lookup(ip))
			}
			_, inList := set[country]
			if (mode == "allow" && !inList) || (mode == "deny" && inList) {
				metrics.Pipeline.BlockedTotal.WithLabelValues(metrics.HostOf(r), "geoip", country).Inc()
				http.Error(w, "403 Forbidden", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func noopMiddleware(next http.Handler) http.Handler { return next }
