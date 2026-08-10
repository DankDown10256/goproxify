// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package tz centralise la prise en compte du fuseau horaire (env TZ).
//
// Les images Docker doivent embarquer les données de zones :
//   - binaire Go : import blank de time/tzdata (cmd/goproxify)
//   - Alpine     : paquet apk tzdata (utile pour libc / SQLite localtime)
package tz

import (
	"log/slog"
	"os"
	"time"
)

// Name retourne le nom IANA du fuseau actif (ex. Europe/Paris), ou "UTC".
func Name() string {
	n := time.Local.String()
	if n != "" && n != "Local" {
		return n
	}
	if v := os.Getenv("TZ"); v != "" {
		return v
	}
	return "UTC"
}

// NowRFC3339 retourne l'heure courante formatée dans le fuseau local.
func NowRFC3339() string {
	return time.Now().Format(time.RFC3339)
}

// LogStartup journalise le fuseau effectif (vérifie que TZ / zoneinfo sont OK).
func LogStartup(log *slog.Logger) {
	if log == nil {
		log = slog.Default()
	}
	now := time.Now()
	abbr, offset := now.Zone()
	log.Info("fuseau horaire",
		"tz", Name(),
		"abbr", abbr,
		"offset_min", offset/60,
		"now", now.Format(time.RFC3339),
		"env_TZ", os.Getenv("TZ"),
	)
}
