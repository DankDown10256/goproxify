// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package ui expose l'interface web d'Administration via go:embed.
package ui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed src
var srcFS embed.FS

// Handler retourne un http.Handler servant les fichiers statiques de l'UI.
// Toutes les routes inconnues renvoient index.html (SPA hash-routing).
func Handler() http.Handler {
	sub, err := fs.Sub(srcFS, "src")
	if err != nil {
		panic("ui: impossible de monter src/: " + err.Error())
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Vérifie si le fichier existe dans l'FS embarqué
		if _, err := fs.Stat(sub, r.URL.Path[1:]); err != nil {
			// SPA fallback → index.html
			r.URL.Path = "/"
		}
		w.Header().Set("Cache-Control", "no-cache")
		fileServer.ServeHTTP(w, r)
	})
}
