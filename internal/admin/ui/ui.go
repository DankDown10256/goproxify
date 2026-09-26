// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package ui expose l'interface web d'Administration via go:embed.
package ui

import (
	"bytes"
	"compress/gzip"
	"embed"
	"io/fs"
	"net/http"
	"strings"
	"sync"
)

//go:embed src
var srcFS embed.FS

// gzGeoJSON sert les contours (plusieurs Mo) compressés : compressés une seule fois, gardés en mémoire.
var gzGeoJSON sync.Map // chemin → []byte

func serveGzipGeoJSON(w http.ResponseWriter, r *http.Request, sub fs.FS) bool {
	if !strings.HasSuffix(r.URL.Path, ".geojson") || !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		return false
	}
	body, ok := gzGeoJSON.Load(r.URL.Path)
	if !ok {
		raw, err := fs.ReadFile(sub, r.URL.Path[1:])
		if err != nil {
			return false
		}
		var buf bytes.Buffer
		zw, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		_, _ = zw.Write(raw)
		_ = zw.Close()
		body, _ = gzGeoJSON.LoadOrStore(r.URL.Path, buf.Bytes())
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Vary", "Accept-Encoding")
	_, _ = w.Write(body.([]byte))
	return true
}

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
		if strings.HasPrefix(r.URL.Path, "/lib/") {
			// Bibliothèques embarquées (Leaflet, contours des pays) : versionnées avec le binaire.
			w.Header().Set("Cache-Control", "public, max-age=86400")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		if serveGzipGeoJSON(w, r, sub) {
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}
