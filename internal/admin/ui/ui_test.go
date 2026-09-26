// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ui

import (
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestGeoJSONServedGzipped(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/lib/world/regions.geojson", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	w := httptest.NewRecorder()
	Handler().ServeHTTP(w, req)
	if w.Header().Get("Content-Encoding") != "gzip" {
		t.Fatalf("réponse non compressée : %v", w.Header())
	}
	zr, err := gzip.NewReader(w.Body)
	if err != nil {
		t.Fatal(err)
	}
	var fc struct {
		Features []json.RawMessage `json:"features"`
	}
	if err := json.NewDecoder(zr).Decode(&fc); err != nil || len(fc.Features) < 3000 {
		t.Fatalf("GeoJSON invalide ou incomplet : %v (%d entités)", err, len(fc.Features))
	}

	plain := httptest.NewRecorder()
	Handler().ServeHTTP(plain, httptest.NewRequest(http.MethodGet, "/lib/world/countries.geojson", nil))
	if plain.Header().Get("Content-Encoding") != "" || plain.Code != http.StatusOK {
		t.Fatalf("sans Accept-Encoding, la réponse doit rester brute : %d %v", plain.Code, plain.Header())
	}
}
