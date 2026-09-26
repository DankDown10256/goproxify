// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestPortalRecordingsRelay(t *testing.T) {
	var gotAuth, gotMethod, gotPath []string
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		gotMethod = append(gotMethod, r.Method)
		gotPath = append(gotPath, r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/internal/v1/portal/recordings":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"recordings":[{"id":"r1","actor":"alice"}]}`))
		case r.Method == http.MethodGet:
			w.Header().Set("Content-Type", "application/x-asciicast")
			_, _ = w.Write([]byte("{\"version\":2}\n"))
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer edge.Close()

	db, err := admindb.Open(filepath.Join(t.TempDir(), "rec.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO tokens (id, node_name, node_endpoint, token, role, revoked)
		VALUES ('t1','edge-a',?, 'tok-plain','edge',0)`, edge.URL); err != nil {
		t.Fatal(err)
	}
	h := &PortalHandler{DB: db}
	do := func(method, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, nil))
		return w
	}

	if w := do(http.MethodGet, "/api/v1/portal/recordings?edge=edge-a"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "alice") {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodGet, "/api/v1/portal/recordings/r1?edge=edge-a"); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"version":2`) ||
		w.Header().Get("Content-Type") != "application/x-asciicast" {
		t.Fatalf("get: %d %s", w.Code, w.Body.String())
	}
	if w := do(http.MethodDelete, "/api/v1/portal/recordings/r1?edge=edge-a"); w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", w.Code)
	}
	if len(gotAuth) != 3 || gotAuth[0] != "Bearer tok-plain" || gotMethod[2] != http.MethodDelete || gotPath[1] != "/internal/v1/portal/recordings/r1" {
		t.Fatalf("relais: %v %v %v", gotAuth, gotMethod, gotPath)
	}
	if w := do(http.MethodGet, "/api/v1/portal/recordings?edge=inconnue"); w.Code != http.StatusBadGateway {
		t.Fatalf("passerelle inconnue: %d", w.Code)
	}
	if w := do(http.MethodGet, "/api/v1/portal/recordings"); w.Code != http.StatusBadRequest {
		t.Fatalf("edge manquant: %d", w.Code)
	}
	if w := do(http.MethodPost, "/api/v1/portal/recordings?edge=edge-a"); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("méthode: %d", w.Code)
	}
	if w := do(http.MethodGet, "/api/v1/portal/recordings/a/b?edge=edge-a"); w.Code != http.StatusNotFound {
		t.Fatalf("chemin imbriqué: %d", w.Code)
	}
}

func TestPortalWatchSessionRelaysStream(t *testing.T) {
	edge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/v1/portal/sessions/abc/watch" || r.Header.Get("Authorization") != "Bearer tok-plain" {
			http.Error(w, "non", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: aGVsbG8=\n\nevent: end\ndata: \n\n"))
	}))
	defer edge.Close()

	db, err := admindb.Open(filepath.Join(t.TempDir(), "watch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _ = db.Exec(`INSERT INTO tokens (id, node_name, node_endpoint, token, role, revoked)
		VALUES ('t1','edge-a',?, 'tok-plain','edge',0)`, edge.URL)
	h := &PortalHandler{DB: db}

	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/portal/sessions/abc/watch?edge=edge-a", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "aGVsbG8=") || w.Header().Get("Content-Type") != "text/event-stream" {
		t.Fatalf("watch: %d %q", w.Code, w.Body.String())
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='watch'`).Scan(&n)
	if n != 1 {
		t.Fatalf("l'observation doit être journalisée: %d", n)
	}

	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/portal/sessions/inconnue/watch?edge=edge-a", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("session inconnue: %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/portal/sessions/a/b/watch?edge=edge-a", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("chemin imbriqué: %d", w.Code)
	}
}
