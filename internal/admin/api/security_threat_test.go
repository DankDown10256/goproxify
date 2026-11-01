// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"encoding/json"
	"path/filepath"
	"time"

	"database/sql"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/edge/logapi/logapitest"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

func TestThreatConfigIsStoredAndPushedPerEdge(t *testing.T) {
	db, err := sql.Open("sqlite", "file:threat_cfg_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatal(err)
	}

	var pushedTo []string
	h := &api.SecurityHandler{
		DB:                   db,
		OnThreatConfigChange: func(edgeRef string, _ any) { pushedTo = append(pushedTo, edgeRef) },
	}

	put := func(query string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/api/v1/security/threat-config"+query, strings.NewReader(`{"enabled":true}`))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("PUT%s: %d %s", query, rec.Code, rec.Body.String())
		}
	}
	get := func(query string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/security/threat-config"+query, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return strings.TrimSpace(rec.Body.String())
	}

	put("?edge=edge-b")

	if got := get("?edge=edge-b"); got != `{"enabled":true}` {
		t.Fatalf("config de la passerelle: %q", got)
	}
	if got := get(""); got != `{"enabled":false}` {
		t.Fatalf("la config globale ne doit pas être touchée par une écriture par passerelle: %q", got)
	}
	if len(pushedTo) != 1 || pushedTo[0] != "edge-b" {
		t.Fatalf("push visé sur edge-b uniquement, reçu %v", pushedTo)
	}

	put("")
	if len(pushedTo) != 2 || pushedTo[1] != "" {
		t.Fatalf("écriture globale : push à tous (edgeRef vide), reçu %v", pushedTo)
	}
}

func TestSimulateThreatEndpoint(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "sim.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	gw := logapitest.New(t, "gw-a")
	if err := gw.Register(db); err != nil {
		t.Fatal(err)
	}
	gw.Add(logstore.Entry{Ts: time.Now().UTC().Add(-5 * time.Minute), Component: "edge", Domain: "a.test", Method: "GET", Path: "/wp-admin/x", Status: 200, IP: "9.9.9.9"})
	h := &api.SecurityHandler{DB: db, Edge: &prismedge.Source{DB: db}}

	body := `{"config":{"enabled":true,"custom_lists":{"paths":["/wp-admin"]}},"hours":1}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/security/threat-config/simulate", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST simulate: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Replayed int            `json:"events_replayed"`
		Delta    map[string]int `json:"delta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Replayed != 1 || out.Delta["legit_blocked"] != 1 {
		t.Fatalf("résultat inattendu : %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/security/threat-config/simulate", strings.NewReader(`{}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("config absente : %d", rec.Code)
	}
}

func TestSimulateThreatWindowWidensForTheSeasonalReference(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "sim.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	gw := logapitest.New(t, "gw-a")
	if err := gw.Register(db); err != nil {
		t.Fatal(err)
	}
	gw.Add(logstore.Entry{Ts: time.Now().UTC().Add(-5 * time.Minute), Component: "edge", Domain: "a.test", Method: "GET", Path: "/", Status: 200, IP: "9.9.9.9"})
	h := &api.SecurityHandler{DB: db, Edge: &prismedge.Source{DB: db}}

	sim := func(body string) map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/security/threat-config/simulate", strings.NewReader(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("POST simulate: %d %s", rec.Code, rec.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	if out := sim(`{"config":{"enabled":true},"hours":100}`); out["window_hours"] != float64(api.SimMaxHours) {
		t.Fatalf("sans référence saisonnière la fenêtre reste bornée à %d h : %v", api.SimMaxHours, out["window_hours"])
	}
	out := sim(`{"config":{"enabled":true,"seasonal":{"mode":"detect"}},"hours":100}`)
	if out["window_hours"] != float64(100) {
		t.Fatalf("avec la référence saisonnière la fenêtre s'élargit : %v", out["window_hours"])
	}
	cand := out["candidate"].(map[string]any)
	seas, ok := cand["seasonal"].(map[string]any)
	if !ok || seas["mode"] != "detect" || len(seas["routes"].([]any)) != 1 {
		t.Fatalf("le rapport doit porter la part saisonnière, une route jugée froide : %v", cand)
	}
	if seas["routes"].([]any)[0].(map[string]any)["warm"] != false {
		t.Fatalf("une heure de trafic ne suffit pas à juger une route : %v", seas)
	}
	if _, has := out["current"].(map[string]any)["seasonal"]; has {
		t.Fatal("la config actuelle n'a pas de référence saisonnière : rien à rapporter")
	}
}
