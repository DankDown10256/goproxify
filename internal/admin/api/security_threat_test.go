// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/vincamok/goproxify/internal/admin/api"
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
