// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/core/portal"
)

func TestPortalPageTemplatesCRUD(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "ptpl.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := &PortalPageTemplatesHandler{DB: db, Log: slog.Default()}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/portal-page-templates", nil))
	if rr.Code != 200 {
		t.Fatalf("list %d %s", rr.Code, rr.Body.String())
	}
	var listed struct {
		Templates []PortalPageTemplateDTO `json:"templates"`
		Keys      []string                `json:"keys"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.Keys) != len(portal.PageTemplateKeys) {
		t.Fatalf("keys %d", len(listed.Keys))
	}

	body := `{"name":"Login custom","body":"<h1>Hi {{brand}}</h1>"}`
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/api/v1/portal-page-templates/login", strings.NewReader(body))
	h.ServeHTTP(rr, req)
	if rr.Code != 200 {
		t.Fatalf("put %d %s", rr.Code, rr.Body.String())
	}

	push := LoadPortalPageTemplatesForPush(db)
	if len(push) != 1 || push[0].Key != portal.PageLogin {
		t.Fatalf("%+v", push)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/api/v1/portal-page-templates/login", nil))
	if rr.Code != 204 {
		t.Fatalf("delete %d", rr.Code)
	}
	if len(LoadPortalPageTemplatesForPush(db)) != 0 {
		t.Fatal("push empty")
	}
}
