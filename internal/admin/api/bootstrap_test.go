// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/vincamok/goproxify/internal/admin/api"
)

func TestBootstrapTicketCreateAndPublic(t *testing.T) {
	db, err := sql.Open("sqlite", "file:bootstrap_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	h := &api.BootstrapHandler{
		DB: db,
		ResolvePublicURL: func(r *http.Request) string {
			return "https://admin.example"
		},
	}

	body := `{"host_name":"Host A","core_endpoint":"http://core:8000","payload":{"compose_text":"services:\n  x:\n","env_text":"A=1","note":"hi"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/bootstrap-tickets", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeCreate(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status %d: %s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	tok, _ := created["token"].(string)
	url, _ := created["url"].(string)
	qr, _ := created["qr_code"].(string)
	if tok == "" || !strings.HasPrefix(url, "https://admin.example/i/") || !strings.HasPrefix(qr, "data:image/png;base64,") {
		t.Fatalf("bad create response: %+v", created)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/i/"+tok, nil)
	rec2 := httptest.NewRecorder()
	h.ServePublic(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("html status %d", rec2.Code)
	}
	if ct := rec2.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("content-type %q", ct)
	}
	if !strings.Contains(rec2.Body.String(), "Host A") || !strings.Contains(rec2.Body.String(), "services:") {
		body := rec2.Body.String()
		if len(body) > 200 {
			body = body[:200]
		}
		t.Fatalf("html missing content: %s", body)
	}

	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap/"+tok+"?format=json", nil)
	rec3 := httptest.NewRecorder()
	h.ServePublic(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("json status %d", rec3.Code)
	}
	var pub map[string]any
	if err := json.Unmarshal(rec3.Body.Bytes(), &pub); err != nil {
		t.Fatal(err)
	}
	if pub["core_endpoint"] != "http://core:8000" {
		t.Fatalf("core_endpoint %+v", pub)
	}

	req4 := httptest.NewRequest(http.MethodGet, "/i/"+tok+".sh", nil)
	rec4 := httptest.NewRecorder()
	h.ServePublic(rec4, req4)
	if rec4.Code != http.StatusOK {
		t.Fatalf("sh status %d", rec4.Code)
	}
	sh := rec4.Body.String()
	if !strings.HasPrefix(sh, "#!/usr/bin/env bash") || !strings.Contains(sh, "docker compose up -d") || !strings.Contains(sh, "services:") {
		snip := sh
		if len(snip) > 300 {
			snip = snip[:300]
		}
		t.Fatalf("bad script: %s", snip)
	}
	cmd, _ := created["install_cmd"].(string)
	if !strings.Contains(cmd, tok+".sh") {
		t.Fatalf("install_cmd %q", cmd)
	}
}
