// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServeIndexCustomLoginAE7(t *testing.T) {
	h := NewHTTPServer(&Config{PublicHost: "access.example"}, NewStore(t.TempDir()+"/p.gpx", "k"), NewSessionManager(), nil, nil)
	h.pageTemplates.ReplaceAll([]PageTemplate{
		{Key: PageLogin, Body: `<h1>CustomLogin {{brand}} {{core_name}}</h1>`},
	})
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != 200 {
		t.Fatalf("%d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "CustomLogin") || !strings.Contains(body, "GoProxify Access") {
		t.Fatalf("%s", body)
	}
	if !strings.Contains(body, "access.example") {
		t.Fatalf("core_name missing: %s", body)
	}
	if strings.Contains(body, "GoProxify Access</h1>") && strings.Contains(body, "Sessions SSH") {
		t.Fatal("should not serve full SPA when custom login set")
	}
}

func TestServeIndexFallbackSPA(t *testing.T) {
	h := NewHTTPServer(&Config{}, NewStore(t.TempDir()+"/p.gpx", "k"), NewSessionManager(), nil, nil)
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if !strings.Contains(rr.Body.String(), "GoProxify Access") || !strings.Contains(rr.Body.String(), "btnLogin") {
		t.Fatal("SPA fallback")
	}
}
