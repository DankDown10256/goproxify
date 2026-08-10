// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/core/router"
)

type mockProviders struct {
	p *router.AuthProvider
}

func (m mockProviders) Get(idOrName string) (*router.AuthProvider, bool) {
	if m.p != nil && (m.p.ID == idOrName || m.p.Name == idOrName) {
		return m.p, true
	}
	return nil, false
}

func TestLoginViaBasicProvider(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir+"/p.gpx", "master")
	cfg := &Config{Enabled: true, AuthProviderID: "basic-1", PublicHost: "p.example"}
	cfg.Defaults()

	sso := router.SSOConfig{
		Enabled:  true,
		Provider: "basic",
		BasicUsers: []router.BasicUser{
			{Username: "alice", Password: "secret-pass"},
		},
	}
	raw, _ := json.Marshal(sso)
	h := NewHTTPServer(cfg, store, NewSessionManager(), slog.Default(), nil)
	h.masterSecret = "master"
	h.providers = mockProviders{p: &router.AuthProvider{
		ID: "basic-1", Name: "Basic", Type: "basic", Config: raw,
	}}

	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"alice","password":"secret-pass"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["via"] != "provider" || out["token"] == nil {
		t.Fatalf("out=%v", out)
	}
	if store.UserCount() != 1 {
		t.Fatalf("expected SSO user created, got %d", store.UserCount())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"alice","password":"bad"}`))
	req2.Header.Set("Content-Type", "application/json")
	rr2 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 got %d %s", rr2.Code, rr2.Body.String())
	}
}

func TestAuthInfo(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir+"/p.gpx", "master")
	cfg := &Config{AuthProviderID: "basic-1"}
	cfg.Defaults()
	sso := router.SSOConfig{Provider: "basic", BasicUsers: []router.BasicUser{{Username: "a", Password: "b"}}}
	raw, _ := json.Marshal(sso)
	h := NewHTTPServer(cfg, store, NewSessionManager(), slog.Default(), nil)
	h.providers = mockProviders{p: &router.AuthProvider{ID: "basic-1", Name: "B", Type: "basic", Config: raw}}

	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/auth-info", nil))
	if rr.Code != 200 {
		t.Fatal(rr.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	prov, _ := out["provider"].(map[string]any)
	if prov["form_login"] != true {
		t.Fatalf("%v", out)
	}
}

func TestAuthenticateProviderBasic(t *testing.T) {
	sso := &router.SSOConfig{
		Provider:   "basic",
		BasicUsers: []router.BasicUser{{Username: "u", Password: "p"}},
	}
	ok, err := authenticateProvider(sso, "u", "p")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	ok, err = authenticateProvider(sso, "u", "wrong")
	if err != nil || ok {
		t.Fatalf("expected fail ok=%v err=%v", ok, err)
	}
}
