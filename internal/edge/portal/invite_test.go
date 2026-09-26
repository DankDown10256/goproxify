// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRegisterGone(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "p.gpx"), "test-secret")
	h := NewHTTPServer(&Config{Enabled: true}, store, NewSessionManager(), nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/api/register", strings.NewReader(`{"username":"a","password":"password1"}`))
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusGone {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestCompleteInviteAndLogin(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "p.gpx"), "test-secret")
	raw, err := NewInviteToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SyncUsers([]SyncedUser{{
		ID: "u1", Email: "alice@example.com", Status: UserStatusInvited,
		Tags: []string{"ops"}, InviteTokenHash: HashInviteToken(raw),
		InviteExpires: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
	}}); err != nil {
		t.Fatal(err)
	}
	var completed string
	h := NewHTTPServer(&Config{Enabled: true}, store, NewSessionManager(), nil, nil)
	h.onInviteCompleted = func(id string) { completed = id }

	req := httptest.NewRequest(http.MethodPost, "/api/complete-invite", strings.NewReader(
		`{"token":"`+raw+`","password":"password1"}`))
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("complete status=%d body=%s", rr.Code, rr.Body.String())
	}
	if completed != "u1" {
		t.Fatalf("hook user=%q", completed)
	}
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["token"] == nil || out["username"] != "alice@example.com" {
		t.Fatalf("%v", out)
	}

	// token réutilisé → invalide
	rr2 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr2, httptest.NewRequest(http.MethodPost, "/api/complete-invite", strings.NewReader(
		`{"token":"`+raw+`","password":"password1"}`)))
	if rr2.Code != http.StatusBadRequest {
		t.Fatalf("reuse status=%d", rr2.Code)
	}

	// login OK
	rr3 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr3, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(
		`{"username":"alice@example.com","password":"password1"}`)))
	if rr3.Code != http.StatusOK {
		t.Fatalf("login status=%d %s", rr3.Code, rr3.Body.String())
	}
}

func TestCompleteInviteExpired(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "p.gpx"), "test-secret")
	raw, _ := NewInviteToken()
	_ = store.SyncUsers([]SyncedUser{{
		ID: "u1", Email: "a@b.c", Status: UserStatusInvited,
		InviteTokenHash: HashInviteToken(raw),
		InviteExpires:   time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	}})
	h := NewHTTPServer(&Config{Enabled: true}, store, NewSessionManager(), nil, nil)
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/complete-invite", strings.NewReader(
		`{"token":"`+raw+`","password":"password1"}`)))
	if rr.Code != http.StatusGone {
		t.Fatalf("status=%d %s", rr.Code, rr.Body.String())
	}
}

func TestLoginDisabledUser(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "p.gpx"), "test-secret")
	hash, _ := HashPassword("password1")
	_ = store.CreateUser(UserRecord{
		ID: "u1", Username: "bob@example.com", PasswordHash: hash,
		Status: UserStatusDisabled, AdminManaged: true,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	h := NewHTTPServer(&Config{Enabled: true}, store, NewSessionManager(), nil, nil)
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(
		`{"username":"bob@example.com","password":"password1"}`)))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d %s", rr.Code, rr.Body.String())
	}
}

func TestSyncUsersPreservesPassword(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "p.gpx"), "test-secret")
	hash, _ := HashPassword("password1")
	_ = store.SyncUsers([]SyncedUser{{
		ID: "u1", Email: "a@b.c", Status: UserStatusActive, Tags: []string{"ops"},
	}})
	_ = store.CompleteInvite("u1", hash)
	_ = store.SyncUsers([]SyncedUser{{
		ID: "u1", Email: "a@b.c", Status: UserStatusActive, Tags: []string{"ops", "prod"},
	}})
	u, ok := store.FindUserByUsername("a@b.c")
	if !ok || u.PasswordHash != hash || len(u.Tags) != 2 {
		t.Fatalf("%+v ok=%v", u, ok)
	}
}

func TestAuthInfoRegisterFalse(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "p.gpx"), "test-secret")
	h := NewHTTPServer(&Config{Enabled: true}, store, NewSessionManager(), nil, nil)
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/auth-info", nil))
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["register"] != false {
		t.Fatalf("%v", out)
	}
}

func TestListTargetsFiltersByTags(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(filepath.Join(dir, "p.gpx"), "test-secret")
	_ = store.SetCatalog([]CatalogTarget{
		{ID: "pub", Name: "public", Kind: TargetSSH, Host: "1.1.1.1", Port: 22},
		{ID: "prod", Name: "prod-box", Kind: TargetSSH, Host: "2.2.2.2", Port: 22, Tags: []string{"prod"}},
		{ID: "dev", Name: "dev-box", Kind: TargetSSH, Host: "3.3.3.3", Port: 22, Tags: []string{"dev"}},
	})
	hash, _ := HashPassword("password1")
	_ = store.SyncUsers([]SyncedUser{{
		ID: "u1", Email: "dev@example.com", Status: UserStatusActive, Tags: []string{"dev"},
	}})
	_ = store.CompleteInvite("u1", hash)

	h := NewHTTPServer(&Config{Enabled: true}, store, NewSessionManager(), nil, nil)
	// login
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(
		`{"username":"dev@example.com","password":"password1"}`)))
	var login map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &login)
	tok, _ := login["token"].(string)
	if tok == "" {
		t.Fatalf("login: %s", rr.Body.String())
	}

	req := httptest.NewRequest(http.MethodGet, "/api/targets", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr2 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr2, req)
	var body struct {
		Targets []struct {
			ID string `json:"id"`
		} `json:"targets"`
	}
	_ = json.Unmarshal(rr2.Body.Bytes(), &body)
	ids := map[string]bool{}
	for _, titem := range body.Targets {
		ids[titem.ID] = true
	}
	if !ids["pub"] || !ids["dev"] || ids["prod"] {
		t.Fatalf("AE2 filter: %+v", body.Targets)
	}

	// session on prod must 404
	reqS := httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(
		`{"target_id":"prod","source":"catalog","facade":"ssh"}`))
	reqS.Header.Set("Authorization", "Bearer "+tok)
	rr3 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr3, reqS)
	if rr3.Code != http.StatusNotFound {
		t.Fatalf("session hidden target: %d %s", rr3.Code, rr3.Body.String())
	}
}
