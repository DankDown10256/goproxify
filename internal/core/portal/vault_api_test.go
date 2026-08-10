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

func TestPersonalTargetsForbiddenWhenDisabled(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "p.gpx"), "test-secret")
	hash, _ := HashPassword("password1")
	_ = store.CreateUser(UserRecord{
		ID: "u1", Username: "a@b.c", PasswordHash: hash,
		Status: UserStatusActive, CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	h := NewHTTPServer(&Config{Enabled: true, AllowPersonalTargets: false}, store, NewSessionManager(), nil, nil)
	tok := loginToken(t, h, "a@b.c", "password1")

	req := httptest.NewRequest(http.MethodPost, "/api/targets", strings.NewReader(
		`{"name":"vm","kind":"ssh","host":"10.0.0.1","port":22}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d %s", rr.Code, rr.Body.String())
	}
}

func TestPersonalDockerTargetsForbidden(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "p.gpx"), "test-secret")
	hash, _ := HashPassword("password1")
	_ = store.CreateUser(UserRecord{
		ID: "u1", Username: "a@b.c", PasswordHash: hash,
		Status: UserStatusActive, CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	h := NewHTTPServer(&Config{Enabled: true, AllowPersonalTargets: true}, store, NewSessionManager(), nil, nil)
	tok := loginToken(t, h, "a@b.c", "password1")

	req := httptest.NewRequest(http.MethodPost, "/api/targets", strings.NewReader(
		`{"name":"box","kind":"docker","agent_name":"agent-1","container":"nginx"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d %s", rr.Code, rr.Body.String())
	}
}

func TestVaultPutGetNeverReturnsSecret(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "p.gpx"), "test-secret")
	hash, _ := HashPassword("password1")
	_ = store.CreateUser(UserRecord{
		ID: "u1", Username: "a@b.c", PasswordHash: hash,
		Status: UserStatusActive, CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	_ = store.SetCatalog([]CatalogTarget{{ID: "c1", Name: "pub", Kind: TargetSSH, Host: "1.1.1.1", Port: 22}})
	h := NewHTTPServer(&Config{Enabled: true}, store, NewSessionManager(), nil, nil)
	tok := loginToken(t, h, "a@b.c", "password1")

	req := httptest.NewRequest(http.MethodPut, "/api/vault/c1", strings.NewReader(
		`{"username":"ubuntu","password":"s3cret","private_key":"KEYDATA"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("put=%d %s", rr.Code, rr.Body.String())
	}
	var putMeta VaultEntryMeta
	_ = json.Unmarshal(rr.Body.Bytes(), &putMeta)
	if putMeta.Username != "ubuntu" || !putMeta.HasPassword || !putMeta.HasPrivateKey {
		t.Fatalf("meta %+v", putMeta)
	}
	body := rr.Body.String()
	if strings.Contains(body, "s3cret") || strings.Contains(body, "KEYDATA") {
		t.Fatalf("secret leaked in PUT response: %s", body)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/vault", nil)
	req2.Header.Set("Authorization", "Bearer "+tok)
	rr2 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("get=%d %s", rr2.Code, rr2.Body.String())
	}
	raw := rr2.Body.String()
	if strings.Contains(raw, "s3cret") || strings.Contains(raw, "KEYDATA") {
		t.Fatalf("secret leaked in GET: %s", raw)
	}
	var out struct {
		Entries []VaultEntryMeta `json:"entries"`
	}
	_ = json.Unmarshal(rr2.Body.Bytes(), &out)
	if len(out.Entries) != 1 || out.Entries[0].Username != "ubuntu" || !out.Entries[0].HasPassword || !out.Entries[0].HasPrivateKey {
		t.Fatalf("%+v", out.Entries)
	}

	req3 := httptest.NewRequest(http.MethodDelete, "/api/vault/c1", nil)
	req3.Header.Set("Authorization", "Bearer "+tok)
	rr3 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr3, req3)
	if rr3.Code != http.StatusNoContent {
		t.Fatalf("del=%d", rr3.Code)
	}
}

func TestAuthInfoExposesPersonalFlag(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "p.gpx"), "test-secret")
	h := NewHTTPServer(&Config{Enabled: true, AllowPersonalTargets: true}, store, NewSessionManager(), nil, nil)
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/auth-info", nil))
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["allow_personal_targets"] != true {
		t.Fatalf("%v", out)
	}
}

func TestCatalogSessionUsesVaultLoginNotEmail(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "p.gpx"), "test-secret")
	hash, _ := HashPassword("password1")
	_ = store.CreateUser(UserRecord{
		ID: "u1", Username: "a@b.c", PasswordHash: hash,
		Status: UserStatusActive, CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	_ = store.SetCatalog([]CatalogTarget{{ID: "c1", Name: "vm", Kind: TargetSSH, Host: "10.0.0.1", Port: 22}})
	h := NewHTTPServer(&Config{Enabled: true, PublicHost: "access.test"}, store, NewSessionManager(), nil, nil)
	tok := loginToken(t, h, "a@b.c", "password1")

	req := httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(
		`{"target_id":"c1","source":"catalog","facade":"ssh"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("without vault: %d %s", rr.Code, rr.Body.String())
	}

	reqV := httptest.NewRequest(http.MethodPut, "/api/vault/c1", strings.NewReader(
		`{"username":"ubuntu","password":"s3cret"}`))
	reqV.Header.Set("Authorization", "Bearer "+tok)
	rrV := httptest.NewRecorder()
	h.Handler().ServeHTTP(rrV, reqV)
	if rrV.Code != http.StatusOK {
		t.Fatalf("vault: %d %s", rrV.Code, rrV.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(
		`{"target_id":"c1","source":"catalog","facade":"ssh"}`))
	req2.Header.Set("Authorization", "Bearer "+tok)
	rr2 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusCreated {
		t.Fatalf("session: %d %s", rr2.Code, rr2.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rr2.Body.Bytes(), &out)
	uuid, _ := out["uuid"].(string)
	if uuid == "" {
		t.Fatal("no uuid")
	}
	sess, ok := h.sessions.Peek(uuid)
	if !ok {
		t.Fatal("peek")
	}
	if sess.Target.Username != "ubuntu" {
		t.Fatalf("ssh user=%q (must not be email)", sess.Target.Username)
	}
	if sess.Target.Username == "a@b.c" {
		t.Fatal("email used as ssh login")
	}
}

func loginToken(t *testing.T, h *HTTPServer, user, pass string) string {
	t.Helper()
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(
		`{"username":"`+user+`","password":"`+pass+`"}`)))
	var login map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &login)
	tok, _ := login["token"].(string)
	if tok == "" {
		t.Fatalf("login failed: %s", rr.Body.String())
	}
	return tok
}
