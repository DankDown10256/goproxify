// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPolicyBlocksLoginAndSession(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "p.gpx"), "test-secret")
	hash, _ := HashPassword("password1")
	_ = store.CreateUser(UserRecord{
		ID: "u1", Username: "a@b.c", PasswordHash: hash,
		Status: UserStatusActive, CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	_ = store.SetCatalog([]CatalogTarget{{ID: "c1", Name: "srv", Kind: TargetSSH, Host: "1.1.1.1", Port: 22}})
	h := NewHTTPServer(&Config{Enabled: true}, store, NewSessionManager(), nil, nil)
	tok := loginToken(t, h, "a@b.c", "password1")

	pol := Policy{IPAllow: []string{"10.0.0.0/8"}}
	h.policy = func() Policy { return pol }

	login := func(remote string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"a@b.c","password":"password1"}`))
		req.RemoteAddr = remote
		rr := httptest.NewRecorder()
		h.Handler().ServeHTTP(rr, req)
		return rr.Code
	}
	if c := login("203.0.113.5:1000"); c != http.StatusForbidden {
		t.Fatalf("IP hors liste: %d", c)
	}
	if c := login("10.1.1.1:1000"); c == http.StatusForbidden {
		t.Fatalf("IP autorisée refusée: %d", c)
	}

	create := func(remote string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/sessions", strings.NewReader(`{"target_id":"c1","source":"catalog","facade":"ssh"}`))
		req.Header.Set("Authorization", "Bearer "+tok)
		req.RemoteAddr = remote
		rr := httptest.NewRecorder()
		h.Handler().ServeHTTP(rr, req)
		return rr.Code
	}
	if c := create("203.0.113.5:1000"); c != http.StatusForbidden {
		t.Fatalf("session depuis IP interdite: %d", c)
	}

	// Fenêtre horaire fermée : jour sans autorisation.
	closedDay := int(time.Now().UTC().Weekday()+1) % 7
	pol = Policy{HoursEnabled: true, Days: []int{closedDay}, StartTime: "00:00", EndTime: "23:59"}
	if c := create("10.1.1.1:1000"); c != http.StatusForbidden {
		t.Fatalf("session hors plage horaire: %d", c)
	}
	pol = Policy{}
	if c := create("10.1.1.1:1000"); c == http.StatusForbidden {
		t.Fatalf("sans politique la session doit passer: %d", c)
	}
}
