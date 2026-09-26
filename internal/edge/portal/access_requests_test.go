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

func TestAccessRequestFlow(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "p.gpx"), "test-secret")
	hash, _ := HashPassword("password1")
	_ = store.CreateUser(UserRecord{
		ID: "u1", Username: "a@b.c", PasswordHash: hash,
		Status: UserStatusActive, CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	_ = store.SetCatalog([]CatalogTarget{
		{ID: "pub", Name: "public", Kind: TargetSSH, Host: "1.1.1.1", Port: 22},
		{ID: "sec", Name: "secret", Kind: TargetSSH, Host: "2.2.2.2", Port: 22, Tags: []string{"ops"}},
	})
	h := NewHTTPServer(&Config{Enabled: true}, store, NewSessionManager(), nil, nil)
	h.grants = NewGrantSet()
	tok := loginToken(t, h, "a@b.c", "password1")

	call := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		rr := httptest.NewRecorder()
		h.Handler().ServeHTTP(rr, req)
		return rr
	}

	if body := call(http.MethodGet, "/api/targets", "").Body.String(); strings.Contains(body, `"sec"`) {
		t.Fatalf("la cible taguée ne doit pas être visible: %s", body)
	}
	if body := call(http.MethodGet, "/api/access/requestable", "").Body.String(); !strings.Contains(body, `"sec"`) || strings.Contains(body, `"pub"`) {
		t.Fatalf("requestable: %s", body)
	}

	valid := `{"target_id":"sec","reason":"migration","duration_min":30}`
	if rr := call(http.MethodPost, "/api/access/requests", valid); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("sans hook: %d", rr.Code)
	}

	var got []AccessRequest
	h.onAccessRequest = func(r AccessRequest) error { got = append(got, r); return nil }
	for _, bad := range []string{
		`{"target_id":"sec","reason":"","duration_min":30}`,
		`{"target_id":"sec","reason":"x","duration_min":1}`,
		`{"target_id":"sec","reason":"x","duration_min":9999}`,
	} {
		if rr := call(http.MethodPost, "/api/access/requests", bad); rr.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d", bad, rr.Code)
		}
	}
	if rr := call(http.MethodPost, "/api/access/requests", `{"target_id":"pub","reason":"x","duration_min":30}`); rr.Code != http.StatusNotFound {
		t.Fatalf("cible déjà visible: %d", rr.Code)
	}
	if rr := call(http.MethodPost, "/api/access/requests", valid); rr.Code != http.StatusAccepted {
		t.Fatalf("demande: %d %s", rr.Code, rr.Body.String())
	}
	if len(got) != 1 || got[0].UserID != "u1" || got[0].TargetID != "sec" || got[0].DurationMin != 30 {
		t.Fatalf("hook: %+v", got)
	}

	h.grants.Replace([]AccessGrant{{UserID: "u1", TargetID: "sec", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}})
	if body := call(http.MethodGet, "/api/targets", "").Body.String(); !strings.Contains(body, `"sec"`) || !strings.Contains(body, "expires_at") {
		t.Fatalf("accès temporaire attendu: %s", body)
	}
	if body := call(http.MethodGet, "/api/access/requestable", "").Body.String(); strings.Contains(body, `"sec"`) {
		t.Fatalf("plus demandable une fois accordé: %s", body)
	}
}
