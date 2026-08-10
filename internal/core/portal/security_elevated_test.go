// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func skipUntilElevatedFix(t *testing.T, id, reason string) {
	t.Helper()
	t.Skipf("pending %s: %s", id, reason)
}

// TestElevatedH4_FinishLoginBlocksDisabled — contrat finishLogin (référence pour OIDC).
func TestElevatedH4_FinishLoginBlocksDisabled(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "p.gpx"), "test-secret")
	_ = store.CreateUser(UserRecord{
		ID: "u1", Username: "sso@ex.com", Status: UserStatusDisabled,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	h := NewHTTPServer(&Config{Enabled: true}, store, NewSessionManager(), nil, nil)
	rr := httptest.NewRecorder()
	u, _ := store.FindUserByID("u1")
	key := DeriveSSOVaultKey("master", u.ID)
	h.finishLogin(rr, u, key, "oidc")
	if rr.Code != http.StatusForbidden {
		t.Fatalf("disabled via finishLogin: status=%d want 403", rr.Code)
	}
	if strings.Contains(rr.Body.String(), `"token"`) {
		t.Fatal("ne doit pas émettre de token pour compte disabled")
	}
}

// TestElevatedH4_OIDCCallbackUsesFinishLogin — callback OIDC via finishOIDCRedirect.
func TestElevatedH4_OIDCCallbackUsesFinishLogin(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(file), "oidc.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if !strings.Contains(src, "finishOIDCRedirect") {
		t.Fatal("H4: oidc.go doit définir finishOIDCRedirect")
	}
	if !strings.Contains(src, "h.finishOIDCRedirect(") {
		t.Fatal("H4: callback OIDC doit appeler finishOIDCRedirect")
	}
	if strings.Contains(src, "issueToken") && strings.Contains(src, "http.Redirect") {
		// OK si redirect après garde-fous — mais pas d’issueToken sans check disabled
	}
	if !strings.Contains(src, "UserStatusDisabled") {
		t.Fatal("H4: finishOIDCRedirect doit refuser UserStatusDisabled")
	}
	if !strings.Contains(portalIndexHTML, "sso_2fa") {
		t.Fatal("H4: UI portal doit gérer le fragment #sso_2fa")
	}
}

// TestElevatedH4_OIDCRedirectBlocksDisabled — finishOIDCRedirect 403.
func TestElevatedH4_OIDCRedirectBlocksDisabled(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "p.gpx"), "test-secret")
	_ = store.CreateUser(UserRecord{
		ID: "u2", Username: "off@ex.com", Status: UserStatusDisabled,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	h := NewHTTPServer(&Config{Enabled: true}, store, NewSessionManager(), nil, nil)
	rr := httptest.NewRecorder()
	u, _ := store.FindUserByID("u2")
	key := DeriveSSOVaultKey("master", u.ID)
	req := httptest.NewRequest(http.MethodGet, "/api/oidc/callback", nil)
	h.finishOIDCRedirect(rr, req, u, key)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("disabled OIDC redirect: status=%d want 403", rr.Code)
	}
}

// TestElevatedH5_PortalUIHasEscHelper — helper d’échappement XSS requis.
func TestElevatedH5_PortalUIHasEscHelper(t *testing.T) {
	if !strings.Contains(portalIndexHTML, "function esc(") && !strings.Contains(portalIndexHTML, "const esc=") {
		t.Fatal("H5: helper esc() absent de portalIndexHTML")
	}
	for _, frag := range []string{
		"esc(s.facade",
		"esc(e.detail",
		"esc(t.name)",
		"esc(name)",
	} {
		if !strings.Contains(portalIndexHTML, frag) {
			t.Fatalf("H5: innerHTML user data non échappé — manque %s", frag)
		}
	}
}
