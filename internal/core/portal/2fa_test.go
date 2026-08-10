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

func TestTOTPEnrollAndLoginChallenge(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "p.gpx"), "secret")
	hash, _ := HashPassword("password1")
	_ = store.CreateUser(UserRecord{
		ID: "u1", Username: "a@b.c", PasswordHash: hash,
		Status: UserStatusActive, CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	h := NewHTTPServer(&Config{Enabled: true}, store, NewSessionManager(), nil, nil)
	tok := loginToken(t, h, "a@b.c", "password1")

	req := httptest.NewRequest(http.MethodPost, "/api/2fa/totp/setup", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("setup=%d %s", rr.Code, rr.Body.String())
	}
	var setup map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &setup)
	secret, _ := setup["secret"].(string)
	qr, _ := setup["qr_code"].(string)
	if secret == "" {
		t.Fatal("secret manquant")
	}
	if !strings.HasPrefix(qr, "data:image/png;base64,") {
		t.Fatalf("qr_code attendu data URL PNG, got %q", qr)
	}
	if uri, _ := setup["otpauth_uri"].(string); !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("otpauth_uri invalide: %v", setup["otpauth_uri"])
	}
	code, err := TOTPCode(secret)
	if err != nil {
		t.Fatal(err)
	}
	req2 := httptest.NewRequest(http.MethodPost, "/api/2fa/totp/verify", strings.NewReader(`{"code":"`+code+`"}`))
	req2.Header.Set("Authorization", "Bearer "+tok)
	rr2 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("enable=%d %s", rr2.Code, rr2.Body.String())
	}

	// login → need_2fa
	rr3 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr3, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(
		`{"username":"a@b.c","password":"password1"}`)))
	var login map[string]any
	_ = json.Unmarshal(rr3.Body.Bytes(), &login)
	if login["need_2fa"] != true || login["challenge_id"] == nil {
		t.Fatalf("login: %v", login)
	}
	chid, _ := login["challenge_id"].(string)
	code2, _ := TOTPCode(secret)
	rr4 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr4, httptest.NewRequest(http.MethodPost, "/api/2fa/verify", strings.NewReader(
		`{"challenge_id":"`+chid+`","method":"totp","code":"`+code2+`"}`)))
	if rr4.Code != http.StatusOK {
		t.Fatalf("verify=%d %s", rr4.Code, rr4.Body.String())
	}
	var okTok map[string]any
	_ = json.Unmarshal(rr4.Body.Bytes(), &okTok)
	if okTok["token"] == nil {
		t.Fatal("missing token")
	}

	// bad code
	rr5 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr5, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(
		`{"username":"a@b.c","password":"password1"}`)))
	_ = json.Unmarshal(rr5.Body.Bytes(), &login)
	chid, _ = login["challenge_id"].(string)
	rr6 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr6, httptest.NewRequest(http.MethodPost, "/api/2fa/verify", strings.NewReader(
		`{"challenge_id":"`+chid+`","method":"totp","code":"000000"}`)))
	if rr6.Code != http.StatusUnauthorized {
		t.Fatalf("bad code status=%d", rr6.Code)
	}
}

func TestRequire2FABlocksWithoutEnrollment(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "p.gpx"), "secret")
	hash, _ := HashPassword("password1")
	_ = store.CreateUser(UserRecord{
		ID: "u1", Username: "a@b.c", PasswordHash: hash,
		Status: UserStatusActive, CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	h := NewHTTPServer(&Config{Enabled: true, Require2FA: true}, store, NewSessionManager(), nil, nil)
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(
		`{"username":"a@b.c","password":"password1"}`)))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "2FA") {
		t.Fatalf("body=%s", rr.Body.String())
	}
}

func TestEmailOTPSendAndVerify(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "p.gpx"), "secret")
	hash, _ := HashPassword("password1")
	_ = store.CreateUser(UserRecord{
		ID: "u1", Username: "a@b.c", PasswordHash: hash,
		Status: UserStatusActive, EmailOTPEnabled: true,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	var sentCode string
	h := NewHTTPServer(&Config{Enabled: true}, store, NewSessionManager(), nil, nil)
	h.sendEmailOTP = func(email, code string) error {
		sentCode = code
		return nil
	}
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(
		`{"username":"a@b.c","password":"password1"}`)))
	var login map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &login)
	chid, _ := login["challenge_id"].(string)
	if chid == "" {
		t.Fatalf("%v", login)
	}
	rr2 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr2, httptest.NewRequest(http.MethodPost, "/api/2fa/email/send", strings.NewReader(
		`{"challenge_id":"`+chid+`"}`)))
	if rr2.Code != http.StatusNoContent || sentCode == "" {
		t.Fatalf("send=%d code=%q", rr2.Code, sentCode)
	}
	rr3 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr3, httptest.NewRequest(http.MethodPost, "/api/2fa/verify", strings.NewReader(
		`{"challenge_id":"`+chid+`","method":"email","code":"`+sentCode+`"}`)))
	if rr3.Code != http.StatusOK {
		t.Fatalf("verify=%d %s", rr3.Code, rr3.Body.String())
	}

	// expired OTP
	rr4 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr4, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(
		`{"username":"a@b.c","password":"password1"}`)))
	_ = json.Unmarshal(rr4.Body.Bytes(), &login)
	chid, _ = login["challenge_id"].(string)
	_ = sentCode
	h.sendEmailOTP = func(email, code string) error { sentCode = code; return nil }
	rr5 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr5, httptest.NewRequest(http.MethodPost, "/api/2fa/email/send", strings.NewReader(
		`{"challenge_id":"`+chid+`"}`)))
	ch, _ := h.challenges.Get(chid)
	ch.EmailOTPExpires = time.Now().UTC().Add(-time.Minute)
	h.challenges.Update(ch)
	rr6 := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr6, httptest.NewRequest(http.MethodPost, "/api/2fa/verify", strings.NewReader(
		`{"challenge_id":"`+chid+`","method":"email","code":"`+sentCode+`"}`)))
	if rr6.Code != http.StatusUnauthorized {
		t.Fatalf("expired status=%d %s", rr6.Code, rr6.Body.String())
	}
}
