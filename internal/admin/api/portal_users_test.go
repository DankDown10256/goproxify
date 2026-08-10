// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/mailer"
	"github.com/vincamok/goproxify/internal/core/portal"
)

func TestInvitePortalUserRequiresSMTP(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "pu.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_ = admindb.SetSetting(db, settingPortalConfigPrefix+"core-a", `{"enabled":true,"public_host":"access.example"}`)

	h := &PortalHandler{DB: db, Log: nil}
	body := `{"email":"a@b.c","home_core":"core-a","tags":["ops"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/portal/users/invite", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "SMTP") {
		t.Fatalf("expected SMTP error, got %s", rr.Body.String())
	}
}

func TestInvitePortalUserRequiresPublicHost(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "pu2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := mailer.Save(db, mailer.Config{Host: "smtp.example", From: "noreply@example.com", Port: 587}); err != nil {
		t.Fatal(err)
	}
	_ = admindb.SetSetting(db, settingPortalConfigPrefix+"core-a", `{"enabled":true}`)

	h := &PortalHandler{DB: db, Log: nil}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/portal/users/invite", strings.NewReader(`{"email":"a@b.c","home_core":"core-a"}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "hôte public") {
		t.Fatalf("expected public host error, got %s", rr.Body.String())
	}
}

func TestListSyncedUsersForCore(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "pu3.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`INSERT INTO portal_users (id, email, status, tags_json, invite_token_hash, invite_expires, home_core)
		VALUES ('u1','a@b.c','invited','["ops"]','hash1','2099-01-01T00:00:00Z','core-a')`)
	if err != nil {
		t.Fatal(err)
	}
	synced := listSyncedUsersForCore(db, "core-a")
	if len(synced) != 1 || synced[0].Email != "a@b.c" || synced[0].InviteTokenHash != "hash1" {
		t.Fatalf("%+v", synced)
	}
	MarkPortalInviteCompleted(db, "u1")
	var st string
	_ = db.QueryRow(`SELECT status FROM portal_users WHERE id='u1'`).Scan(&st)
	if st != portal.UserStatusActive {
		t.Fatalf("status=%s", st)
	}
	synced = listSyncedUsersForCore(db, "core-a")
	if synced[0].InviteTokenHash != "" {
		t.Fatalf("invite hash should be cleared on active push: %+v", synced[0])
	}
}

func TestUpdatePortalUserDisable(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "pu4.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _ = db.Exec(`INSERT INTO portal_users (id, email, status, tags_json, home_core)
		VALUES ('u1','a@b.c','active','[]','core-a')`)
	h := &PortalHandler{DB: db, Log: nil}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/portal/users/u1", strings.NewReader(`{"status":"disabled","tags":["x"]}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d %s", rr.Code, rr.Body.String())
	}
	var u PortalUser
	_ = json.Unmarshal(rr.Body.Bytes(), &u)
	if u.Status != "disabled" || len(u.Tags) != 1 {
		t.Fatalf("%+v", u)
	}
}

func TestPortalUsersTableExists(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "pu5.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM portal_users`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	_ = sql.ErrNoRows
}
