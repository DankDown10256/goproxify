// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/vincamok/goproxify/internal/admin/auth"
)

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL)`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestIsFirstRun(t *testing.T) {
	db := openDB(t)
	if !IsFirstRun(db) {
		t.Fatal("empty DB should be first run")
	}
	if err := CreateFirstAdmin(db, "admin@test.com", "password123"); err != nil {
		t.Fatal(err)
	}
	if IsFirstRun(db) {
		t.Fatal("non-empty DB should not be first run")
	}
}

func TestCreateFirstAdmin(t *testing.T) {
	db := openDB(t)
	if err := CreateFirstAdmin(db, "admin@test.com", "secure-pass"); err != nil {
		t.Fatal(err)
	}
	var hash string
	if err := db.QueryRow(`SELECT password_hash FROM users WHERE email=?`, "admin@test.com").Scan(&hash); err != nil {
		t.Fatal(err)
	}
	if !auth.CheckPassword(hash, "secure-pass") {
		t.Fatal("password hash does not match")
	}
}

func TestInitFirstRun_EnvVars(t *testing.T) {
	db := openDB(t)
	t.Setenv("GPX_FIRST_ADMIN_EMAIL", "env@test.com")
	t.Setenv("GPX_FIRST_ADMIN_PASSWORD", "env-password")
	Init(db, nil)
	if IsFirstRun(db) {
		t.Fatal("Init should have created admin from env vars")
	}
}

func TestInitFirstRun_MissingEnv(t *testing.T) {
	db := openDB(t)
	t.Setenv("GPX_FIRST_ADMIN_EMAIL", "")
	t.Setenv("GPX_FIRST_ADMIN_PASSWORD", "")
	Init(db, nil)
	// should remain first run with no error
	if !IsFirstRun(db) {
		t.Fatal("Init should not create admin without env vars")
	}
}

func TestInitPasswordReset(t *testing.T) {
	db := openDB(t)
	// Create admin with original password
	if err := CreateFirstAdmin(db, "recover@test.com", "old-password"); err != nil {
		t.Fatal(err)
	}
	// Simulate password change by direct DB update (e.g. after import with different hash)
	badHash, _ := auth.HashPassword("some-other-password")
	db.Exec(`UPDATE users SET password_hash=? WHERE email=?`, badHash, "recover@test.com")

	// Init should reset password to match env
	t.Setenv("GPX_FIRST_ADMIN_EMAIL", "recover@test.com")
	t.Setenv("GPX_FIRST_ADMIN_PASSWORD", "new-password")
	Init(db, nil)

	var hash string
	db.QueryRow(`SELECT password_hash FROM users WHERE email=?`, "recover@test.com").Scan(&hash)
	if !auth.CheckPassword(hash, "new-password") {
		t.Fatal("password should have been reset by Init")
	}
}
