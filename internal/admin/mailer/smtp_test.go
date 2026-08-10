// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mailer

import (
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestLoadSaveConfigured(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "smtp.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if Load(db).Configured() {
		t.Fatal("expected empty smtp")
	}
	if err := Save(db, Config{Host: "smtp.example", From: "a@b.c", Port: 587}); err != nil {
		t.Fatal(err)
	}
	got := Load(db)
	if !got.Configured() || got.Host != "smtp.example" || got.From != "a@b.c" {
		t.Fatalf("%+v", got)
	}
	pub := got.PublicView()
	if pub.Password != "" && pub.Password != "••••••••" {
		// empty password stays empty
	}
	got.Password = "secret"
	_ = Save(db, got)
	if Load(db).PublicView().Password != "••••••••" {
		t.Fatal("password not masked")
	}
}

func TestSaveValidation(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "smtp2.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Save(db, Config{From: "a@b.c"}); err == nil {
		t.Fatal("expected host required")
	}
	if err := Save(db, Config{Host: "x"}); err == nil {
		t.Fatal("expected from required")
	}
}

func TestSendNotConfigured(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "smtp3.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Send(db, "a@b.c", "s", "b"); err != ErrNotConfigured {
		t.Fatalf("got %v", err)
	}
}
