// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"log/slog"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "portal.gpx")
	s := NewStore(path, "test-master-key")
	u := UserRecord{ID: "u1", Username: "alice", PasswordHash: "x", CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertPersonalTarget("u1", PersonalTarget{ID: "t1", Name: "vm", Kind: TargetSSH, Host: "10.0.0.1", Port: 22}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetCatalog([]CatalogTarget{{ID: "c1", Name: "pub", Kind: TargetSSH, Host: "1.2.3.4", Port: 22}}); err != nil {
		t.Fatal(err)
	}

	s2 := NewStore(path, "test-master-key")
	if err := s2.Load(); err != nil {
		t.Fatal(err)
	}
	got, ok := s2.FindUserByUsername("alice")
	if !ok || got.ID != "u1" {
		t.Fatalf("user: %+v", got)
	}
	if len(s2.PersonalTargets("u1")) != 1 {
		t.Fatalf("personal: %v", s2.PersonalTargets("u1"))
	}
	if len(s2.Catalog()) != 1 {
		t.Fatalf("catalog: %v", s2.Catalog())
	}
}

func TestVaultSealOpen(t *testing.T) {
	key := DeriveVaultKey("u1", "password123")
	payload := VaultPayload{"t1": {Password: "secret", PrivateKey: "KEY"}}
	blob, err := SealVault(key, payload)
	if err != nil {
		t.Fatal(err)
	}
	out, err := OpenVault(key, blob)
	if err != nil {
		t.Fatal(err)
	}
	if out["t1"].Password != "secret" {
		t.Fatalf("got %+v", out["t1"])
	}
	bad := DeriveVaultKey("u1", "wrong")
	if _, err := OpenVault(bad, blob); err == nil {
		t.Fatal("expected decrypt fail")
	}
}

func TestSessionOneShot(t *testing.T) {
	m := NewSessionManager()
	s := m.Create("u", "alice", "t1", dialTarget{Kind: TargetSSH, Host: "h", Port: 22}, FacadeSSH, DefaultSessionTTL, SessionModeOneShot)
	if _, ok := m.Peek(s.ID); !ok {
		t.Fatal("peek")
	}
	got, ok := m.Consume(s.ID)
	if !ok || got.ID != s.ID {
		t.Fatal("consume")
	}
	if _, ok := m.Consume(s.ID); ok {
		t.Fatal("second consume should fail")
	}
}

func TestHashPassword(t *testing.T) {
	h, err := HashPassword("password123")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword(h, "password123") {
		t.Fatal("check")
	}
	if CheckPassword(h, "nope") {
		t.Fatal("should fail")
	}
}

func TestAuthSessionPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "portal.gpx")
	s := NewStore(path, "test-master-key")
	u := UserRecord{ID: "u1", Username: "bob", PasswordHash: "x", CreatedAt: time.Now().UTC().Format(time.RFC3339)}
	if err := s.CreateUser(u); err != nil {
		t.Fatal(err)
	}
	tok := "abc123token"
	if err := s.PutAuthSession(tok, AuthSession{
		UserID: "u1", Username: "bob", VaultKey: "aa", Expires: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	s2 := NewStore(path, "test-master-key")
	if err := s2.Load(); err != nil {
		t.Fatal(err)
	}
	if s2.UserCount() != 1 {
		t.Fatalf("users=%d", s2.UserCount())
	}
	got, ok := s2.GetAuthSession(tok)
	if !ok || got.Username != "bob" {
		t.Fatalf("session: %+v ok=%v", got, ok)
	}
}

func TestApplyConfigHotReloadKeepsStore(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "portal.gpx")
	t.Setenv("GPX_PORTAL_MASTER_KEY", "hot-reload-key")

	svc := NewService(slog.Default())
	cfg := Config{Enabled: true, SSHPort: 2222, HTTPPort: 18444, DBPath: db, PublicHost: "a.example"}
	if err := svc.ApplyConfig(cfg); err != nil {
		t.Fatal(err)
	}
	defer svc.Stop()

	if err := svc.store.CreateUser(UserRecord{
		ID: "u1", Username: "keepme", PasswordHash: "x",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}

	cfg2 := cfg
	cfg2.PublicHost = "b.example"
	if err := svc.ApplyConfig(cfg2); err != nil {
		t.Fatal(err)
	}
	if svc.store.UserCount() != 1 {
		t.Fatalf("users lost after hot reload: %d", svc.store.UserCount())
	}
	if svc.Config().PublicHost != "b.example" {
		t.Fatalf("host=%s", svc.Config().PublicHost)
	}
}
