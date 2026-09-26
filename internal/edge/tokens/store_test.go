// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"testing"
	"time"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestBootstrapIdempotent(t *testing.T) {
	s := openTestStore(t)
	if err := s.Bootstrap("admin", "gpx_admin_abc", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	// second call on non-empty store must be no-op
	if err := s.Bootstrap("other", "gpx_admin_xyz", RoleAdmin); err != nil {
		t.Fatal(err)
	}
	list, _ := s.List()
	if len(list) != 1 {
		t.Fatalf("expected 1 token, got %d", len(list))
	}
}

func TestCreateAndValidate(t *testing.T) {
	s := openTestStore(t)
	raw, id, err := s.Create("test-agent", RoleAgent, 0)
	if err != nil {
		t.Fatal(err)
	}
	if id == "" || raw == "" {
		t.Fatal("empty id or token")
	}
	ok, err := s.Validate(raw)
	if err != nil || !ok {
		t.Fatalf("validate: ok=%v err=%v", ok, err)
	}
	// Unknown token
	ok, _ = s.Validate("gpx_agent_unknown")
	if ok {
		t.Fatal("unknown token should not validate")
	}
}

func TestRevoke(t *testing.T) {
	s := openTestStore(t)
	raw, id, _ := s.Create("to-revoke", RoleAdmin, 0)
	if err := s.Revoke(id); err != nil {
		t.Fatal(err)
	}
	ok, _ := s.Validate(raw)
	if ok {
		t.Fatal("revoked token should not validate")
	}
}

func TestRevokeByRaw(t *testing.T) {
	s := openTestStore(t)
	raw, _, _ := s.Create("to-revoke-raw", RoleAgent, 0)
	if err := s.RevokeByRaw(raw); err != nil {
		t.Fatal(err)
	}
	ok, _ := s.Validate(raw)
	if ok {
		t.Fatal("revoked token should not validate")
	}
}

func TestExpiry(t *testing.T) {
	s := openTestStore(t)
	raw, id, _ := s.Create("short-lived", RoleAgent, time.Hour)
	// force expiry to the past
	s.db.Exec(`UPDATE tokens SET expires_at=datetime('now','-1 hour') WHERE id=?`, id)
	ok, _ := s.Validate(raw)
	if ok {
		t.Fatal("expired token should not validate")
	}
}

func TestEnsureToken(t *testing.T) {
	s := openTestStore(t)
	raw := "gpx_agent_ensure123"
	if err := s.EnsureToken("ensure", raw, RoleAgent); err != nil {
		t.Fatal(err)
	}
	ok, _ := s.Validate(raw)
	if !ok {
		t.Fatal("ensured token should validate")
	}
	// idempotent
	if err := s.EnsureToken("ensure", raw, RoleAgent); err != nil {
		t.Fatal(err)
	}
}

func TestEnsureToken_ReactivatesRevoked(t *testing.T) {
	s := openTestStore(t)
	raw := "gpx_agent_reactivate"
	if err := s.EnsureToken("r", raw, RoleAgent); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeByRaw(raw); err != nil {
		t.Fatal(err)
	}
	// EnsureToken should reactivate
	if err := s.EnsureToken("r", raw, RoleAgent); err != nil {
		t.Fatal(err)
	}
	ok, _ := s.Validate(raw)
	if !ok {
		t.Fatal("reactivated token should validate")
	}
}

func TestHasActiveAgent(t *testing.T) {
	s := openTestStore(t)
	if s.HasActiveAgent("agent-1") {
		t.Fatal("should be false on empty store")
	}
	if err := s.EnsureToken("agent-1", "gpx_agent_ha1", RoleAgent); err != nil {
		t.Fatal(err)
	}
	if !s.HasActiveAgent("agent-1") {
		t.Fatal("should be true after insert")
	}
}

func TestRevokeUnknownID(t *testing.T) {
	s := openTestStore(t)
	if err := s.Revoke("nonexistent"); err == nil {
		t.Fatal("should error on unknown id")
	}
	if err := s.Revoke(""); err == nil {
		t.Fatal("should error on empty id")
	}
}
