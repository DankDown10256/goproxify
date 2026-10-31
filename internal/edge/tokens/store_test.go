// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"path/filepath"
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

func TestRevokeNamedExceptKeepsTheGivenTokenAndOtherNames(t *testing.T) {
	s := openTestStore(t)
	for _, tok := range []struct{ name, raw string }{
		{"admin-ws", "gpx_ancien_admin"}, {"admin-ws", "gpx_admin_courant"}, {"admin-edge-1", "gpx_amorcage"},
	} {
		if err := s.EnsureToken(tok.name, tok.raw, RoleAdmin); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.RevokeNamedExcept("admin-ws", "gpx_admin_courant")
	if err != nil || n != 1 {
		t.Fatalf("un seul jeton révoqué : %d %v", n, err)
	}
	for raw, want := range map[string]bool{"gpx_ancien_admin": false, "gpx_admin_courant": true, "gpx_amorcage": true} {
		if _, ok, _ := s.RoleOf(raw); ok != want {
			t.Errorf("%s : valide=%v, attendu %v", raw, ok, want)
		}
	}
	if _, err := s.RevokeNamedExcept("admin-ws", ""); err == nil {
		t.Fatal("sans jeton à garder, rien n'est révoqué")
	}
}

func countTokens(t *testing.T, s *Store, role Role, name string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tokens WHERE role=? AND name=?`, string(role), name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Chaque appairage ajoute un jeton : la purge garde les plus récents d'un nom, jamais le dernier émis, et ne touche ni
// les autres noms ni les autres rôles.
func TestPruneNamedKeepsTheMostRecent(t *testing.T) {
	s := openTestStore(t)
	raws := make([]string, 30)
	for i := range raws {
		raws[i], _, _ = s.Create("a1", RoleAgent, 0)
	}
	for i := 0; i < 5; i++ {
		_, _, _ = s.Create("a2", RoleAgent, 0)
	}
	_, _, _ = s.Create("a1", RoleAdmin, 0) // même nom, autre rôle

	n, err := s.PruneNamed(RoleAgent, "a1", 20)
	if err != nil || n != 10 {
		t.Fatalf("PruneNamed = %d, %v ; attendu 10 supprimés", n, err)
	}
	if got := countTokens(t, s, RoleAgent, "a1"); got != 20 {
		t.Errorf("a1 : %d jetons, attendu 20", got)
	}
	for i, raw := range raws {
		ok, _ := s.Validate(raw)
		if want := i >= 10; ok != want {
			t.Errorf("jeton %d : valide=%v, attendu %v (les 20 plus récents seulement)", i, ok, want)
		}
	}
	if countTokens(t, s, RoleAgent, "a2") != 5 || countTokens(t, s, RoleAdmin, "a1") != 1 {
		t.Error("les autres noms et les autres rôles ne doivent pas être touchés")
	}

	// Rien à supprimer : second passage sans effet.
	if n, _ := s.PruneNamed(RoleAgent, "a1", 20); n != 0 {
		t.Errorf("second passage : %d supprimés", n)
	}
}

func TestPruneCountsRevokedTokensToo(t *testing.T) {
	s := openTestStore(t)
	for i := 0; i < 6; i++ {
		_, id, _ := s.Create("a1", RoleAgent, 0)
		if i < 3 {
			_ = s.Revoke(id)
		}
	}
	if n, err := s.PruneNamed(RoleAgent, "a1", 2); err != nil || n != 4 {
		t.Fatalf("PruneNamed = %d, %v", n, err)
	}
}

func TestPruneAllBoundsEveryName(t *testing.T) {
	s := openTestStore(t)
	for i := 0; i < 25; i++ {
		_, _, _ = s.Create("a1", RoleAgent, 0)
	}
	for i := 0; i < 12; i++ {
		_, _, _ = s.Create("a2", RoleAgent, 0)
	}
	for i := 0; i < 3; i++ {
		_, _, _ = s.Create("a3", RoleAgent, 0)
	}
	n, err := s.PruneAll(RoleAgent, 10)
	if err != nil || n != 17 { // 15 de a1 + 2 de a2
		t.Fatalf("PruneAll = %d, %v ; attendu 17", n, err)
	}
	for name, want := range map[string]int{"a1": 10, "a2": 10, "a3": 3} {
		if got := countTokens(t, s, RoleAgent, name); got != want {
			t.Errorf("%s : %d jetons, attendu %d", name, got, want)
		}
	}
}

func TestPruneRefusesToKeepNothing(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.PruneNamed(RoleAgent, "a1", 0); err == nil {
		t.Error("PruneNamed(0) doit être refusé : il vide le magasin")
	}
	if _, err := s.PruneAll(RoleAgent, 0); err == nil {
		t.Error("PruneAll(0) doit être refusé")
	}
}

// Un gros nettoyage (17 457 jetons constatés pour un seul Agent) rend aussi la place au fichier, sur disque.
func TestPruneAllOnADiskFileAfterAFlood(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "edge-tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.db.Exec(`WITH RECURSIVE c(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM c WHERE i < 1100)
		INSERT INTO tokens(id, name, token_hash, role) SELECT 'id'||i, 'goproxify-agent', 'h'||i, 'agent' FROM c`); err != nil {
		t.Fatal(err)
	}
	newest, _, _ := s.Create("goproxify-agent", RoleAgent, 0)

	n, err := s.PruneAll(RoleAgent, KeepAgentTokens)
	if err != nil || n != 1101-KeepAgentTokens {
		t.Fatalf("PruneAll = %d, %v", n, err)
	}
	if ok, _ := s.Validate(newest); !ok {
		t.Error("le jeton le plus récent doit rester valide")
	}
	if _, _, err := s.Create("goproxify-agent", RoleAgent, 0); err != nil {
		t.Errorf("le magasin doit rester utilisable après le nettoyage : %v", err)
	}
}
