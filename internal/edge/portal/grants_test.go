// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"testing"
	"time"
)

func TestGrantSetExpiry(t *testing.T) {
	g := NewGrantSet()
	now := time.Now().UTC()
	g.Replace([]AccessGrant{
		{UserID: "u1", TargetID: "t1", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)},
		{UserID: "u1", TargetID: "t2", ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339)},
		{UserID: "u1", TargetID: "t3", ExpiresAt: "n'importe quoi"},
	})
	if _, ok := g.Expiry("u1", "t1"); !ok {
		t.Fatal("accès actif attendu")
	}
	if _, ok := g.Expiry("u1", "t2"); ok {
		t.Fatal("accès expiré ignoré attendu")
	}
	if _, ok := g.Expiry("u1", "t3"); ok {
		t.Fatal("date invalide ignorée attendue")
	}
	if _, ok := g.Expiry("u2", "t1"); ok {
		t.Fatal("autre utilisateur sans accès")
	}
	g.Replace(nil)
	if _, ok := g.Expiry("u1", "t1"); ok {
		t.Fatal("Replace doit vider l'ensemble")
	}
	var nilSet *GrantSet
	if _, ok := nilSet.Expiry("a", "b"); ok {
		t.Fatal("nil safe")
	}
}
