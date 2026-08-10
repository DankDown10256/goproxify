// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ws

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReviewP2_HMACStorePropagatesSaveError(t *testing.T) {
	dir := t.TempDir()
	// Parent = fichier : MkdirAll/WriteFile doivent échouer.
	blocker := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewAgentHMACStore(filepath.Join(blocker, "hmac.json"))
	if err := s.Set("a1", "deadbeef"); err == nil {
		t.Fatal("Set doit propager l'erreur de persistance")
	}
}

func TestReviewP2_HMACStorePersistsRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hmac.json")
	s := NewAgentHMACStore(path)
	if err := s.Set("a1", "deadbeef"); err != nil {
		t.Fatal(err)
	}
	s2 := NewAgentHMACStore(path)
	got, ok := s2.Get("a1")
	if !ok || got != "deadbeef" {
		t.Fatalf("got %q ok=%v", got, ok)
	}
}
