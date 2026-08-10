// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"os"
	"strings"
	"testing"
)

func TestNodeTokenSealOpenAndHash(t *testing.T) {
	os.Unsetenv("GPX_NODE_TOKEN_KEY")
	ConfigureNodeTokenKey("jwt-secret-for-test")
	plain := "gpx_core_abc123deadbeef"
	stored, hash := PrepareNodeTokenForStore(plain)
	if hash != HashNodeToken(plain) {
		t.Fatal("hash mismatch")
	}
	if !strings.HasPrefix(stored, nodeTokenEncPrefix) {
		t.Fatalf("attendu chiffrement, got %s", stored)
	}
	got, err := OpenNodeToken(stored)
	if err != nil || got != plain {
		t.Fatalf("open: %v %q", err, got)
	}
	if PlainNodeToken(stored) != plain {
		t.Fatal("PlainNodeToken")
	}
}

func TestNodeTokenLegacyPlain(t *testing.T) {
	ConfigureNodeTokenKey("")
	os.Unsetenv("GPX_NODE_TOKEN_KEY")
	ConfigureNodeTokenKey("")
	plain := "legacy-token"
	stored, hash := PrepareNodeTokenForStore(plain)
	if stored != plain {
		t.Fatalf("sans clé: passthrough, got %s", stored)
	}
	if hash != HashNodeToken(plain) {
		t.Fatal("hash even without seal")
	}
}
