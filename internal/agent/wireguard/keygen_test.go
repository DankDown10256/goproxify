// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package wireguard

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestGenerateKeyPair_PubNotPriv(t *testing.T) {
	priv, pub, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if priv == "" || pub == "" {
		t.Fatal("clés vides")
	}
	if priv == pub {
		t.Fatal("pubkey ne doit pas égaler la privée")
	}
	privB, _ := base64.StdEncoding.DecodeString(priv)
	pubB, _ := base64.StdEncoding.DecodeString(pub)
	if bytes.Equal(privB, pubB) {
		t.Fatal("bytes pubkey == privée (fallback M12)")
	}
}

func TestCurve25519ScalarBaseMult_Deterministic(t *testing.T) {
	var priv [32]byte
	for i := range priv {
		priv[i] = byte(i + 1)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
	a, err := curve25519ScalarBaseMult(priv)
	if err != nil {
		t.Fatal(err)
	}
	b, err := curve25519ScalarBaseMult(priv)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("non déterministe")
	}
	if bytes.Equal(a[:], priv[:]) {
		t.Fatal("ne doit pas renvoyer la privée")
	}
}
