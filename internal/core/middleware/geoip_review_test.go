// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReviewP0_OpenGeoDBCachesSamePath(t *testing.T) {
	// Sans .mmdb valide, Open échoue — on vérifie juste que deux échecs n'insèrent rien.
	path := filepath.Join(t.TempDir(), "missing.mmdb")
	_, err1 := openGeoDB(path)
	_, err2 := openGeoDB(path)
	if err1 == nil || err2 == nil {
		t.Fatal("fichier absent doit échouer")
	}
	if _, ok := geoReaders.Load(path); ok {
		t.Fatal("échec Open ne doit pas polluer geoReaders")
	}
}

func TestReviewP0_GeoIPMissingFileIsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nope.mmdb")
	_ = os.WriteFile(path+".other", []byte("x"), 0o600)
	mw := GeoIP(path, "deny", []string{"CN"})
	// noopMiddleware renvoie next tel quel — smoke : pas de panic
	if mw == nil {
		t.Fatal("middleware nil")
	}
}
