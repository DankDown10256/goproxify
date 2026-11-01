// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package surface

import "testing"

func TestEnumShape(t *testing.T) {
	cases := []struct {
		path, shape, values string
		ok                  bool
	}{
		{"/api/users/42", "/api/users/{int}", "42", true},
		{"/api/users/42/orders/7", "/api/users/{int}/orders/{int}", "42/7", true},
		{"/api/files/3f2504e0-4f89-11d3-9a0c-0305e82c3301", "/api/files/{uuid}", "3f2504e0-4f89-11d3-9a0c-0305e82c3301", true},
		{"/api/users", "", "", false},
		{"/", "", "", false},
		{"/api/archive/2026-11-02", "", "", false}, // une date est un filtre, pas un identifiant à énumérer
		{"/static/app.js", "", "", false},
	}
	for _, c := range cases {
		shape, values, ok := EnumShape(c.path)
		if ok != c.ok || shape != c.shape || values != c.values {
			t.Errorf("%s : %q %q %v ; attendu %q %q %v", c.path, shape, values, ok, c.shape, c.values, c.ok)
		}
	}
}

func TestConvergedIsFalseWithoutAProfile(t *testing.T) {
	c := NewCollector(Options{})
	if c.Converged("inconnue") {
		t.Fatal("pas de profil, pas de référence")
	}
}
