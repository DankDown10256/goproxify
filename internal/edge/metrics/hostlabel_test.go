// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"net/http/httptest"
	"testing"
)

func TestHostOf(t *testing.T) {
	r := httptest.NewRequest("GET", "http://client-choice.example.fr/", nil)
	if got := HostOf(r); got != "client-choice.example.fr" {
		t.Fatalf("sans étiquette fixée : %q, attendu le nom reçu", got)
	}
	r = r.WithContext(WithHost(r.Context(), "*.example.fr"))
	if got := HostOf(r); got != "*.example.fr" {
		t.Fatalf("avec étiquette fixée : %q, attendu *.example.fr", got)
	}
}
