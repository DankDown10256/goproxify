// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package i18n

import "testing"

func TestParse(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", LocaleEN},
		{"en", LocaleEN},
		{"EN", LocaleEN},
		{"en-US", LocaleEN},
		{"fr", LocaleFR},
		{"fr-FR", LocaleFR},
		{"fr_CA", LocaleFR},
		{"es", LocaleES},
		{"es-ES", LocaleES},
		{"es_MX", LocaleES},
		{"de", LocaleDE},
		{"de-DE", LocaleDE},
		{"de_AT", LocaleDE},
		{"it", LocaleEN},
	}
	for _, c := range cases {
		if got := Parse(c.in); got != c.want {
			t.Errorf("Parse(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestFromAcceptLanguage(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", LocaleEN},
		{"en", LocaleEN},
		{"fr", LocaleFR},
		{"es", LocaleES},
		{"de", LocaleDE},
		{"fr-FR,fr;q=0.9,en;q=0.8", LocaleFR},
		{"en-US,en;q=0.9,fr;q=0.8", LocaleEN},
		{"de,en;q=0.5", LocaleDE},
		{"de-DE", LocaleDE},
		{"es-ES,es;q=0.9,en;q=0.8", LocaleES},
		{"fr;q=0.2,en;q=0.8", LocaleEN},
		{"*;q=0.1", LocaleEN},
		{"it,en;q=0.5", LocaleEN},
	}
	for _, c := range cases {
		if got := FromAcceptLanguage(c.in); got != c.want {
			t.Errorf("FromAcceptLanguage(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestTFallbackToEN(t *testing.T) {
	got := T(LocaleEN, "err.title.404")
	if got != "Page not found" {
		t.Fatalf("EN title: got %q", got)
	}
	got = T(LocaleFR, "err.title.404")
	if got != "Page introuvable" {
		t.Fatalf("FR title: got %q", got)
	}
	got = T(LocaleES, "err.title.404")
	if got != "Página no encontrada" {
		t.Fatalf("ES title: got %q", got)
	}
	got = T(LocaleDE, "err.title.404")
	if got != "Seite nicht gefunden" {
		t.Fatalf("DE title: got %q", got)
	}
	got = T(LocaleFR, "err.title.999_missing")
	if got != "err.title.999_missing" {
		t.Fatalf("unknown key should return key, got %q", got)
	}
}
