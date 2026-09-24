// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package errorpages

import (
	"strings"
	"testing"
)

func TestBuildLogURLRequiresAdminBase(t *testing.T) {
	SetAdminBaseURL("")
	if got := buildLogURL("abc123"); got != "" {
		t.Fatalf("sans AdminBaseURL, attendu lien vide, got %q", got)
	}
}

func TestBuildLogURLAbsoluteToAdmin(t *testing.T) {
	SetAdminBaseURL("https://admin.example:9443/")
	defer SetAdminBaseURL("")

	got := buildLogURL("73ed347cac24da64c11de247")
	if !strings.HasPrefix(got, "https://admin.example:9443/?") {
		t.Fatalf("lien doit pointer vers l'Admin, got %q", got)
	}
	for _, want := range []string{
		"gpx_page=logs",
		"component=core",
		"search=73ed347cac24da64c11de247",
		"kind=access",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("lien %q doit contenir %q", got, want)
		}
	}
}

func TestRenderDoesNotExposeAdminURL(t *testing.T) {
	SetAdminBaseURL("http://203.0.113.90:9443")
	defer SetAdminBaseURL("")

	html := Render(502, "api.example.com", "req-xyz", "en")
	// L'URL Admin ne doit jamais apparaître dans la page publique.
	if strings.Contains(html, "203.0.113.90") {
		t.Fatalf("l'URL Admin ne doit pas être exposée dans la page d'erreur publique, html=%s", html)
	}
	if strings.Contains(html, `href=`) {
		t.Fatal("aucun lien href ne doit apparaître dans la page d'erreur publique")
	}
	// Le reqID doit rester affiché (utile support).
	if !strings.Contains(html, "req-xyz") {
		t.Fatal("le request ID doit rester visible")
	}
	if !strings.Contains(html, `lang="en"`) {
		t.Fatal("attendu lang=en")
	}
	if !strings.Contains(html, "Bad gateway") {
		t.Fatal("attendu titre EN Bad gateway")
	}
}

func TestRenderFrenchAcceptLanguage(t *testing.T) {
	html := Render(404, "example.com", "", "fr-FR,fr;q=0.9")
	if !strings.Contains(html, `lang="fr"`) {
		t.Fatalf("attendu lang=fr, html excerpt missing")
	}
	if !strings.Contains(html, "Page introuvable") {
		t.Fatal("attendu titre FR")
	}
	if !strings.Contains(html, "Hôte") {
		t.Fatal("attendu label Hôte")
	}
}
