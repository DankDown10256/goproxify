// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac

import "testing"

func TestShouldReceiveCert_AdminSansScope_Tout(t *testing.T) {
	if !ShouldReceiveCert("admin", nil, "*.dankdown.fr") {
		t.Fatal("admin sans scope doit recevoir tous les certs")
	}
	if !ShouldReceiveCert("admin", []Scope{}, "*.example.com") {
		t.Fatal("admin scopes vides doit recevoir tous les certs")
	}
}

func TestShouldReceiveCert_AdminAvecScope(t *testing.T) {
	scopes := []Scope{{Type: "domain", Value: "*.dankdown.fr"}}
	if !ShouldReceiveCert("admin", scopes, "*.dankdown.fr") {
		t.Fatal("doit matcher le wildcard cert")
	}
	if !ShouldReceiveCert("admin", scopes, "api.dankdown.fr") {
		t.Fatal("doit matcher un host couvert")
	}
	if ShouldReceiveCert("admin", scopes, "*.example.com") {
		t.Fatal("ne doit pas recevoir un autre domaine")
	}
}

func TestShouldReceiveCert_ViewerSansScope_Rien(t *testing.T) {
	if ShouldReceiveCert("viewer", nil, "*.dankdown.fr") {
		t.Fatal("viewer sans scope ne doit rien recevoir")
	}
}

func TestMatchCertName_ApexEtWildcard(t *testing.T) {
	scopes := []Scope{{Type: "domain", Value: "*.example.fr"}}
	if !MatchCertName(scopes, "example.fr") {
		t.Fatal("scope wildcard doit couvrir l'apex stocké sans *.")
	}
	if !MatchCertName(scopes, "*.example.fr") {
		t.Fatal("scope wildcard doit couvrir le nom *.example.fr")
	}
}
