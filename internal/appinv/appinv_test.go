// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package appinv

import "testing"

func TestParseImage(t *testing.T) {
	for _, tc := range []struct {
		ref  string
		want Image
	}{
		{"nginx", Image{Repo: "nginx"}},
		{"nginx:1.25.3-alpine", Image{Repo: "nginx", Tag: "1.25.3-alpine"}},
		{"grafana/grafana:10.2.0", Image{Repo: "grafana/grafana", Tag: "10.2.0"}},
		{"ghcr.io/gitea/gitea:1.21", Image{Registry: "ghcr.io", Repo: "gitea/gitea", Tag: "1.21"}},
		{"registry.local:5000/team/app:v2", Image{Registry: "registry.local:5000", Repo: "team/app", Tag: "v2"}},
		{"registry.local:5000/app", Image{Registry: "registry.local:5000", Repo: "app"}},
		{"nginx@sha256:abc", Image{Repo: "nginx", Digest: "sha256:abc"}},
		{"Nginx:Latest", Image{Repo: "nginx", Tag: "Latest"}},
	} {
		if got := ParseImage(tc.ref); got != tc.want {
			t.Errorf("%q : %+v, attendu %+v", tc.ref, got, tc.want)
		}
	}
}

func TestFromImage(t *testing.T) {
	for _, tc := range []struct {
		ref               string
		product, cpe, ver string
		partial           bool
	}{
		{"wordpress:6.4.2-apache", "wordpress", "wordpress:wordpress", "6.4.2", false},
		{"nginx:1.25.3-alpine3.18", "nginx", "nginx:nginx", "1.25.3", false},
		{"docker.io/library/nginx:1.25", "nginx", "nginx:nginx", "1.25", true},
		{"grafana/grafana:10.2.0", "grafana", "grafana:grafana", "10.2.0", false},
		{"grafana/grafana-image-renderer:v10.2.0", "", "", "", false}, // pas dans la table : rien n'est deviné
		{"lscr.io/linuxserver/nextcloud:28.0.1-ls300", "nextcloud", "nextcloud:nextcloud_server", "28.0.1", false},
		{"vaultwarden/server:1.30.1", "vaultwarden", "", "1.30.1", false}, // produit connu, sans CPE sûr
		{"nginx:latest", "nginx", "nginx:nginx", "", false},
		{"nginx", "nginx", "nginx:nginx", "", false},
		{"nginx:mainline-alpine", "nginx", "nginx:nginx", "", false},
		{"nginx:1", "nginx", "nginx:nginx", "", false}, // une seule composante : pas une version précise
		{"postgres:16.1-bookworm", "postgresql", "postgresql:postgresql", "16.1", true},
		{"nginx@sha256:0123", "nginx", "nginx:nginx", "", false},
		{"myorg/nginx-custom:1.2.3", "", "", "", false},
		{"registry.local:5000/team/app:2.0.1", "", "", "", false},
	} {
		got, ok := FromImage(tc.ref)
		if !ok {
			t.Errorf("%q : non reconnu", tc.ref)
			continue
		}
		if got.Product != tc.product || got.CPE != tc.cpe || got.Version != tc.ver || got.Partial != tc.partial || got.Source != SourceImage || got.Evidence != tc.ref {
			t.Errorf("%q : %+v", tc.ref, got)
		}
	}
	if _, ok := FromImage("  "); ok {
		t.Error("une référence vide ne se reconnaît pas")
	}
}

func TestTablesAreConsistent(t *testing.T) {
	cpeOf := map[string]string{}
	check := func(table string, m map[string]known) {
		for name, k := range m {
			if k.product == "" {
				t.Errorf("%s/%s : produit vide", table, name)
			}
			if k.cpe != "" && !CPEPattern.MatchString(k.cpe) {
				t.Errorf("%s/%s : CPE %q mal formé", table, name, k.cpe)
			}
			if prev, ok := cpeOf[k.product]; ok && prev != k.cpe {
				t.Errorf("%s/%s : le produit %q a deux identifiants, %q et %q", table, name, k.product, prev, k.cpe)
			}
			cpeOf[k.product] = k.cpe
		}
	}
	check("images", knownImages)
	check("serveurs", serverProducts)
	check("générateurs", generators)
}
