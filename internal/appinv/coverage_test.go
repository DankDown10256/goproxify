// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package appinv

import "testing"

func TestCoverage(t *testing.T) {
	for _, tc := range []struct {
		f    Finding
		want string
	}{
		{Finding{Product: "nginx", CPE: "nginx:nginx", Version: "1.25.3"}, CoverageCovered},
		{Finding{Product: "nginx", CPE: "nginx:nginx", Version: "1.25", Partial: true}, CoverageCovered},
		{Finding{Product: "nginx", CPE: "nginx:nginx"}, CoverageNoVersion},
		{Finding{Product: "vaultwarden", Version: "1.30.1"}, CoverageNoCPE},
		{Finding{Source: SourceImage, Evidence: "team/app:2"}, CoverageUnknown},
	} {
		if got := tc.f.Coverage(); got != tc.want {
			t.Errorf("%+v : %s, attendu %s", tc.f, got, tc.want)
		}
	}
}

func TestNameAndEvidenceVersionOfUnrecognisedEntries(t *testing.T) {
	for _, tc := range []struct {
		f             Finding
		name, version string
	}{
		{Finding{Source: SourceImage, Evidence: "registry.local:5000/Team/Shop:2.4.1-fpm"}, "team/shop", "2.4.1"},
		{Finding{Source: SourceImage, Evidence: "team/app:latest"}, "team/app", ""},
		{Finding{Source: SourceHeaders, Evidence: "Server: Microsoft-HTTPAPI/2.0"}, "microsoft-httpapi", "2.0"},
		{Finding{Source: SourceHTML, Evidence: `<meta name="generator"> Mon CMS 1.2.3`}, "mon", "1.2.3"},
		{Finding{Product: "wordpress", Source: SourceImage, Evidence: "wordpress:6.4.2"}, "wordpress", "6.4.2"},
	} {
		if got := tc.f.Name(); got != tc.name {
			t.Errorf("%+v : nom %q, attendu %q", tc.f, got, tc.name)
		}
		if got := tc.f.EvidenceVersion(); got != tc.version {
			t.Errorf("%+v : version %q, attendu %q", tc.f, got, tc.version)
		}
	}
}

func TestWithCPE(t *testing.T) {
	f := Finding{Source: SourceImage, Evidence: "team/shop:2.4"}.WithCPE("shop", "acme:shop")
	if f.Product != "shop" || f.CPE != "acme:shop" || f.Version != "2.4" || !f.Partial || f.Coverage() != CoverageCovered {
		t.Errorf("%+v", f)
	}
	g := Finding{Product: "vaultwarden", Version: "1.30.1", Source: SourceImage, Evidence: "vaultwarden/server:1.31.0"}.WithCPE("vaultwarden", "dani-garcia:vaultwarden")
	if g.Version != "1.30.1" {
		t.Errorf("une version connue n'est pas remplacée : %+v", g)
	}
}
