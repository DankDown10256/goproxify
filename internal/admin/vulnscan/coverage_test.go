// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"context"
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/appinv"
	"github.com/vincamok/goproxify/internal/edge/logapi"
)

func entry(host, backend string, f appinv.Finding) logapi.InventoryEntry {
	return logapi.InventoryEntry{Route: host, Host: host, Backend: backend, Finding: f}
}

func TestValidateOverrides(t *testing.T) {
	got, err := ValidateOverrides([]Override{{Match: "  Vaultwarden ", CPE: "Dani-Garcia:Vaultwarden"}})
	if err != nil || got[0].Match != "vaultwarden" || got[0].CPE != "dani-garcia:vaultwarden" {
		t.Fatalf("normalisation : %+v %v", got, err)
	}
	for name, in := range map[string][]Override{
		"sans nom":      {{Match: " ", CPE: "a:b"}},
		"cpe sans :":    {{Match: "x", CPE: "vaultwarden"}},
		"cpe complet":   {{Match: "x", CPE: "cpe:2.3:a:a:b:*:*:*:*:*:*:*"}},
		"cpe à espaces": {{Match: "x", CPE: "a b:c"}},
		"doublon":       {{Match: "x", CPE: "a:b"}, {Match: "X", CPE: "c:d"}},
	} {
		if _, err := ValidateOverrides(in); err == nil {
			t.Errorf("%s : doit être refusé", name)
		}
	}
	tooMany := make([]Override, maxOverrides+1)
	for i := range tooMany {
		tooMany[i] = Override{Match: string(rune('a'+i%26)) + string(rune('a'+i/26)), CPE: "a:b"}
	}
	if _, err := ValidateOverrides(tooMany); err == nil {
		t.Error("trop de surcharges")
	}
}

func TestOverridesCompleteOnlyWhatTheTableDoesNotCover(t *testing.T) {
	in := []logapi.InventoryEntry{
		entry("vw.test", "http://a", appinv.Finding{Product: "vaultwarden", Source: "image", Evidence: "vaultwarden/server:1.30.1"}),
		entry("app.test", "http://b", appinv.Finding{Source: "image", Evidence: "registry.local:5000/team/Shop:2.4.1"}),
		entry("erp.test", "http://c", appinv.Finding{Source: "headers", Evidence: "Server: Microsoft-HTTPAPI/2.0"}),
		entry("wp.test", "http://d", appinv.Finding{Product: "wordpress", CPE: "wordpress:wordpress", Version: "6.4.2", Source: "image", Evidence: "wordpress:6.4.2"}),
		entry("lat.test", "http://e", appinv.Finding{Product: "grafana", CPE: "grafana:grafana", Source: "image", Evidence: "grafana/grafana:latest"}),
	}
	ov := []Override{
		{Match: "vaultwarden", CPE: "dani-garcia:vaultwarden"},
		{Match: "shop", CPE: "acme:shop"},                       // dernier segment du dépôt
		{Match: "microsoft-httpapi", CPE: "microsoft:http_api"}, // jeton d'en-tête
		{Match: "wordpress", CPE: "evil:wordpress"},             // la table l'emporte
	}
	got := ApplyOverrides(in, ov)
	if in[0].CPE != "" || in[0].Coverage != "" {
		t.Fatal("les entrées passées ne sont pas modifiées")
	}
	if g := got[0]; g.CPE != "dani-garcia:vaultwarden" || g.Version != "1.30.1" || g.Coverage != appinv.CoverageCovered {
		t.Errorf("produit connu sans CPE : %+v", g)
	}
	if g := got[1]; g.CPE != "acme:shop" || g.Product != "shop" || g.Version != "2.4.1" || g.Coverage != appinv.CoverageCovered {
		t.Errorf("image inconnue : %+v", g)
	}
	if g := got[2]; g.CPE != "microsoft:http_api" || g.Version != "2.0" || g.Coverage != appinv.CoverageCovered {
		t.Errorf("logiciel inconnu d'un en-tête : %+v", g)
	}
	if g := got[3]; g.CPE != "wordpress:wordpress" {
		t.Errorf("la table n'est pas écrasée : %+v", g)
	}
	if g := got[4]; g.Coverage != appinv.CoverageNoVersion {
		t.Errorf("latest : %+v", g)
	}
}

func TestCoverageReportGroupsWhatCannotBeSearched(t *testing.T) {
	es := ApplyOverrides([]logapi.InventoryEntry{
		entry("a.test", "http://1", appinv.Finding{Product: "wordpress", CPE: "wordpress:wordpress", Version: "6.4.2", Source: "image", Evidence: "wordpress:6.4.2"}),
		entry("b.test", "http://2", appinv.Finding{Product: "postgresql", CPE: "postgresql:postgresql", Version: "16.1", Partial: true, Source: "image", Evidence: "postgres:16.1"}),
		entry("c.test", "http://3", appinv.Finding{Product: "grafana", CPE: "grafana:grafana", Source: "image", Evidence: "grafana/grafana:latest"}),
		entry("d.test", "http://4", appinv.Finding{Product: "vaultwarden", Source: "image", Evidence: "vaultwarden/server:1.30.1"}),
		entry("e.test", "http://5", appinv.Finding{Product: "vaultwarden", Source: "image", Evidence: "vaultwarden/server:1.30.1"}),
		entry("f.test", "http://6", appinv.Finding{Source: "image", Evidence: "team/app:2"}),
		entry("g.test", "http://7", appinv.Finding{Source: "headers", Evidence: "Server: Microsoft-HTTPAPI/2.0"}),
	}, nil)
	c := BuildCoverage(es)
	if c.Total != 7 || c.Covered != 2 || c.Partial != 1 || c.NoVersion != 1 || c.NoCPE != 2 || c.Unknown != 2 {
		t.Fatalf("totaux : %+v", c)
	}
	if len(c.Gaps) != 4 {
		t.Fatalf("une ligne par raison et par nom : %+v", c.Gaps)
	}
	top := c.Gaps[0]
	if top.Name != "vaultwarden" || top.Reason != appinv.CoverageNoCPE || top.Entries != 2 || len(top.Hosts) != 2 || top.Hosts[0] != "d.test" {
		t.Errorf("le plus fréquent d'abord : %+v", top)
	}
	names := map[string]string{}
	for _, g := range c.Gaps {
		names[g.Name] = g.Reason
	}
	if names["team/app"] != appinv.CoverageUnknown || names["microsoft-httpapi"] != appinv.CoverageUnknown || names["grafana"] != appinv.CoverageNoVersion {
		t.Errorf("raisons : %v", names)
	}
}

func TestOverridesAreStoredAndUsedByTheScan(t *testing.T) {
	s, w, db := newScanWorld(t)
	w.inventory = []logapi.InventoryEntry{entry("vw.test", "http://10.9.0.7:80", appinv.Finding{Product: "vaultwarden", Source: "image", Evidence: "vaultwarden/server:1.30.1"})}
	w.nvd["dani-garcia%3Avaultwarden%3A1.30.1"] = []string{"CVE-2024-9999"}

	s.run(context.Background())
	if st := s.GetState(); st.FoundCVEs != 0 || st.InventoryN != 0 {
		t.Fatalf("sans surcharge, un produit sans CPE n'est pas cherché : %+v", st)
	}

	list, err := ValidateOverrides([]Override{{Match: "vaultwarden", CPE: "dani-garcia:vaultwarden"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveOverrides(context.Background(), db, list); err != nil {
		t.Fatal(err)
	}
	if got := LoadOverrides(context.Background(), db); len(got) != 1 || got[0].CPE != "dani-garcia:vaultwarden" {
		t.Fatalf("relues : %+v", got)
	}
	s.run(context.Background())
	st := s.GetState()
	if st.FoundCVEs != 1 || st.InventoryN != 1 {
		t.Fatalf("avec la surcharge : %+v", st)
	}
	if row := cveRows(t, db)["CVE-2024-9999@http://10.9.0.7:80"]; row != [4]string{"vw.test|vaultwarden", "1.30.1", "image", "open"} {
		t.Errorf("CVE : %v", row)
	}
}

func TestLoadOverridesWithoutSetting(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if got := LoadOverrides(context.Background(), db); len(got) != 0 {
		t.Errorf("aucun réglage : %+v", got)
	}
}
