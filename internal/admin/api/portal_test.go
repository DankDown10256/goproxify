// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/core/portal"
)

func TestLoadPortalConfigPerCore(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "portal.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	a := PortalConfig{Enabled: true, PublicHost: "a.example", SSHPort: 2222, HTTPPort: 8444}
	b := PortalConfig{Enabled: false, PublicHost: "b.example", SSHPort: 2223, HTTPPort: 8445}
	ra, _ := json.Marshal(a)
	rb, _ := json.Marshal(b)
	_ = admindb.SetSetting(db, settingPortalConfigPrefix+"core-a", string(ra))
	_ = admindb.SetSetting(db, settingPortalConfigPrefix+"core-b", string(rb))

	gotA := loadPortalConfig(db, "core-a")
	gotB := loadPortalConfig(db, "core-b")
	if !gotA.Enabled || gotA.PublicHost != "a.example" || gotA.CoreName != "core-a" {
		t.Fatalf("core-a: %+v", gotA)
	}
	if gotB.Enabled || gotB.PublicHost != "b.example" || gotB.SSHPort != 2223 {
		t.Fatalf("core-b: %+v", gotB)
	}
}

func TestLoadPortalConfigLegacyFallback(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "portal-leg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	legacy := PortalConfig{Enabled: true, PublicHost: "legacy.example"}
	raw, _ := json.Marshal(legacy)
	_ = admindb.SetSetting(db, settingPortalConfigLegacy, string(raw))

	got := loadPortalConfig(db, "core-new")
	if !got.Enabled || got.PublicHost != "legacy.example" || got.CoreName != "core-new" {
		t.Fatalf("%+v", got)
	}
}

func TestPortalDestinationsCRUDAndCatalog(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "portal-dest.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	h := &PortalHandler{DB: db, Log: nil}
	d := PortalDestination{
		CoreName: "core-a", Kind: "ssh", Name: "vm1", Host: "10.0.0.1", Port: 22,
		Tags: []string{"Prod", "prod", " db "},
	}
	if err := validateDestination(&d); err != nil {
		t.Fatal(err)
	}
	tags, _ := json.Marshal(d.Tags)
	d.ID = "d1"
	_, err = db.Exec(`INSERT INTO portal_destinations
		(id, core_name, kind, name, host, port, agent_name, container, tags_json, enabled)
		VALUES (?,?,?,?,?,?,?,?,?,1)`,
		d.ID, d.CoreName, d.Kind, d.Name, d.Host, d.Port, "", "", string(tags))
	if err != nil {
		t.Fatal(err)
	}

	_ = admindb.SetSetting(db, settingPortalConfigPrefix+"core-a", `{"enabled":true,"public_host":"p.example"}`)
	cfg := loadPortalConfig(db, "core-a")
	if len(cfg.Catalog) != 1 || cfg.Catalog[0].Name != "vm1" {
		t.Fatalf("catalog: %+v", cfg.Catalog)
	}
	if len(cfg.Catalog[0].Tags) != 2 { // prod, db
		t.Fatalf("tags: %v", cfg.Catalog[0].Tags)
	}

	all := listDestinationsAsCatalog(db, "core-b")
	if all == nil {
		all = []portal.CatalogTarget{}
	}
	if len(all) != 0 {
		t.Fatalf("core-b should be empty: %v", all)
	}
	_ = h // keep handler for future HTTP tests
}

func TestMigrateLegacyCatalog(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "portal-mig.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	raw := `{"enabled":true,"catalog":[{"id":"c1","name":"old","kind":"ssh","host":"1.1.1.1","port":22,"tags":["x"]}]}`
	_ = admindb.SetSetting(db, settingPortalConfigPrefix+"core-m", raw)
	cfg := loadPortalConfig(db, "core-m")
	if len(cfg.Catalog) != 1 || cfg.Catalog[0].ID != "c1" {
		t.Fatalf("%+v", cfg.Catalog)
	}
	// second load must not duplicate
	cfg2 := loadPortalConfig(db, "core-m")
	if len(cfg2.Catalog) != 1 {
		t.Fatalf("dup: %+v", cfg2.Catalog)
	}
}

func TestPreviewDestinationsFilter(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "portal-prev.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, _ = db.Exec(`INSERT INTO portal_destinations
		(id, core_name, kind, name, host, port, agent_name, container, tags_json, enabled)
		VALUES
		('d1','core-a','ssh','pub','1.1.1.1',22,'','','[]',1),
		('d2','core-a','ssh','prod','1.1.1.2',22,'','','["prod"]',1),
		('d3','core-a','ssh','dev','1.1.1.3',22,'','','["dev"]',1)`)

	h := &PortalHandler{DB: db, Log: nil}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/portal/destinations/preview?core=core-a&tags=prod", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d %s", rr.Code, rr.Body.String())
	}
	var out struct {
		VisibleN int `json:"visible_n"`
		HiddenN  int `json:"hidden_n"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out.VisibleN != 2 || out.HiddenN != 1 {
		t.Fatalf("%+v body=%s", out, rr.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/portal/destinations/preview?core=core-a&tags=", nil)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	_ = json.Unmarshal(rr2.Body.Bytes(), &out)
	if out.VisibleN != 1 || out.HiddenN != 2 {
		t.Fatalf("user sans tags: %+v", out)
	}
}
