// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/appinv"
	"github.com/vincamok/goproxify/internal/edge/logapi"
)

func TestInventoryIsReadFromEachGateway(t *testing.T) {
	h, paris, _ := surfaceHandler(t)
	paris.Inventory = []logapi.InventoryEntry{
		{Route: "p1", Host: "blog.test", Backend: "http://10.0.0.1:80", Container: "c1",
			Finding: appinv.Finding{Product: "wordpress", CPE: "wordpress:wordpress", Version: "6.4.2", Source: "image", Evidence: "wordpress:6.4.2-apache"}},
		{Route: "p2", Host: "git.test", Backend: "http://10.0.0.2:3000", Finding: appinv.Finding{Source: "image", Evidence: "team/gitea-fork:1"}},
	}
	code, out := surfCall(t, h, http.MethodGet, "/api/v1/security/inventory")
	if code != http.StatusOK || len(out["gateways"].([]any)) != 2 {
		t.Fatalf("liste : %d %v", code, out)
	}
	code, out = surfCall(t, h, http.MethodGet, "/api/v1/security/inventory?route=blog.test&edge=paris")
	gws := out["gateways"].([]any)
	if code != http.StatusOK || len(gws) != 1 {
		t.Fatalf("par proxy : %d %v", code, out)
	}
	entries := gws[0].(map[string]any)["entries"].([]any)
	e := entries[0].(map[string]any)
	if len(entries) != 1 || e["product"] != "wordpress" || e["version"] != "6.4.2" || e["cpe"] != "wordpress:wordpress" || e["evidence"] != "wordpress:6.4.2-apache" {
		t.Errorf("entrée : %v", entries)
	}
}

func TestInventoryCoverageAndCPEOverrides(t *testing.T) {
	h, paris, _ := surfaceHandler(t)
	paris.Inventory = []logapi.InventoryEntry{
		{Route: "p1", Host: "vw.test", Backend: "http://10.0.0.1:80", Finding: appinv.Finding{Product: "vaultwarden", Source: "image", Evidence: "vaultwarden/server:1.30.1"}},
		{Route: "p2", Host: "wp.test", Backend: "http://10.0.0.2:80", Finding: appinv.Finding{Product: "wordpress", CPE: "wordpress:wordpress", Version: "6.4.2", Source: "image", Evidence: "wordpress:6.4.2"}},
	}
	cov := func() map[string]any {
		_, out := surfCall(t, h, http.MethodGet, "/api/v1/security/inventory")
		return out["coverage"].(map[string]any)
	}
	if c := cov(); c["total"].(float64) != 2 || c["covered"].(float64) != 1 || c["no_cpe"].(float64) != 1 {
		t.Fatalf("avant surcharge : %v", c)
	}
	put := func(body string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/v1/security/cpe-overrides", strings.NewReader(body)))
		return rec.Code
	}
	if code := put(`{"overrides":[{"match":"vaultwarden","cpe":"pas un cpe"}]}`); code != http.StatusBadRequest {
		t.Errorf("un CPE mal formé est refusé : %d", code)
	}
	if code := put(`{"overrides":[{"match":"Vaultwarden","cpe":"dani-garcia:vaultwarden"}]}`); code != http.StatusNoContent {
		t.Fatalf("enregistrement : %d", code)
	}
	code, got := surfCall(t, h, http.MethodGet, "/api/v1/security/cpe-overrides")
	ov := got["overrides"].([]any)
	if code != http.StatusOK || len(ov) != 1 || ov[0].(map[string]any)["match"] != "vaultwarden" {
		t.Fatalf("relecture : %d %v", code, got)
	}
	if c := cov(); c["covered"].(float64) != 2 || c["no_cpe"].(float64) != 0 || len(c["gaps"].([]any)) != 0 {
		t.Errorf("après surcharge, plus rien n'est non couvert : %v", c)
	}
}
