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
	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/logapi/logapitest"
	"github.com/vincamok/goproxify/internal/edge/surface"
)

func surfaceHandler(t *testing.T) (*SecurityHandler, *logapitest.Gateway, *logapitest.Gateway) {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	paris, lyon := logapitest.New(t, "paris"), logapitest.New(t, "lyon")
	paris.Surface = logapi.SurfaceListResponse{Proxies: []surface.Summary{{Route: "p1", Host: "app.test", Mode: "learn", Learned: 1200, Templates: 14}}}
	paris.Reports = map[string]surface.Report{"p1": {Route: "p1", Host: "app.test", Mode: "learn", Members: 2, Learned: 1200,
		Templates: []surface.TemplateInfo{{Path: "/api/users/{int}", Requests: 900}}}}
	lyon.Surface = logapi.SurfaceListResponse{Proxies: []surface.Summary{}}
	lyon.Reports = map[string]surface.Report{}
	for _, g := range []*logapitest.Gateway{paris, lyon} {
		if err := g.Register(db); err != nil {
			t.Fatal(err)
		}
	}
	return &SecurityHandler{DB: db, Edge: &prismedge.Source{DB: db}}, paris, lyon
}

func surfCall(t *testing.T, h *SecurityHandler, method, target string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestSurfaceIsReadFromEachGateway(t *testing.T) {
	h, _, _ := surfaceHandler(t)
	code, out := surfCall(t, h, http.MethodGet, "/api/v1/security/surface")
	if code != http.StatusOK {
		t.Fatalf("liste : %d %v", code, out)
	}
	gws := out["gateways"].([]any)
	if len(gws) != 2 {
		t.Fatalf("une entrée par passerelle : %v", gws)
	}
	code, out = surfCall(t, h, http.MethodGet, "/api/v1/security/surface?edge=paris")
	if gws = out["gateways"].([]any); code != 200 || len(gws) != 1 || gws[0].(map[string]any)["node_name"] != "paris" {
		t.Fatalf("edge=paris : %d %v", code, out)
	}
}

func TestSurfaceReportAndMissingProfile(t *testing.T) {
	h, _, _ := surfaceHandler(t)
	if code, _ := surfCall(t, h, http.MethodGet, "/api/v1/security/surface/report"); code != http.StatusBadRequest {
		t.Errorf("sans route : %d", code)
	}
	code, out := surfCall(t, h, http.MethodGet, "/api/v1/security/surface/report?route=p1")
	if code != http.StatusOK {
		t.Fatalf("rapport : %d %v", code, out)
	}
	byNode := map[string]any{}
	for _, g := range out["gateways"].([]any) {
		gw := g.(map[string]any)
		byNode[gw["node_name"].(string)] = gw["report"]
	}
	if byNode["lyon"] != nil {
		t.Errorf("Lyon n'a pas de profil : son rapport doit être nul, reçu %v", byNode["lyon"])
	}
	rep, _ := byNode["paris"].(map[string]any)
	if rep == nil || rep["learned"].(float64) != 1200 || rep["members"].(float64) != 2 {
		t.Errorf("rapport de Paris : %v", byNode["paris"])
	}
	if _, partial := out["partial"]; partial {
		t.Errorf("un proxy sans profil n'est pas une panne : %v", out)
	}
}

func TestSurfaceResetReachesEveryGateway(t *testing.T) {
	h, paris, lyon := surfaceHandler(t)
	if code, _ := surfCall(t, h, http.MethodPost, "/api/v1/security/surface/reset"); code != http.StatusBadRequest {
		t.Errorf("sans route : %d", code)
	}
	code, out := surfCall(t, h, http.MethodPost, "/api/v1/security/surface/reset?route=p1")
	if code != http.StatusOK {
		t.Fatalf("reset : %d %v", code, out)
	}
	if len(paris.Resets) != 1 || len(lyon.Resets) != 1 {
		t.Errorf("chaque membre d'un groupe doit être remis à zéro : Paris %v, Lyon %v", paris.Resets, lyon.Resets)
	}
}

func TestSurfaceWithoutGateway(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := &SecurityHandler{DB: db, Edge: &prismedge.Source{DB: db}}
	if code, _ := surfCall(t, h, http.MethodGet, "/api/v1/security/surface"); code == http.StatusOK {
		t.Error("sans passerelle il n'y a rien à lire")
	}
}

func TestSurfaceProposalsAreReadFromEachGateway(t *testing.T) {
	h, paris, _ := surfaceHandler(t)
	paris.Proposals = map[string]surface.Proposals{"p1": {
		Route: "p1", Host: "app.test", Learned: 1200,
		Items:   []surface.Proposal{{Setting: surface.SettingMaxBody, Option: "max_body_size", Command: "goproxify proxy option p1 max_body_size '16384'", Measured: true, Of: 1200}},
		Skipped: []surface.Skipped{{Setting: surface.SettingCORS, Reason: "aucune requête venant d'une autre origine"}},
	}}
	if code, _ := surfCall(t, h, http.MethodGet, "/api/v1/security/surface/proposals"); code != http.StatusBadRequest {
		t.Errorf("sans route : %d", code)
	}
	code, out := surfCall(t, h, http.MethodGet, "/api/v1/security/surface/proposals?route=p1")
	if code != http.StatusOK {
		t.Fatalf("propositions : %d %v", code, out)
	}
	byNode := map[string]any{}
	for _, g := range out["gateways"].([]any) {
		gw := g.(map[string]any)
		byNode[gw["node_name"].(string)] = gw["proposals"]
	}
	if byNode["lyon"] != nil {
		t.Errorf("Lyon n'a pas de profil : %v", byNode["lyon"])
	}
	pr, _ := byNode["paris"].(map[string]any)
	items, _ := pr["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["setting"] != "max_body_size" || pr["learned"].(float64) != 1200 {
		t.Errorf("propositions de Paris : %v", byNode["paris"])
	}
	if _, partial := out["partial"]; partial {
		t.Errorf("un proxy sans profil n'est pas une panne : %v", out)
	}
}

func TestSurfaceOpenAPIIsReadFromEachGateway(t *testing.T) {
	h, paris, _ := surfaceHandler(t)
	paris.OpenAPI = map[string]surface.OpenAPIResult{"p1": {
		Route: "p1", Host: "app.test", Members: 2, Paths: 4, Operations: 5, Ready: false,
		Config:   json.RawMessage(`{"enabled":true,"mode":"detect","unknown_paths":"block","spec":{"openapi":"3.1.0","paths":{}}}`),
		Excluded: []surface.ExcludedPath{{Path: "/rare", Reason: "faible soutien"}},
	}}
	if code, _ := surfCall(t, h, http.MethodGet, "/api/v1/security/surface/openapi"); code != http.StatusBadRequest {
		t.Errorf("sans route : %d", code)
	}
	code, out := surfCall(t, h, http.MethodGet, "/api/v1/security/surface/openapi?route=p1")
	if code != http.StatusOK {
		t.Fatalf("openapi : %d %v", code, out)
	}
	byNode := map[string]any{}
	for _, g := range out["gateways"].([]any) {
		gw := g.(map[string]any)
		byNode[gw["node_name"].(string)] = gw["openapi"]
	}
	if byNode["lyon"] != nil {
		t.Errorf("Lyon n'a pas de profil : %v", byNode["lyon"])
	}
	pr, _ := byNode["paris"].(map[string]any)
	cfg, _ := pr["config"].(map[string]any)
	if pr["paths"].(float64) != 4 || cfg["mode"] != "detect" || cfg["unknown_paths"] != "block" {
		t.Errorf("politique de Paris : %v", byNode["paris"])
	}
}
