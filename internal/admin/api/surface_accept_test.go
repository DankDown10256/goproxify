// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/edge/logapi/logapitest"
	"github.com/vincamok/goproxify/internal/edge/surface"
)

func acceptFixture(t *testing.T, sugg []surface.Suggestion, cfg string) (*SecurityHandler, *logapitest.Gateway, *sql.DB) {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	gw := logapitest.New(t, "paris")
	rep := converged()
	rep.Suggestions = sugg
	gw.Reports = map[string]surface.Report{"p1": rep, "app.test": rep}
	if err := gw.Register(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO proxies (id, name, config) VALUES ('p1', 'app.test', ?)`, cfg); err != nil {
		t.Fatal(err)
	}
	return &SecurityHandler{DB: db, Edge: &prismedge.Source{DB: db}, Proxies: &ProxiesHandler{DB: db}}, gw, db
}

func postAccept(t *testing.T, h *SecurityHandler, query string, body any) (int, AcceptResult) {
	t.Helper()
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/security/surface/accept"+query, &buf))
	var res AcceptResult
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	return rec.Code, res
}

func sugg(key, conf, method, path string) surface.Suggestion {
	reason := "unknown_path"
	if i := strings.IndexByte(key, ' '); i > 0 {
		reason = key[:i]
	}
	return surface.Suggestion{Key: key, Reason: reason, Method: method, Path: path, Confidence: conf, Count: 30}
}

func TestSuggestionsAreReadFromTheProfile(t *testing.T) {
	h, _, _ := acceptFixture(t, []surface.Suggestion{sugg("unknown_path GET /nouveau/{int}", "high", "GET", "/nouveau/{int}")}, policyJSON)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/security/surface/suggestions?route=p1", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var out struct {
		Gateways []GatewaySuggestions `json:"gateways"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Gateways) != 1 || len(out.Gateways[0].Suggestions) != 1 || !out.Gateways[0].Converged {
		t.Errorf("suggestions : %+v", out)
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/security/surface/suggestions", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("sans route : %d", rec.Code)
	}
}

func TestAcceptAddsToThePolicyAndForgetsTheViolations(t *testing.T) {
	cfg := strings.Replace(policyJSON, `"spec":{"openapi":"3.1.0","paths":{"/a":{"get":{}}}}`, `"spec":"{\"openapi\":\"3.1.0\",\"paths\":{\"/a\":{\"get\":{}}}}"`, 1)
	h, gw, db := acceptFixture(t, []surface.Suggestion{
		sugg("unknown_path GET /nouveau/{int}", "high", "GET", "/nouveau/{int}"),
		sugg("unknown_method POST /a", "high", "POST", "/a"),
		sugg("unknown_path GET /rapports/{int}", "low", "GET", "/rapports/{int}"),
	}, cfg)

	// Une simulation n'écrit rien.
	code, res := postAccept(t, h, "?route=app.test", AcceptRequest{AllHigh: true, DryRun: true})
	if code != http.StatusOK || res.Applied || !res.DryRun || len(res.Added) != 2 || !strings.Contains(string(res.Spec), "/nouveau/{nouveau_id}") {
		t.Fatalf("simulation : %d %+v", code, res)
	}
	if len(gw.Forgotten) != 0 {
		t.Error("une simulation ne doit rien effacer")
	}

	// all_high ne prend que la confiance haute ; la basse demande d'être nommée.
	code, res = postAccept(t, h, "?route=app.test", AcceptRequest{AllHigh: true, Keys: []string{"unknown_path GET /rapports/{int}", "unknown_path GET /inconnue"}})
	if code != http.StatusOK || !res.Applied || len(res.Added) != 3 || len(res.Skipped) != 1 || !strings.Contains(res.Skipped[0].Reason, "pas (ou plus)") {
		t.Fatalf("acceptation : %d %+v", code, res)
	}
	oa := storedOpenAPI(t, db)
	spec, ok := oa["spec"].(map[string]any)
	if !ok {
		t.Fatalf("la spécification doit être un objet JSON après l'ajout : %T", oa["spec"])
	}
	paths := spec["paths"].(map[string]any)
	if _, ok := paths["/a"].(map[string]any)["post"]; !ok || paths["/a"].(map[string]any)["get"] == nil {
		t.Errorf("/a doit garder get et recevoir post : %v", paths["/a"])
	}
	if paths["/nouveau/{nouveau_id}"] == nil || paths["/rapports/{rapports_id}"] == nil {
		t.Errorf("chemins : %v", paths)
	}
	if oa["mode"] != "detect" || oa["unknown_paths"] != "allow" {
		t.Errorf("le reste du réglage openapi ne doit pas bouger : %v", oa)
	}
	if len(gw.Forgotten) != 3 || res.Forgotten != 3 {
		t.Errorf("violations effacées : %v (%d)", gw.Forgotten, res.Forgotten)
	}
	if auditCount(t, db, "surface_accept") != 1 {
		t.Error("l'ajout doit être consigné à l'audit")
	}

	// Rejouer la même demande : la politique couvre déjà ce chemin, rien n'est ajouté, mais son compte périmé est effacé.
	code, res = postAccept(t, h, "?route=app.test", AcceptRequest{Keys: []string{"unknown_path GET /nouveau/{int}"}})
	if code != http.StatusOK || len(res.Added) != 0 || len(res.Skipped) != 1 || res.Skipped[0].Reason != "déjà dans la politique" || res.Forgotten != 1 {
		t.Errorf("déjà ajoutée : %d %+v", code, res)
	}
}

func TestAcceptRefusals(t *testing.T) {
	one := []surface.Suggestion{sugg("unknown_path GET /nouveau/{int}", "high", "GET", "/nouveau/{int}")}
	h, _, db := acceptFixture(t, one, `{"host":"app.test","backends":[{"url":"http://10.0.0.1:80"}]}`)
	if code, res := postAccept(t, h, "?route=p1", AcceptRequest{AllHigh: true}); code != http.StatusConflict || !strings.Contains(strings.Join(res.Blockers, ""), "politique openapi") {
		t.Errorf("sans politique : %d %+v", code, res)
	}

	yaml := strings.Replace(policyJSON, `"spec":{"openapi":"3.1.0","paths":{"/a":{"get":{}}}}`, `"spec":"openapi: 3.1.0\npaths:\n  /a:\n    get: {}\n"`, 1)
	h, _, db = acceptFixture(t, one, yaml)
	code, res := postAccept(t, h, "?route=p1", AcceptRequest{AllHigh: true})
	if code != http.StatusConflict || !strings.Contains(strings.Join(res.Blockers, ""), "YAML") {
		t.Errorf("spécification YAML : %d %+v", code, res)
	}
	if oa := storedOpenAPI(t, db); oa["spec"] == nil {
		t.Error("la spécification YAML ne doit pas être touchée")
	}

	h, _, _ = acceptFixture(t, one, policyJSON)
	if code, _ := postAccept(t, h, "?route=p1", AcceptRequest{}); code != http.StatusBadRequest {
		t.Errorf("sans clé ni all_high : %d", code)
	}
	if code, res := postAccept(t, h, "?route=p1", AcceptRequest{Keys: []string{"unknown_path GET /x"}}); code != http.StatusConflict || len(res.Skipped) != 1 {
		t.Errorf("clé qui n'est pas une suggestion : %d %+v", code, res)
	}
	if code, _ := postAccept(t, h, "", AcceptRequest{AllHigh: true}); code != http.StatusBadRequest {
		t.Errorf("sans route : %d", code)
	}
}
