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

const policyJSON = `{"host":"app.test","backends":[{"url":"http://10.0.0.1:80"}],"openapi":{"enabled":true,"mode":"detect","unknown_paths":"allow","spec":{"openapi":"3.1.0","paths":{"/a":{"get":{}}}}}}`

// enforceFixture monte un proxy "p1" avec une politique openapi en detect et une passerelle dont le rapport est celui de rep.
func enforceFixture(t *testing.T, rep surface.Report, cfg string) (*SecurityHandler, *ProxiesHandler, *sql.DB) {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	gw := logapitest.New(t, "paris")
	if rep.Route != "" {
		gw.Reports = map[string]surface.Report{"p1": rep, "app.test": rep}
	}
	if err := gw.Register(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO proxies (id, name, config) VALUES ('p1', 'app.test', ?)`, cfg); err != nil {
		t.Fatal(err)
	}
	ph := &ProxiesHandler{DB: db}
	return &SecurityHandler{DB: db, Edge: &prismedge.Source{DB: db}, Proxies: ph}, ph, db
}

func converged(v ...surface.ViolationInfo) surface.Report {
	totals := map[string]int64{}
	for _, x := range v {
		totals[x.Reason] += x.Count
	}
	var tl []surface.Count
	for k, n := range totals {
		tl = append(tl, surface.Count{Name: k, Count: n})
	}
	return surface.Report{Route: "p1", Host: "app.test", Members: 1, Learned: 5000, Violations: v, ViolationTotals: tl,
		Convergence: surface.Convergence{Converged: true}}
}

func post(t *testing.T, h *SecurityHandler, path string, body any) (int, EnforceResult) {
	t.Helper()
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(body)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, &buf))
	var res EnforceResult
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	return rec.Code, res
}

func storedOpenAPI(t *testing.T, db *sql.DB) map[string]any {
	t.Helper()
	var cfg string
	if err := db.QueryRow(`SELECT config FROM proxies WHERE id='p1'`).Scan(&cfg); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(cfg), &m)
	oa, _ := m["openapi"].(map[string]any)
	return oa
}

func auditCount(t *testing.T, db *sql.DB, action string) int {
	t.Helper()
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=?`, action).Scan(&n)
	return n
}

func TestEnforceRefusedWhileProfileIsNotConverged(t *testing.T) {
	rep := converged()
	rep.Convergence = surface.Convergence{Converged: false, Reasons: []string{"ancienneté 2 j sur 7 j"}}
	h, _, db := enforceFixture(t, rep, policyJSON)
	code, res := post(t, h, "/api/v1/security/surface/enforce?route=p1", EnforceRequest{Reasons: []string{"unknown_path"}})
	if code != http.StatusConflict || res.Applied || len(res.Blockers) != 1 || !strings.Contains(res.Blockers[0], "pas encore fiable") {
		t.Fatalf("profil jeune : %d %+v", code, res)
	}
	if oa := storedOpenAPI(t, db); oa["block_reasons"] != nil || oa["mode"] != "detect" {
		t.Errorf("la configuration a été modifiée malgré le refus : %v", oa)
	}

	// Avec force : appliqué, consigné à l'audit comme tel.
	code, res = post(t, h, "/api/v1/security/surface/enforce?route=p1", EnforceRequest{Reasons: []string{"unknown_path"}, Force: true})
	if code != http.StatusOK || !res.Applied || !res.Forced {
		t.Fatalf("force : %d %+v", code, res)
	}
	if auditCount(t, db, "surface_enforce_forced") != 1 || auditCount(t, db, "surface_enforce") != 0 {
		t.Error("un passage forcé doit être consigné comme tel à l'audit")
	}
}

func TestEnforceAppliesReasonByReason(t *testing.T) {
	rep := converged(
		surface.ViolationInfo{Reason: "unknown_path", Method: "GET", Path: "/wp-login.php", Count: 40, Legit: 0, Clients: 3},
		surface.ViolationInfo{Reason: "invalid_param", Method: "GET", Path: "/a", Count: 5, Legit: 5, Clients: 4},
	)
	h, _, db := enforceFixture(t, rep, policyJSON)

	code, res := post(t, h, "/api/v1/security/surface/enforce?route=app.test", EnforceRequest{Reasons: []string{"unknown_path", "unknown_method"}, DryRun: true})
	if code != http.StatusOK || res.Applied || !res.DryRun || res.UnknownPaths != "block" {
		t.Fatalf("simulation : %d %+v", code, res)
	}
	if oa := storedOpenAPI(t, db); oa["block_reasons"] != nil || oa["unknown_paths"] != "allow" {
		t.Fatalf("une simulation n'écrit rien : %v", oa)
	}

	code, res = post(t, h, "/api/v1/security/surface/enforce?route=app.test", EnforceRequest{Reasons: []string{"unknown_method", "unknown_path", "unknown_path"}})
	if code != http.StatusOK || !res.Applied || res.Forced || res.Route != "p1" {
		t.Fatalf("application : %d %+v", code, res)
	}
	oa := storedOpenAPI(t, db)
	got := strings.Join(strSlice(oa["block_reasons"]), ",")
	if got != "unknown_method,unknown_path" || oa["mode"] != "detect" || oa["unknown_paths"] != "block" {
		t.Errorf("openapi après le passage : %v", oa)
	}
	if oa["spec"] == nil {
		t.Error("la spécification a été perdue")
	}
	if auditCount(t, db, "surface_enforce") != 1 {
		t.Error("le passage en block doit être consigné à l'audit")
	}
	if len(res.Impact) != 2 || res.Impact[1].Reason != "unknown_path" || res.Impact[1].Total != 40 {
		t.Errorf("impact : %+v", res.Impact)
	}

	// Un paramètre invalide qui réussit depuis des clients propres : avertissement, pas de blocage (aucun chemin n'est à ajouter).
	code, res = post(t, h, "/api/v1/security/surface/enforce?route=p1", EnforceRequest{Reasons: []string{"invalid_param"}})
	if code != http.StatusOK || len(res.Warnings) == 0 || !strings.Contains(strings.Join(res.Warnings, " "), "seraient refusées") {
		t.Errorf("paramètres invalides réussis : %d %+v", code, res)
	}
}

func TestEnforceRefusesReasonsWithLikelyLegitPaths(t *testing.T) {
	rep := converged(surface.ViolationInfo{Reason: "unknown_path", Method: "GET", Path: "/nouveau/{int}", Count: 50, Legit: 48, Clients: 9, LikelyLegit: true})
	h, _, db := enforceFixture(t, rep, policyJSON)
	code, res := post(t, h, "/api/v1/security/surface/enforce?route=p1", EnforceRequest{Reasons: []string{"unknown_path"}})
	if code != http.StatusConflict || len(res.Blockers) != 1 || !strings.Contains(res.Blockers[0], "/nouveau/{int}") {
		t.Fatalf("chemin probablement légitime : %d %+v", code, res)
	}
	// Une autre raison, sans chemin à ajouter, n'est pas gênée.
	if code, res = post(t, h, "/api/v1/security/surface/enforce?route=p1", EnforceRequest{Reasons: []string{"too_large"}}); code != http.StatusOK || !res.Applied {
		t.Errorf("autre raison : %d %+v", code, res)
	}
	if oa := storedOpenAPI(t, db); strings.Join(strSlice(oa["block_reasons"]), ",") != "too_large" {
		t.Errorf("openapi : %v", oa)
	}
}

func TestEnforceNeedsAPolicyAndAProfileAndKnownReasons(t *testing.T) {
	h, _, _ := enforceFixture(t, converged(), `{"host":"app.test","backends":[{"url":"http://10.0.0.1:80"}]}`)
	if code, res := post(t, h, "/api/v1/security/surface/enforce?route=p1", EnforceRequest{Reasons: []string{"unknown_path"}, Force: true}); code != http.StatusConflict || !strings.Contains(strings.Join(res.Blockers, ""), "politique openapi") {
		t.Errorf("sans politique (force n'y change rien) : %d %+v", code, res)
	}
	h, _, _ = enforceFixture(t, surface.Report{}, policyJSON)
	if code, res := post(t, h, "/api/v1/security/surface/enforce?route=p1", EnforceRequest{Reasons: []string{"unknown_path"}, Force: true}); code != http.StatusConflict || len(res.Blockers) == 0 {
		t.Errorf("sans profil : %d %+v", code, res)
	}
	h, _, _ = enforceFixture(t, converged(), policyJSON)
	for _, bad := range [][]string{nil, {"inconnue"}} {
		if code, _ := post(t, h, "/api/v1/security/surface/enforce?route=p1", EnforceRequest{Reasons: bad}); code != http.StatusBadRequest {
			t.Errorf("raisons %v : %d, attendu 400", bad, code)
		}
	}
	if code, _ := post(t, h, "/api/v1/security/surface/enforce", EnforceRequest{Reasons: []string{"unknown_path"}}); code != http.StatusBadRequest {
		t.Errorf("sans route : %d", code)
	}
	h.Proxies = nil
	if code, _ := post(t, h, "/api/v1/security/surface/enforce?route=p1", EnforceRequest{Reasons: []string{"unknown_path"}}); code != http.StatusNotImplemented {
		t.Errorf("sans écriture de proxy : %d", code)
	}
}

func TestRelaxGoesBackToDetect(t *testing.T) {
	cfg := strings.Replace(policyJSON, `"mode":"detect"`, `"mode":"block","block_reasons":["unknown_path"]`, 1)
	h, _, db := enforceFixture(t, converged(), cfg)
	code, res := post(t, h, "/api/v1/security/surface/relax?route=app.test", nil)
	if code != http.StatusOK || !res.Applied || res.Mode != "detect" {
		t.Fatalf("relax : %d %+v", code, res)
	}
	if oa := storedOpenAPI(t, db); oa["mode"] != "detect" || oa["block_reasons"] != nil || oa["spec"] == nil {
		t.Errorf("openapi après relax : %v", oa)
	}
	if auditCount(t, db, "surface_relax") != 1 {
		t.Error("le retour en detect doit être consigné à l'audit")
	}
	h2, _, _ := enforceFixture(t, converged(), `{"host":"app.test","backends":[{"url":"http://10.0.0.1:80"}]}`)
	if code, _ := post(t, h2, "/api/v1/security/surface/relax?route=p1", nil); code != http.StatusConflict {
		t.Errorf("relax sans politique : %d", code)
	}
}
