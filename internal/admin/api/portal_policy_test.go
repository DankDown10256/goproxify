// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/portal"
)

func TestPortalPolicyPutGetAndSurvivesSettingsSave(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rec := &pushRecorder{}
	h := &PortalHandler{DB: db, Pusher: rec}

	do := func(method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		return w
	}

	bad := `{"hours_enabled":true,"days":[1],"start_time":"20:00","end_time":"07:00"}`
	if w := do(http.MethodPut, "/api/v1/portal/policy?edge=edge-a", bad); w.Code != http.StatusBadRequest {
		t.Fatalf("politique invalide acceptée: %d", w.Code)
	}
	good := `{"hours_enabled":true,"days":[1,2,3],"start_time":"07:00","end_time":"20:00","timezone":"Europe/Paris","ip_allow":["10.0.0.0/8"],"idle_timeout_min":15}`
	if w := do(http.MethodPut, "/api/v1/portal/policy?edge=edge-a", good); w.Code != http.StatusOK {
		t.Fatalf("put: %d %s", w.Code, w.Body.String())
	}
	if len(rec.pushed) != 1 {
		t.Fatalf("push attendu: %v", rec.pushed)
	}

	var p portal.Policy
	w := do(http.MethodGet, "/api/v1/portal/policy?edge=edge-a", "")
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || p.IdleTimeoutMin != 15 || len(p.IPAllow) != 1 {
		t.Fatalf("get: %v %s", err, w.Body.String())
	}

	// Le formulaire Réglages ne connaît pas la politique : il ne doit pas l'effacer.
	if w := do(http.MethodPut, "/api/v1/portal?edge=edge-a", `{"enabled":true,"public_host":"x.example"}`); w.Code != http.StatusOK {
		t.Fatalf("put réglages: %d", w.Code)
	}
	w = do(http.MethodGet, "/api/v1/portal/policy?edge=edge-a", "")
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil || p.IdleTimeoutMin != 15 {
		t.Fatalf("politique perdue après Réglages: %s", w.Body.String())
	}

	if cfg := BuildPortalPayload(db, nil, "edge-a"); cfg.Policy == nil || cfg.Policy.IdleTimeoutMin != 15 {
		t.Fatalf("payload sans politique: %+v", cfg.Policy)
	}
	if w := do(http.MethodGet, "/api/v1/portal/policy", ""); w.Code != http.StatusBadRequest {
		t.Fatalf("edge manquant: %d", w.Code)
	}
}
