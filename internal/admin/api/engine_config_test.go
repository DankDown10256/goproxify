// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	admincrowdsec "github.com/vincamok/goproxify/internal/admin/crowdsec"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	adminfleet "github.com/vincamok/goproxify/internal/admin/fleet"
	"github.com/vincamok/goproxify/internal/modules"
)

func newEngineSecurityHandler(t *testing.T) *SecurityHandler {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "eng.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &SecurityHandler{DB: db, Log: log, CrowdSec: admincrowdsec.New(db, log), Fleet: adminfleet.New(db, log)}
}

func engCall(h *SecurityHandler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func TestEngineConfigs_PutValidates(t *testing.T) {
	h := newEngineSecurityHandler(t)
	for name, c := range map[string]struct{ path, body string }{
		"ephor clé inconnue":     {"/api/v1/security/threat-config", `{"enabled":true,"modee":"block"}`},
		"ephor mode":             {"/api/v1/security/threat-config", `{"mode":"off"}`},
		"ephor durée":            {"/api/v1/security/threat-config", `{"ban_duration":"demain"}`},
		"fleet négatif":       {"/api/v1/security/fleet", `{"enabled":true,"max_errors":-1}`},
		"fleet liste blanche": {"/api/v1/security/fleet", `{"whitelist":["nope"]}`},
		"crowdsec URL":           {"/api/v1/security/crowdsec", `{"api_url":"localhost"}`},
		"crowdsec sans clé":      {"/api/v1/security/crowdsec", `{"enabled":true,"api_url":"http://l:8080"}`},
	} {
		if rec := engCall(h, http.MethodPut, c.path, c.body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s : %d (attendu 400) %s", name, rec.Code, rec.Body.String())
		}
	}
	for _, c := range []struct{ path, body string }{
		{"/api/v1/security/threat-config", `{"enabled":true,"mode":"block","ban_duration":"24h","whitelist":{"ips":["10.0.0.0/8"]}}`},
		{"/api/v1/security/fleet", `{"enabled":true,"window_sec":300,"max_errors":50}`},
		{"/api/v1/security/crowdsec", `{"enabled":true,"api_url":"http://l:8080","api_key":"K"}`},
	} {
		if rec := engCall(h, http.MethodPut, c.path, c.body); rec.Code != http.StatusNoContent {
			t.Errorf("%s : %d %s", c.path, rec.Code, rec.Body.String())
		}
	}
}

// GET /security/crowdsec renvoyait la clé d'API du bouncer en clair.
func TestCrowdSecConfig_KeyMaskedAndKept(t *testing.T) {
	h := newEngineSecurityHandler(t)
	if rec := engCall(h, http.MethodPut, "/api/v1/security/crowdsec", `{"enabled":true,"api_url":"http://l:8080","api_key":"BOUNCER-KEY"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT : %d %s", rec.Code, rec.Body.String())
	}
	got := engCall(h, http.MethodGet, "/api/v1/security/crowdsec", "").Body.String()
	if strings.Contains(got, "BOUNCER-KEY") || !strings.Contains(got, modules.Masque) || !strings.Contains(got, "http://l:8080") {
		t.Fatalf("GET = %s", got)
	}
	// L'interface renvoie ce qu'elle a lu (clé masquée), ou omet la clé : la clé enregistrée est conservée.
	for _, body := range []string{
		`{"enabled":true,"api_url":"http://other:8080","api_key":"` + modules.Masque + `"}`,
		`{"enabled":true,"api_url":"http://other:8080"}`,
	} {
		if rec := engCall(h, http.MethodPut, "/api/v1/security/crowdsec", body); rec.Code != http.StatusNoContent {
			t.Fatalf("PUT %s : %d %s", body, rec.Code, rec.Body.String())
		}
		if cfg := h.CrowdSec.GetConfig(); cfg.APIKey != "BOUNCER-KEY" || cfg.APIURL != "http://other:8080" {
			t.Fatalf("config = %+v", cfg)
		}
	}
	var raw string
	_ = h.DB.QueryRow(`SELECT value FROM crowdsec_config WHERE key='config'`).Scan(&raw)
	if !strings.Contains(raw, "BOUNCER-KEY") || strings.Contains(raw, modules.Masque) {
		t.Fatalf("stockage = %s", raw)
	}
}

func TestEngineTypes_Endpoint(t *testing.T) {
	rec := httptest.NewRecorder()
	EngineTypesHandler{}.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/security/engine-types", nil))
	var got []modules.Manifest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 4 {
		t.Fatalf("manifestes = %d, %v", len(got), err)
	}
}

// La simulation refuse une configuration candidate que l'enregistrement refuserait : sinon elle
// simulerait une configuration qui ne peut pas être appliquée.
func TestSimulateEphor_RejectsInvalidCandidate(t *testing.T) {
	h := newEngineSecurityHandler(t)
	for name, cfg := range map[string]map[string]any{
		"clé inconnue": {"modee": "block"},
		"mode":         {"mode": "off"},
		"durée":        {"ban_duration": "demain"},
	} {
		if _, err := SimulateEphor(t.Context(), h.DB, nil, "threat_engine_config", cfg, 1, ""); err == nil {
			t.Errorf("%s : acceptée", name)
		}
	}
	// Une candidate valide passe la validation ; sans passerelle il n'y a ensuite rien à rejouer.
	if _, err := SimulateEphor(t.Context(), h.DB, nil, "threat_engine_config", map[string]any{"enabled": true, "error_threshold": 5}, 1, ""); !errors.Is(err, errNoGatewayToReplay) {
		t.Errorf("candidate valide : %v, attendu l'absence de passerelle", err)
	}
}
