// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/domainwatch"
)

type noCT struct{}

func (noCT) Fetch(context.Context, string, string) ([]domainwatch.CTEntry, error) { return nil, nil }

type noDNS struct{}

func (noDNS) CAA(context.Context, string) ([]domainwatch.CAARecord, error) { return nil, nil }
func (noDNS) Dangling(context.Context, string) (string, error)             { return "", nil }

func domainWatchHandler(t *testing.T) *SecurityHandler {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := domainwatch.Migrate(db); err != nil {
		t.Fatal(err)
	}
	w := &domainwatch.Watcher{DB: db, CT: noCT{}, DNS: func(string) (domainwatch.DNSClient, error) { return noDNS{}, nil },
		CheckURL: func(string) error { return nil }}
	return &SecurityHandler{DB: db, DomainWatch: w}
}

func dwCall(t *testing.T, h *SecurityHandler, method, target, body string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, strings.NewReader(body)))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestDomainWatchIsOffByDefaultAndConfigurable(t *testing.T) {
	h := domainWatchHandler(t)
	code, out := dwCall(t, h, http.MethodGet, "/api/v1/security/domain-watch", "")
	cfg, _ := out["config"].(map[string]any)
	if code != http.StatusOK || cfg["enabled"] != false || cfg["ct"] != false || cfg["caa"] != false || cfg["dangling"] != false {
		t.Fatalf("tout est désactivé par défaut : %d %v", code, out)
	}
	if code, _ = dwCall(t, h, http.MethodPut, "/api/v1/security/domain-watch", `{"enabled":true,"caa":true,"interval_hours":12}`); code != http.StatusNoContent {
		t.Fatalf("enregistrement : %d", code)
	}
	_, out = dwCall(t, h, http.MethodGet, "/api/v1/security/domain-watch", "")
	if cfg = out["config"].(map[string]any); cfg["enabled"] != true || cfg["caa"] != true || cfg["ct"] != false || cfg["interval_hours"] != float64(12) {
		t.Fatalf("config relue : %v", cfg)
	}
}

func TestDomainWatchRefusesBadConfigs(t *testing.T) {
	h := domainWatchHandler(t)
	for name, body := range map[string]string{
		"cadence":             `{"interval_hours":1}`,
		"journal en clair":    `{"ct_endpoint":"http://crt.sh"}`,
		"champ inconnu":       `{"enabled":true,"surprise":1}`,
		"résolveur sans port": `{"resolver":"9.9.9.9"}`,
	} {
		if code, _ := dwCall(t, h, http.MethodPut, "/api/v1/security/domain-watch", body); code != http.StatusBadRequest {
			t.Errorf("%s : %d, attendu 400", name, code)
		}
	}
}

func TestDomainWatchRunNeedsAnActiveCheckAndIsRateLimited(t *testing.T) {
	h := domainWatchHandler(t)
	if code, _ := dwCall(t, h, http.MethodPost, "/api/v1/security/domain-watch/run", ""); code != http.StatusConflict {
		t.Fatalf("désactivée : %d, attendu 409", code)
	}
	dwCall(t, h, http.MethodPut, "/api/v1/security/domain-watch", `{"enabled":true,"dangling":true}`)
	if code, _ := dwCall(t, h, http.MethodPost, "/api/v1/security/domain-watch/run", ""); code != http.StatusAccepted {
		t.Fatalf("analyse à la demande : %d, attendu 202", code)
	}
	if code, _ := dwCall(t, h, http.MethodPost, "/api/v1/security/domain-watch/run", ""); code != http.StatusTooManyRequests {
		t.Fatalf("une toutes les cinq minutes : %d, attendu 429", code)
	}
}

func TestDomainWatchAcceptNeedsAnExistingFinding(t *testing.T) {
	h := domainWatchHandler(t)
	if code, _ := dwCall(t, h, http.MethodPost, "/api/v1/security/domain-watch/accept", `{"domain":"a.example.fr","check":"ct","key":"abc"}`); code != http.StatusNotFound {
		t.Fatalf("rien à reconnaître : %d, attendu 404", code)
	}
	if _, err := h.DB.Exec(`INSERT INTO domain_watch (domain, check_name, key, status, severity, detail, first_seen, last_seen) VALUES ('a.example.fr','ct','abc','open','critical','{}',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if code, _ := dwCall(t, h, http.MethodPost, "/api/v1/security/domain-watch/accept", `{"domain":"a.example.fr","check":"ct","key":"abc"}`); code != http.StatusNoContent {
		t.Fatalf("reconnaître : %d", code)
	}
	_, out := dwCall(t, h, http.MethodGet, "/api/v1/security/domain-watch", "")
	if out["open"] != float64(0) {
		t.Fatalf("plus aucun constat ouvert : %v", out["open"])
	}
	if code, _ := dwCall(t, h, http.MethodPost, "/api/v1/security/domain-watch/accept", `{}`); code != http.StatusBadRequest {
		t.Fatalf("corps vide : %d", code)
	}
}

func TestDomainWatchUnavailableWithoutAWatcher(t *testing.T) {
	h := domainWatchHandler(t)
	h.DomainWatch = nil
	if code, _ := dwCall(t, h, http.MethodGet, "/api/v1/security/domain-watch", ""); code != http.StatusServiceUnavailable {
		t.Fatalf("sans surveillant : %d", code)
	}
}
