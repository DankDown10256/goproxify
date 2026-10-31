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
	"github.com/vincamok/goproxify/internal/admin/logs"
)

// La conservation du volume de logs de l'Admin se règle (accès et système), est validée, enregistrée, auditée et appliquée.
func TestVaultRetentionSettingIsValidatedSavedAuditedAndApplied(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var applied [2]int
	h := &LogsHandler{DB: db, Store: logs.New(db), OnVaultRetention: func(a, s int) { applied = [2]int{a, s} }}
	do := func(method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/v1/logs/settings", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	view := func() (v struct {
		VaultRetention struct {
			AccessDays int            `json:"access_days"`
			SystemDays int            `json:"system_days"`
			Defaults   map[string]int `json:"defaults"`
		} `json:"vault_retention"`
	}) {
		rec := do(http.MethodGet, "")
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &v) != nil {
			t.Fatalf("GET : %d %s", rec.Code, rec.Body)
		}
		return v
	}

	if v := view(); v.VaultRetention.AccessDays != 365 || v.VaultRetention.SystemDays != 90 || v.VaultRetention.Defaults["access_days"] != 365 {
		t.Fatalf("avant réglage : %+v", v.VaultRetention)
	}
	for name, body := range map[string]string{
		"zéro":      `{"vault_retention":{"access_days":0,"system_days":90}}`,
		"trop long": `{"vault_retention":{"access_days":4000,"system_days":90}}`,
		"système":   `{"vault_retention":{"access_days":30,"system_days":-1}}`,
	} {
		if rec := do(http.MethodPut, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s : %d", name, rec.Code)
		}
	}
	if applied != [2]int{} {
		t.Fatalf("une valeur refusée a été appliquée : %v", applied)
	}
	if rec := do(http.MethodPut, `{"vault_retention":{"access_days":400,"system_days":30}}`); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT : %d %s", rec.Code, rec.Body)
	}
	if applied != [2]int{400, 30} {
		t.Errorf("conservation appliquée = %v, attendu [400 30]", applied)
	}
	if v := view(); v.VaultRetention.AccessDays != 400 || v.VaultRetention.SystemDays != 30 {
		t.Errorf("après réglage : %+v", v.VaultRetention)
	}
	var audits int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'logs_vault_retention'`).Scan(&audits); err != nil || audits != 1 {
		t.Errorf("audit logs_vault_retention : %d, %v", audits, err)
	}
	if got := LoadVaultRetention(db); got.AccessDays != 400 {
		t.Errorf("LoadVaultRetention = %+v", got)
	}
}
