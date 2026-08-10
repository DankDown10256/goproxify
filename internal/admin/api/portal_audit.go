// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"
)

// PortalAuditEntry row Admin (métadonnées uniquement).
type PortalAuditEntry struct {
	ID       int64  `json:"id"`
	CoreName string `json:"core_name"`
	Ts       string `json:"ts"`
	Actor    string `json:"actor"`
	TargetID string `json:"target_id"`
	Facade   string `json:"facade"`
	Success  bool   `json:"success"`
	Detail   string `json:"detail,omitempty"`
}

func (h *PortalHandler) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
		return
	}
	core := portalCoreParam(r)
	limit := 100
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	q := `SELECT id, core_name, ts, actor, target_id, facade, success, detail FROM portal_audit`
	var rows *sql.Rows
	var err error
	if core != "" {
		rows, err = h.DB.Query(q+` WHERE core_name=? ORDER BY id DESC LIMIT ?`, core, limit)
	} else {
		rows, err = h.DB.Query(q+` ORDER BY id DESC LIMIT ?`, limit)
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	out := []PortalAuditEntry{}
	for rows.Next() {
		var e PortalAuditEntry
		var success int
		if err := rows.Scan(&e.ID, &e.CoreName, &e.Ts, &e.Actor, &e.TargetID, &e.Facade, &success, &e.Detail); err != nil {
			continue
		}
		e.Success = success != 0
		out = append(out, e)
	}
	jsonOK(w, map[string]any{"events": out})
}

// InsertPortalAudit persisté depuis WS Core.
func InsertPortalAudit(db *sql.DB, core, ts, actor, targetID, facade string, success bool, detail string) {
	if db == nil {
		return
	}
	suc := 0
	if success {
		suc = 1
	}
	_, _ = db.Exec(`INSERT INTO portal_audit (core_name, ts, actor, target_id, facade, success, detail)
		VALUES (?,?,?,?,?,?,?)`, core, ts, actor, targetID, facade, suc, detail)
}
