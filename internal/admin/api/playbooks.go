// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/playbooks"
)

// PlaybooksHandler expose le CRUD des playbooks et leurs exécutions.
type PlaybooksHandler struct {
	DB     *sql.DB
	Log    *slog.Logger
	Engine *playbooks.Engine
}

func (h *PlaybooksHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/playbooks")
	path = strings.TrimPrefix(path, "/")
	// path : "", "{id}", "{id}/run", "{id}/runs", ou "runs/{run_id}/approve|reject".
	if strings.HasPrefix(path, "runs/") {
		rest := strings.TrimPrefix(path, "runs/")
		parts := strings.SplitN(rest, "/", 2)
		runID := parts[0]
		if len(parts) == 2 && r.Method == http.MethodPost && parts[1] == "approve" {
			h.decideRun(w, r, runID, true)
			return
		}
		if len(parts) == 2 && r.Method == http.MethodPost && parts[1] == "reject" {
			h.decideRun(w, r, runID, false)
			return
		}
		if len(parts) == 1 && r.Method == http.MethodGet {
			h.getRun(w, r, runID)
			return
		}
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}

	parts := strings.SplitN(path, "/", 2)
	id := parts[0]
	sub := ""
	if len(parts) == 2 {
		sub = parts[1]
	}

	switch {
	case r.Method == http.MethodGet && id == "" && sub == "":
		h.list(w, r)
	case r.Method == http.MethodPost && id == "" && sub == "":
		h.create(w, r)
	case r.Method == http.MethodPut && id != "" && sub == "":
		h.update(w, r, id)
	case r.Method == http.MethodDelete && id != "" && sub == "":
		h.delete(w, r, id)
	case r.Method == http.MethodPost && id != "" && sub == "run":
		h.run(w, r, id)
	case r.Method == http.MethodGet && id != "" && sub == "runs":
		h.listRuns(w, r, id)
	default:
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
	}
}

type playbookBody struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Steps       []playbooks.Step `json:"steps"`
	Enabled     *bool            `json:"enabled"`
}

func (h *PlaybooksHandler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, name, description, steps_json, enabled, created_at, updated_at FROM playbooks ORDER BY name`)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, name, desc, stepsJSON string
		var enabled int
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&id, &name, &desc, &stepsJSON, &enabled, &createdAt, &updatedAt); err != nil {
			continue
		}
		var steps []playbooks.Step
		_ = json.Unmarshal([]byte(stepsJSON), &steps)
		out = append(out, map[string]any{
			"id": id, "name": name, "description": desc, "steps": steps, "enabled": enabled == 1,
			"created_at": createdAt, "updated_at": updatedAt,
		})
	}
	jsonOK(w, out)
}

func (h *PlaybooksHandler) create(w http.ResponseWriter, r *http.Request) {
	var body playbookBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	if strings.TrimSpace(body.Name) == "" || len(body.Steps) == 0 {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	stepsJSON, _ := json.Marshal(body.Steps)
	enabled := 1
	if body.Enabled != nil && !*body.Enabled {
		enabled = 0
	}
	id := uuid.New().String()
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO playbooks (id, name, description, steps_json, enabled) VALUES (?, ?, ?, ?, ?)`,
		id, body.Name, body.Description, string(stepsJSON), enabled,
	); err != nil {
		h.Log.Error("playbooks: create", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]string{"id": id})
}

func (h *PlaybooksHandler) update(w http.ResponseWriter, r *http.Request, id string) {
	var body playbookBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	if len(body.Steps) == 0 {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	stepsJSON, _ := json.Marshal(body.Steps)
	enabled := 1
	if body.Enabled != nil && !*body.Enabled {
		enabled = 0
	}
	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE playbooks SET name=?, description=?, steps_json=?, enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		body.Name, body.Description, string(stepsJSON), enabled, id,
	)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *PlaybooksHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM playbooks WHERE id=?`, id)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *PlaybooksHandler) run(w http.ResponseWriter, r *http.Request, id string) {
	if h.Engine == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.internal")
		return
	}
	runID, err := h.Engine.RunNow(id)
	if err != nil {
		writeErr(w, r, http.StatusBadRequest, err.Error())
		return
	}
	jsonOK(w, map[string]string{"run_id": runID})
}

func (h *PlaybooksHandler) listRuns(w http.ResponseWriter, r *http.Request, playbookID string) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, current_step, status, log_json, started_at, updated_at, finished_at
		 FROM playbook_runs WHERE playbook_id=? ORDER BY started_at DESC LIMIT 50`, playbookID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, status, logJSON string
		var step int
		var startedAt, updatedAt time.Time
		var finishedAt sql.NullTime
		if rows.Scan(&id, &step, &status, &logJSON, &startedAt, &updatedAt, &finishedAt) != nil {
			continue
		}
		var log []playbooks.LogEntry
		_ = json.Unmarshal([]byte(logJSON), &log)
		item := map[string]any{
			"id": id, "current_step": step, "status": status, "log": log,
			"started_at": startedAt, "updated_at": updatedAt,
		}
		if finishedAt.Valid {
			item["finished_at"] = finishedAt.Time
		}
		out = append(out, item)
	}
	jsonOK(w, out)
}

func (h *PlaybooksHandler) getRun(w http.ResponseWriter, r *http.Request, id string) {
	var playbookID, playbookName, stepsJSON, status, logJSON, contextJSON string
	var step int
	var startedAt, updatedAt time.Time
	var finishedAt sql.NullTime
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT playbook_id, playbook_name, steps_json, current_step, status, log_json, context_json, started_at, updated_at, finished_at
		 FROM playbook_runs WHERE id=?`, id,
	).Scan(&playbookID, &playbookName, &stepsJSON, &step, &status, &logJSON, &contextJSON, &startedAt, &updatedAt, &finishedAt)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	var steps []playbooks.Step
	var log []playbooks.LogEntry
	var ctxMap map[string]any
	_ = json.Unmarshal([]byte(stepsJSON), &steps)
	_ = json.Unmarshal([]byte(logJSON), &log)
	_ = json.Unmarshal([]byte(contextJSON), &ctxMap)
	item := map[string]any{
		"id": id, "playbook_id": playbookID, "playbook_name": playbookName, "steps": steps,
		"current_step": step, "status": status, "log": log, "context": ctxMap,
		"started_at": startedAt, "updated_at": updatedAt,
	}
	if finishedAt.Valid {
		item["finished_at"] = finishedAt.Time
	}
	jsonOK(w, item)
}

func (h *PlaybooksHandler) decideRun(w http.ResponseWriter, r *http.Request, runID string, approve bool) {
	if h.Engine == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.internal")
		return
	}
	if err := h.Engine.Decide(runID, approve); err != nil {
		writeErr(w, r, http.StatusBadRequest, err.Error())
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}
