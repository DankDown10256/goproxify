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
	"github.com/vincamok/goproxify/internal/admin/scheduler"
)

// SchedulerHandler expose le CRUD des planifications (cron) et leur historique.
type SchedulerHandler struct {
	DB     *sql.DB
	Log    *slog.Logger
	Engine *scheduler.Engine
}

func (h *SchedulerHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/scheduled-tasks")
	path = strings.TrimPrefix(path, "/")
	// path est soit vide (collection), soit "{id}", soit "{id}/run" ou "{id}/runs".
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
		h.runNow(w, r, id)
	case r.Method == http.MethodGet && id != "" && sub == "runs":
		h.listRuns(w, r, id)
	default:
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
	}
}

type taskBody struct {
	Name     string         `json:"name"`
	CronExpr string         `json:"cron_expr"`
	Action   map[string]any `json:"action"`
	Enabled  *bool          `json:"enabled"`
}

func (h *SchedulerHandler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, name, cron_expr, action_json, enabled, last_run_at, created_at, updated_at
		 FROM scheduled_tasks ORDER BY name`)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, name, cronExpr, actionJSON string
		var enabled int
		var lastRun sql.NullTime
		var createdAt, updatedAt time.Time
		if err := rows.Scan(&id, &name, &cronExpr, &actionJSON, &enabled, &lastRun, &createdAt, &updatedAt); err != nil {
			continue
		}
		var action map[string]any
		_ = json.Unmarshal([]byte(actionJSON), &action)
		item := map[string]any{
			"id": id, "name": name, "cron_expr": cronExpr, "action": action, "enabled": enabled == 1,
			"created_at": createdAt, "updated_at": updatedAt,
		}
		if lastRun.Valid {
			item["last_run_at"] = lastRun.Time
		}
		out = append(out, item)
	}
	jsonOK(w, out)
}

func (h *SchedulerHandler) create(w http.ResponseWriter, r *http.Request) {
	var body taskBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	if strings.TrimSpace(body.Name) == "" || strings.TrimSpace(body.CronExpr) == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	if _, err := scheduler.ParseExpr(body.CronExpr); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	actionJSON, _ := json.Marshal(body.Action)
	enabled := 1
	if body.Enabled != nil && !*body.Enabled {
		enabled = 0
	}
	id := uuid.New().String()
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO scheduled_tasks (id, name, cron_expr, action_json, enabled) VALUES (?, ?, ?, ?, ?)`,
		id, body.Name, body.CronExpr, string(actionJSON), enabled,
	); err != nil {
		h.Log.Error("scheduler: create", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]string{"id": id})
}

func (h *SchedulerHandler) update(w http.ResponseWriter, r *http.Request, id string) {
	var body taskBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	if _, err := scheduler.ParseExpr(body.CronExpr); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	actionJSON, _ := json.Marshal(body.Action)
	enabled := 1
	if body.Enabled != nil && !*body.Enabled {
		enabled = 0
	}
	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE scheduled_tasks SET name=?, cron_expr=?, action_json=?, enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		body.Name, body.CronExpr, string(actionJSON), enabled, id,
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

func (h *SchedulerHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM scheduled_tasks WHERE id=?`, id)
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

func (h *SchedulerHandler) runNow(w http.ResponseWriter, r *http.Request, id string) {
	if h.Engine == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.internal")
		return
	}
	if err := h.Engine.RunNow(id); err != nil {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func (h *SchedulerHandler) listRuns(w http.ResponseWriter, r *http.Request, taskID string) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, success, error, ran_at FROM scheduled_task_runs WHERE task_id=? ORDER BY ran_at DESC LIMIT 100`, taskID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var success int
		var errStr string
		var ranAt time.Time
		if rows.Scan(&id, &success, &errStr, &ranAt) != nil {
			continue
		}
		out = append(out, map[string]any{"id": id, "success": success == 1, "error": errStr, "ran_at": ranAt})
	}
	jsonOK(w, out)
}
