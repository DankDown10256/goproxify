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
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
)

// WorkspacesHandler gère le CRUD des espaces de travail (multi-tenancy).
type WorkspacesHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

func (h *WorkspacesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/api/v1/workspaces")
	p = strings.TrimPrefix(p, "/")
	parts := strings.SplitN(p, "/", 4)
	id := parts[0]
	sub := ""
	subID := ""
	if len(parts) > 1 {
		sub = parts[1]
	}
	if len(parts) > 2 {
		subID = parts[2]
	}
	if len(parts) > 3 {
		subID = parts[2] + "/" + parts[3]
	}

	switch {
	case r.Method == http.MethodGet && id == "":
		h.list(w, r)
	case r.Method == http.MethodPost && id == "":
		h.create(w, r)
	case r.Method == http.MethodGet && id != "" && sub == "":
		h.get(w, r, id)
	case r.Method == http.MethodPut && id != "" && sub == "":
		h.update(w, r, id)
	case r.Method == http.MethodDelete && id != "" && sub == "":
		h.delete(w, r, id)
	case r.Method == http.MethodPost && sub == "members":
		h.addMember(w, r, id)
	case r.Method == http.MethodDelete && sub == "members" && subID != "":
		h.removeMember(w, r, id, subID)
	case r.Method == http.MethodPost && sub == "resources":
		h.addResource(w, r, id)
	case r.Method == http.MethodDelete && sub == "resources" && subID != "":
		h.removeResource(w, r, id, subID)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

type workspace struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	CreatedAt     time.Time `json:"created_at"`
	CreatedBy     string    `json:"created_by"`
	MemberCount   int       `json:"member_count"`
	ResourceCount int       `json:"resource_count"`
}

type workspaceMember struct {
	EntityType string `json:"entity_type"`
	EntityID   string `json:"entity_id"`
	EntityName string `json:"entity_name,omitempty"`
}

type workspaceResource struct {
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	ResourceName string `json:"resource_name,omitempty"`
}

type workspaceDetail struct {
	workspace
	Members   []workspaceMember   `json:"members"`
	Resources []workspaceResource `json:"resources"`
}

func (h *WorkspacesHandler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT w.id, w.name, w.description, w.created_at, w.created_by,
			(SELECT COUNT(*) FROM workspace_members WHERE workspace_id=w.id) as mc,
			(SELECT COUNT(*) FROM workspace_resources WHERE workspace_id=w.id) as rc
		FROM workspaces w ORDER BY w.name`)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.db")
		return
	}
	defer rows.Close()
	out := []workspace{}
	for rows.Next() {
		var ws workspace
		if err := rows.Scan(&ws.ID, &ws.Name, &ws.Description, &ws.CreatedAt, &ws.CreatedBy, &ws.MemberCount, &ws.ResourceCount); err == nil {
			out = append(out, ws)
		}
	}
	jsonOK(w, out)
}

func (h *WorkspacesHandler) get(w http.ResponseWriter, r *http.Request, id string) {
	var ws workspaceDetail
	err := h.DB.QueryRowContext(r.Context(), `
		SELECT id, name, description, created_at, created_by FROM workspaces WHERE id=?`, id).
		Scan(&ws.ID, &ws.Name, &ws.Description, &ws.CreatedAt, &ws.CreatedBy)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	} else if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.db")
		return
	}

	// Members
	mrows, _ := h.DB.QueryContext(r.Context(), `
		SELECT m.entity_type, m.entity_id,
			COALESCE(
				CASE WHEN m.entity_type='user' THEN (SELECT email FROM users WHERE id=m.entity_id)
				ELSE (SELECT name FROM teams WHERE id=m.entity_id) END,
			'')
		FROM workspace_members m WHERE m.workspace_id=?`, id)
	if mrows != nil {
		defer mrows.Close()
		for mrows.Next() {
			var mb workspaceMember
			mrows.Scan(&mb.EntityType, &mb.EntityID, &mb.EntityName) //nolint:errcheck
			ws.Members = append(ws.Members, mb)
		}
	}
	if ws.Members == nil {
		ws.Members = []workspaceMember{}
	}

	// Resources
	rrows, _ := h.DB.QueryContext(r.Context(), `
		SELECT res.resource_type, res.resource_id,
			COALESCE(
				CASE WHEN res.resource_type='proxy' THEN (SELECT name FROM proxies WHERE id=res.resource_id)
				WHEN res.resource_type='edge' THEN (SELECT node_name FROM nodes WHERE id=res.resource_id)
				ELSE '' END,
			'')
		FROM workspace_resources res WHERE res.workspace_id=?`, id)
	if rrows != nil {
		defer rrows.Close()
		for rrows.Next() {
			var res workspaceResource
			rrows.Scan(&res.ResourceType, &res.ResourceID, &res.ResourceName) //nolint:errcheck
			ws.Resources = append(ws.Resources, res)
		}
	}
	if ws.Resources == nil {
		ws.Resources = []workspaceResource{}
	}

	ws.MemberCount = len(ws.Members)
	ws.ResourceCount = len(ws.Resources)
	jsonOK(w, ws)
}

func (h *WorkspacesHandler) create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Name) == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	id := uuid.New().String()
	actor := adminauth.UserIDFromContext(r.Context())
	_, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO workspaces(id,name,description,created_by) VALUES(?,?,?,?)`,
		id, strings.TrimSpace(body.Name), body.Description, actor)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			writeErr(w, r, http.StatusConflict, "api.err.conflict")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.db")
		return
	}
	jsonOK(w, map[string]string{"id": id})
}

func (h *WorkspacesHandler) update(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE workspaces SET name=?, description=? WHERE id=?`,
		strings.TrimSpace(body.Name), body.Description, id)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.db")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func (h *WorkspacesHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	h.DB.ExecContext(r.Context(), `DELETE FROM workspace_members WHERE workspace_id=?`, id)    //nolint:errcheck
	h.DB.ExecContext(r.Context(), `DELETE FROM workspace_resources WHERE workspace_id=?`, id)  //nolint:errcheck
	h.DB.ExecContext(r.Context(), `DELETE FROM workspaces WHERE id=?`, id)                     //nolint:errcheck
	jsonOK(w, map[string]bool{"ok": true})
}

func (h *WorkspacesHandler) addMember(w http.ResponseWriter, r *http.Request, wsID string) {
	var body workspaceMember
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
		(body.EntityType != "user" && body.EntityType != "team") ||
		body.EntityID == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	_, err := h.DB.ExecContext(r.Context(),
		`INSERT OR IGNORE INTO workspace_members(workspace_id,entity_type,entity_id) VALUES(?,?,?)`,
		wsID, body.EntityType, body.EntityID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.db")
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func (h *WorkspacesHandler) removeMember(w http.ResponseWriter, r *http.Request, wsID, subID string) {
	// subID = "user/abc" or "team/abc"
	parts := strings.SplitN(subID, "/", 2)
	if len(parts) != 2 {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	h.DB.ExecContext(r.Context(), //nolint:errcheck
		`DELETE FROM workspace_members WHERE workspace_id=? AND entity_type=? AND entity_id=?`,
		wsID, parts[0], parts[1])
	jsonOK(w, map[string]bool{"ok": true})
}

func (h *WorkspacesHandler) addResource(w http.ResponseWriter, r *http.Request, wsID string) {
	var body workspaceResource
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil ||
		(body.ResourceType != "proxy" && body.ResourceType != "domain" && body.ResourceType != "edge") ||
		body.ResourceID == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	_, err := h.DB.ExecContext(r.Context(),
		`INSERT OR IGNORE INTO workspace_resources(workspace_id,resource_type,resource_id) VALUES(?,?,?)`,
		wsID, body.ResourceType, body.ResourceID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.db")
		return
	}
	jsonOK(w, map[string]bool{"ok": true})
}

func (h *WorkspacesHandler) removeResource(w http.ResponseWriter, r *http.Request, wsID, subID string) {
	// subID = "proxy/abc" or "domain/abc" or "edge/abc"
	parts := strings.SplitN(subID, "/", 2)
	if len(parts) != 2 {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	h.DB.ExecContext(r.Context(), //nolint:errcheck
		`DELETE FROM workspace_resources WHERE workspace_id=? AND resource_type=? AND resource_id=?`,
		wsID, parts[0], parts[1])
	jsonOK(w, map[string]bool{"ok": true})
}
