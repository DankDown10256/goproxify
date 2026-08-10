// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/core/portal"
)

// PortalDestination row Admin.
type PortalDestination struct {
	ID        string   `json:"id"`
	CoreName  string   `json:"core_name"`
	Kind      string   `json:"kind"`
	Name      string   `json:"name"`
	Host      string   `json:"host,omitempty"`
	Port      int      `json:"port,omitempty"`
	AgentName string   `json:"agent_name,omitempty"`
	Container string   `json:"container,omitempty"`
	Tags      []string `json:"tags"`
	Enabled   bool     `json:"enabled"`
}

// handleDestinationsRoute dispatches /api/v1/portal/destinations[/{id}].
func (h *PortalHandler) handleDestinations(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/v1/portal/destinations")
	rest = strings.Trim(rest, "/")
	id := rest

	switch {
	case id == "preview" && r.Method == http.MethodGet:
		h.previewDestinations(w, r)
	case id == "" && r.Method == http.MethodGet:
		h.listDestinations(w, r)
	case id == "" && r.Method == http.MethodPost:
		h.createDestination(w, r)
	case id != "" && id != "preview" && r.Method == http.MethodGet:
		h.getDestination(w, r, id)
	case id != "" && id != "preview" && r.Method == http.MethodPut:
		h.updateDestination(w, r, id)
	case id != "" && id != "preview" && r.Method == http.MethodDelete:
		h.deleteDestination(w, r, id)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

// previewDestinations applique le filtre tags R9–R10 comme sur Access (miroir Admin).
func (h *PortalHandler) previewDestinations(w http.ResponseWriter, r *http.Request) {
	core := portalCoreParam(r)
	userTags := normalizeTags(splitCSV(r.URL.Query().Get("tags")))
	if uid := strings.TrimSpace(r.URL.Query().Get("user_id")); uid != "" {
		row := h.DB.QueryRow(`SELECT tags_json FROM portal_users WHERE id=?`, uid)
		var tagsJSON string
		if err := row.Scan(&tagsJSON); err == nil {
			var tags []string
			_ = json.Unmarshal([]byte(tagsJSON), &tags)
			userTags = normalizeTags(tags)
		}
	}

	q := `SELECT id, core_name, kind, name, host, port, agent_name, container, tags_json, enabled
		FROM portal_destinations WHERE enabled=1`
	var rows *sql.Rows
	var err error
	if core != "" {
		rows, err = h.DB.Query(q+` AND core_name=? ORDER BY name`, core)
	} else {
		rows, err = h.DB.Query(q + ` ORDER BY core_name, name`)
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	visible := []PortalDestination{}
	hidden := []PortalDestination{}
	for rows.Next() {
		d, err := scanDestination(rows)
		if err != nil {
			continue
		}
		if portal.CatalogVisible(userTags, d.Tags) {
			visible = append(visible, d)
		} else {
			hidden = append(hidden, d)
		}
	}
	jsonOK(w, map[string]any{
		"user_tags": userTags,
		"visible":   visible,
		"hidden":    hidden,
		"visible_n": len(visible),
		"hidden_n":  len(hidden),
	})
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		out = append(out, p)
	}
	return out
}

func (h *PortalHandler) listDestinations(w http.ResponseWriter, r *http.Request) {
	core := portalCoreParam(r)
	q := `SELECT id, core_name, kind, name, host, port, agent_name, container, tags_json, enabled
		FROM portal_destinations`
	var rows *sql.Rows
	var err error
	if core != "" {
		rows, err = h.DB.Query(q+` WHERE core_name=? ORDER BY name`, core)
	} else {
		rows, err = h.DB.Query(q + ` ORDER BY core_name, name`)
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	out := []PortalDestination{}
	for rows.Next() {
		d, err := scanDestination(rows)
		if err != nil {
			continue
		}
		out = append(out, d)
	}
	jsonOK(w, map[string]any{"destinations": out})
}

func (h *PortalHandler) getDestination(w http.ResponseWriter, r *http.Request, id string) {
	row := h.DB.QueryRow(`SELECT id, core_name, kind, name, host, port, agent_name, container, tags_json, enabled
		FROM portal_destinations WHERE id=?`, id)
	d, err := scanDestination(row)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, d)
}

func (h *PortalHandler) createDestination(w http.ResponseWriter, r *http.Request) {
	var body PortalDestination
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
		return
	}
	if err := validateDestination(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if body.ID == "" {
		body.ID = uuid.New().String()
	}
	body.Enabled = true
	tags, _ := json.Marshal(normalizeTags(body.Tags))
	_, err := h.DB.Exec(`INSERT INTO portal_destinations
		(id, core_name, kind, name, host, port, agent_name, container, tags_json, enabled)
		VALUES (?,?,?,?,?,?,?,?,?,1)`,
		body.ID, body.CoreName, body.Kind, body.Name, body.Host, body.Port, body.AgentName, body.Container, string(tags))
	if err != nil {
		h.Log.Error("portal dest create", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "create", "portal_destination", body.ID)
	h.pushCatalogForCore(r, body.CoreName)
	body.Tags = normalizeTags(body.Tags)
	jsonOK(w, body)
}

func (h *PortalHandler) updateDestination(w http.ResponseWriter, r *http.Request, id string) {
	var body PortalDestination
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
		return
	}
	body.ID = id
	if err := validateDestination(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	tags, _ := json.Marshal(normalizeTags(body.Tags))
	en := 0
	if body.Enabled {
		en = 1
	}
	res, err := h.DB.Exec(`UPDATE portal_destinations SET
		core_name=?, kind=?, name=?, host=?, port=?, agent_name=?, container=?, tags_json=?, enabled=?,
		updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		body.CoreName, body.Kind, body.Name, body.Host, body.Port, body.AgentName, body.Container, string(tags), en, id)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "update", "portal_destination", id)
	h.pushCatalogForCore(r, body.CoreName)
	body.Tags = normalizeTags(body.Tags)
	jsonOK(w, body)
}

func (h *PortalHandler) deleteDestination(w http.ResponseWriter, r *http.Request, id string) {
	var core string
	_ = h.DB.QueryRow(`SELECT core_name FROM portal_destinations WHERE id=?`, id).Scan(&core)
	res, err := h.DB.Exec(`DELETE FROM portal_destinations WHERE id=?`, id)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "delete", "portal_destination", id)
	if core != "" {
		h.pushCatalogForCore(r, core)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *PortalHandler) pushCatalogForCore(r *http.Request, core string) {
	if h.Pusher == nil || core == "" {
		return
	}
	cfg := loadPortalConfig(h.DB, core)
	h.Pusher.PushPortal(r.Context(), core, cfg)
}

func validateDestination(d *PortalDestination) error {
	d.CoreName = strings.TrimSpace(d.CoreName)
	d.Name = strings.TrimSpace(d.Name)
	d.Kind = strings.TrimSpace(strings.ToLower(d.Kind))
	if d.CoreName == "" {
		return errStr("core_name requis")
	}
	if d.Name == "" {
		return errStr("name requis")
	}
	if d.Kind != "ssh" && d.Kind != "docker" {
		return errStr("kind doit être ssh ou docker")
	}
	if d.Kind == "ssh" {
		d.Host = strings.TrimSpace(d.Host)
		if d.Host == "" {
			return errStr("host requis pour ssh")
		}
		if d.Port <= 0 {
			d.Port = 22
		}
	} else {
		d.AgentName = strings.TrimSpace(d.AgentName)
		d.Container = strings.TrimSpace(d.Container)
		if d.AgentName == "" || d.Container == "" {
			return errStr("agent_name + container requis pour docker")
		}
	}
	d.Tags = normalizeTags(d.Tags)
	return nil
}

type errStr string

func (e errStr) Error() string { return string(e) }

func normalizeTags(in []string) []string {
	if in == nil {
		return []string{}
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.TrimSpace(strings.ToLower(t))
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

type scanner interface {
	Scan(dest ...any) error
}

func scanDestination(s scanner) (PortalDestination, error) {
	var d PortalDestination
	var tagsRaw string
	var en int
	if err := s.Scan(&d.ID, &d.CoreName, &d.Kind, &d.Name, &d.Host, &d.Port, &d.AgentName, &d.Container, &tagsRaw, &en); err != nil {
		return d, err
	}
	d.Enabled = en != 0
	_ = json.Unmarshal([]byte(tagsRaw), &d.Tags)
	d.Tags = normalizeTags(d.Tags)
	return d, nil
}

// listDestinationsAsCatalog returns enabled destinations for a Core as CatalogTarget.
func listDestinationsAsCatalog(db *sql.DB, coreName string) []portal.CatalogTarget {
	rows, err := db.Query(`SELECT id, kind, name, host, port, agent_name, container, tags_json
		FROM portal_destinations WHERE core_name=? AND enabled=1 ORDER BY name`, coreName)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []portal.CatalogTarget
	for rows.Next() {
		var id, kind, name, host, agent, container, tagsRaw string
		var port int
		if err := rows.Scan(&id, &kind, &name, &host, &port, &agent, &container, &tagsRaw); err != nil {
			continue
		}
		var tags []string
		_ = json.Unmarshal([]byte(tagsRaw), &tags)
		out = append(out, portal.CatalogTarget{
			ID: id, Name: name, Kind: portal.TargetKind(kind),
			Host: host, Port: port, AgentName: agent, Container: container,
			Tags: normalizeTags(tags),
		})
	}
	return out
}

// migrateLegacyCatalogIntoDestinations one-shot: settings catalog JSON → rows.
func migrateLegacyCatalogIntoDestinations(db *sql.DB, coreName string, catalog []portal.CatalogTarget) {
	var n int
	_ = db.QueryRow(`SELECT COUNT(1) FROM portal_destinations WHERE core_name=?`, coreName).Scan(&n)
	if n > 0 || len(catalog) == 0 {
		return
	}
	for _, c := range catalog {
		id := c.ID
		if id == "" {
			id = uuid.New().String()
		}
		tags, _ := json.Marshal(normalizeTags(c.Tags))
		_, _ = db.Exec(`INSERT OR IGNORE INTO portal_destinations
			(id, core_name, kind, name, host, port, agent_name, container, tags_json, enabled)
			VALUES (?,?,?,?,?,?,?,?,?,1)`,
			id, coreName, string(c.Kind), c.Name, c.Host, c.Port, c.AgentName, c.Container, string(tags))
	}
}
