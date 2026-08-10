// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/ipprofile"
)

// IPProfilesHandler gère les profils de filtrage IP.
type IPProfilesHandler struct {
	DB      *sql.DB
	Log     *slog.Logger
	Updater *ipprofile.Updater
}

func (h *IPProfilesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/ip-profiles")
	path = strings.TrimPrefix(path, "/")

	switch {
	case r.Method == http.MethodGet && path == "":
		h.list(w, r)
	case r.Method == http.MethodPost && path == "":
		h.create(w, r)
	case r.Method == http.MethodGet && path != "" && !strings.Contains(path, "/"):
		h.get(w, r, path)
	case r.Method == http.MethodPut && path != "" && !strings.Contains(path, "/"):
		h.update(w, r, path)
	case r.Method == http.MethodDelete && path != "" && !strings.Contains(path, "/"):
		h.delete(w, r, path)
	case r.Method == http.MethodPost && strings.HasSuffix(path, "/refresh"):
		id := strings.TrimSuffix(path, "/refresh")
		h.refresh(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

func (h *IPProfilesHandler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, name, profile_type, mode, feed_urls, feed_format, refresh_interval_h,
		        cidrs, COALESCE(last_updated_at,''), enabled, created_at, updated_at
		 FROM ip_profiles ORDER BY name`)
	if err != nil {
		jsonErrF(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var profiles []ipprofile.Profile
	for rows.Next() {
		var p ipprofile.Profile
		var feedURLsJSON, cidrsJSON string
		var enabled int
		var lastUpdated string
		if err := rows.Scan(&p.ID, &p.Name, &p.ProfileType, &p.Mode,
			&feedURLsJSON, &p.FeedFormat, &p.RefreshIntervalH,
			&cidrsJSON, &lastUpdated, &enabled,
			&p.CreatedAt, &p.UpdatedAt); err != nil {
			continue
		}
		json.Unmarshal([]byte(feedURLsJSON), &p.FeedURLs)   //nolint:errcheck
		json.Unmarshal([]byte(cidrsJSON), &p.CIDRs)         //nolint:errcheck
		p.Enabled = enabled == 1
		if lastUpdated != "" {
			p.LastUpdatedAt = &lastUpdated
		}
		profiles = append(profiles, p)
	}
	if profiles == nil {
		profiles = []ipprofile.Profile{}
	}
	jsonOK(w, profiles)
}

func (h *IPProfilesHandler) get(w http.ResponseWriter, r *http.Request, id string) {
	var p ipprofile.Profile
	var feedURLsJSON, cidrsJSON string
	var enabled int
	var lastUpdated string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, name, profile_type, mode, feed_urls, feed_format, refresh_interval_h,
		        cidrs, COALESCE(last_updated_at,''), enabled, created_at, updated_at
		 FROM ip_profiles WHERE id=?`, id).Scan(
		&p.ID, &p.Name, &p.ProfileType, &p.Mode,
		&feedURLsJSON, &p.FeedFormat, &p.RefreshIntervalH,
		&cidrsJSON, &lastUpdated, &enabled,
		&p.CreatedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		jsonErrF(w, err, http.StatusInternalServerError)
		return
	}
	json.Unmarshal([]byte(feedURLsJSON), &p.FeedURLs) //nolint:errcheck
	json.Unmarshal([]byte(cidrsJSON), &p.CIDRs)       //nolint:errcheck
	p.Enabled = enabled == 1
	if lastUpdated != "" {
		p.LastUpdatedAt = &lastUpdated
	}
	jsonOK(w, p)
}

func (h *IPProfilesHandler) create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name             string   `json:"name"`
		ProfileType      string   `json:"profile_type"`
		Mode             string   `json:"mode"`
		FeedURLs         []string `json:"feed_urls"`
		FeedFormat       string   `json:"feed_format"`
		RefreshIntervalH int      `json:"refresh_interval_h"`
		Enabled          bool     `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErrF(w, err, http.StatusBadRequest)
		return
	}
	if body.Name == "" {
		jsonErrF(w, fmt.Errorf("name requis"), http.StatusBadRequest)
		return
	}
	if body.Mode == "" {
		body.Mode = "deny"
	}
	if body.FeedFormat == "" {
		body.FeedFormat = "plain"
	}
	if body.RefreshIntervalH == 0 {
		body.RefreshIntervalH = 24
	}
	furlsJSON, _ := json.Marshal(body.FeedURLs)
	id := uuid.New().String()
	enabled := 0
	if body.Enabled {
		enabled = 1
	}
	_, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO ip_profiles (id, name, profile_type, mode, feed_urls, feed_format, refresh_interval_h, cidrs, enabled)
		 VALUES (?, ?, ?, ?, ?, ?, ?, '[]', ?)`,
		id, body.Name, body.ProfileType, body.Mode,
		string(furlsJSON), body.FeedFormat, body.RefreshIntervalH, enabled)
	if err != nil {
		jsonErrF(w, err, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": id}) //nolint:errcheck
}

func (h *IPProfilesHandler) update(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Name             string   `json:"name"`
		Mode             string   `json:"mode"`
		FeedURLs         []string `json:"feed_urls"`
		FeedFormat       string   `json:"feed_format"`
		RefreshIntervalH int      `json:"refresh_interval_h"`
		Enabled          *bool    `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonErrF(w, err, http.StatusBadRequest)
		return
	}
	furlsJSON, _ := json.Marshal(body.FeedURLs)
	enabled := 1
	if body.Enabled != nil && !*body.Enabled {
		enabled = 0
	}
	_, err := h.DB.ExecContext(r.Context(),
		`UPDATE ip_profiles
		 SET name=?, mode=?, feed_urls=?, feed_format=?, refresh_interval_h=?, enabled=?, updated_at=?
		 WHERE id=?`,
		body.Name, body.Mode, string(furlsJSON), body.FeedFormat,
		body.RefreshIntervalH, enabled, time.Now().UTC().Format(time.RFC3339), id)
	if err != nil {
		jsonErrF(w, err, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *IPProfilesHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	h.DB.ExecContext(r.Context(), `DELETE FROM ip_profiles WHERE id=?`, id) //nolint:errcheck
	w.WriteHeader(http.StatusNoContent)
}

func (h *IPProfilesHandler) refresh(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.Updater.RefreshProfile(r.Context(), id); err != nil {
		jsonErrF(w, err, http.StatusBadRequest)
		return
	}
	jsonOK(w, map[string]string{"status": "refreshed"})
}

func jsonErrF(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
}
