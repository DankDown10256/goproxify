// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// ACMEProvidersHandler gère GET/POST /api/v1/acme/providers
// et GET/PUT/DELETE /api/v1/acme/providers/{id}.
type ACMEProvidersHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

type acmeProviderRow struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Type   string            `json:"type"`
	Params map[string]string `json:"params"`
}

func (h *ACMEProvidersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// /api/v1/acme/providers       → list / create
	// /api/v1/acme/providers/{id}  → get / update / delete
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/acme/providers")
	path = strings.TrimPrefix(path, "/")
	id := path // vide si racine

	switch {
	case id == "" && r.Method == http.MethodGet:
		h.list(w, r)
	case id == "" && r.Method == http.MethodPost:
		h.create(w, r)
	case id != "" && r.Method == http.MethodGet:
		h.get(w, r, id)
	case id != "" && r.Method == http.MethodPut:
		h.update(w, r, id)
	case id != "" && r.Method == http.MethodDelete:
		h.delete(w, r, id)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method_not_allowed")
	}
}

func (h *ACMEProvidersHandler) list(w http.ResponseWriter, _ *http.Request) {
	rows, err := h.DB.Query(
		`SELECT id, name, type, params FROM acme_providers ORDER BY name`)
	if err != nil {
		h.Log.Error("acme_providers: list", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var out []acmeProviderRow
	for rows.Next() {
		var p acmeProviderRow
		var paramsJSON string
		if err := rows.Scan(&p.ID, &p.Name, &p.Type, &paramsJSON); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(paramsJSON), &p.Params)
		out = append(out, p)
	}
	if out == nil {
		out = []acmeProviderRow{}
	}
	jsonOK(w, out)
}

func (h *ACMEProvidersHandler) get(w http.ResponseWriter, _ *http.Request, id string) {
	var p acmeProviderRow
	var paramsJSON string
	err := h.DB.QueryRow(
		`SELECT id, name, type, params FROM acme_providers WHERE id=?`, id).
		Scan(&p.ID, &p.Name, &p.Type, &paramsJSON)
	if err == sql.ErrNoRows {
		writeErr(w, nil, http.StatusNotFound, "api.err.not_found")
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.Unmarshal([]byte(paramsJSON), &p.Params)
	jsonOK(w, p)
}

func (h *ACMEProvidersHandler) create(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name   string            `json:"name"`
		Type   string            `json:"type"`
		Params map[string]string `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
		return
	}
	if body.Name == "" || body.Type == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.missing_fields")
		return
	}
	if body.Params == nil {
		body.Params = map[string]string{}
	}
	paramsJSON, _ := json.Marshal(body.Params)
	var id string
	err := h.DB.QueryRow(
		`INSERT INTO acme_providers (id, name, type, params)
		 VALUES (lower(hex(randomblob(16))), ?, ?, ?)
		 RETURNING id`, body.Name, body.Type, string(paramsJSON)).Scan(&id)
	if err != nil {
		h.Log.Error("acme_providers: create", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.Log.Info("acme_providers: créé", "id", id, "name", body.Name, "type", body.Type)
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"id": id}) //nolint:errcheck
}

func (h *ACMEProvidersHandler) update(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Name   string            `json:"name"`
		Type   string            `json:"type"`
		Params map[string]string `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
		return
	}
	if body.Params == nil {
		body.Params = map[string]string{}
	}
	paramsJSON, _ := json.Marshal(body.Params)
	res, err := h.DB.Exec(
		`UPDATE acme_providers SET name=?, type=?, params=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		body.Name, body.Type, string(paramsJSON), id)
	if err != nil {
		h.Log.Error("acme_providers: update", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	h.Log.Info("acme_providers: mis à jour", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

func (h *ACMEProvidersHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	res, err := h.DB.Exec(`DELETE FROM acme_providers WHERE id=?`, id)
	if err != nil {
		h.Log.Error("acme_providers: delete", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	h.Log.Info("acme_providers: supprimé", "id", id)
	w.WriteHeader(http.StatusNoContent)
}
