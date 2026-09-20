// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/acme"
)

// ACMEProvidersHandler gère GET/POST /api/v1/acme/providers
// et GET/PUT/DELETE /api/v1/acme/providers/{id}.
type ACMEProvidersHandler struct {
	Store *acme.ProviderStore
	Log   *slog.Logger
}

func (h *ACMEProvidersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/acme/providers")
	path = strings.TrimPrefix(path, "/")
	id := path

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
	entries, err := h.Store.List()
	if err != nil {
		h.Log.Error("acme_providers: list", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if entries == nil {
		entries = []acme.ProviderEntry{}
	}
	jsonOK(w, entries)
}

func (h *ACMEProvidersHandler) get(w http.ResponseWriter, r *http.Request, id string) {
	e, err := h.Store.Get(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if e == nil {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	jsonOK(w, e)
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
	id, err := h.Store.Create(body.Name, body.Type, body.Params)
	if err != nil {
		h.Log.Error("acme_providers: create", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.Log.Info("acme_providers: créé", "id", id, "name", body.Name)
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
	if err := h.Store.Update(id, body.Name, body.Type, body.Params); err != nil {
		h.Log.Error("acme_providers: update", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.Log.Info("acme_providers: mis à jour", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

func (h *ACMEProvidersHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.Store.Delete(id); err != nil {
		h.Log.Error("acme_providers: delete", "err", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.Log.Info("acme_providers: supprimé", "id", id)
	w.WriteHeader(http.StatusNoContent)
}
