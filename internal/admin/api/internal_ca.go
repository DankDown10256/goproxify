// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/internalca"
)

// InternalCAHandler expose la gestion de la CA interne.
//
//	GET    /api/v1/internal-ca                    → liste des CA
//	POST   /api/v1/internal-ca                    → création d'une CA racine
//	GET    /api/v1/internal-ca/{id}/certs          → liste des certs émis par la CA
//	POST   /api/v1/internal-ca/{id}/certs          → émission d'un certificat
//	DELETE /api/v1/internal-ca/{id}/certs/{certID} → révocation
type InternalCAHandler struct {
	Log     *slog.Logger
	Manager *internalca.Manager
}

func (h *InternalCAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/internal-ca"), "/")
	var parts []string
	if path != "" {
		parts = strings.Split(path, "/")
	}

	switch {
	case r.Method == http.MethodGet && len(parts) == 0:
		h.list(w, r)
	case r.Method == http.MethodPost && len(parts) == 0:
		h.create(w, r)
	case r.Method == http.MethodGet && len(parts) == 2 && parts[1] == "certs":
		h.listCerts(w, r, parts[0])
	case r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "certs":
		h.issueCert(w, r, parts[0])
	case r.Method == http.MethodDelete && len(parts) == 3 && parts[1] == "certs":
		h.revokeCert(w, r, parts[2])
	default:
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
	}
}

func (h *InternalCAHandler) list(w http.ResponseWriter, r *http.Request) {
	cas, err := h.Manager.ListCAs(r.Context())
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	json.NewEncoder(w).Encode(cas) //nolint:errcheck
}

func (h *InternalCAHandler) create(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name          string `json:"name"`
		CommonName    string `json:"common_name"`
		ValidityYears int    `json:"validity_years"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	if req.Name == "" || req.CommonName == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	years := req.ValidityYears
	if years <= 0 {
		years = 10
	}
	ca, err := h.Manager.CreateCA(r.Context(), req.Name, req.CommonName, time.Duration(years)*365*24*time.Hour)
	if err != nil {
		h.Log.Warn("internal-ca: création CA", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(ca) //nolint:errcheck
}

func (h *InternalCAHandler) listCerts(w http.ResponseWriter, r *http.Request, caID string) {
	certs, err := h.Manager.ListCerts(r.Context(), caID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	json.NewEncoder(w).Encode(certs) //nolint:errcheck
}

func (h *InternalCAHandler) issueCert(w http.ResponseWriter, r *http.Request, caID string) {
	var req struct {
		CommonName   string   `json:"common_name"`
		SANs         []string `json:"sans"`
		Usage        string   `json:"usage"`
		ValidityDays int      `json:"validity_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	if req.CommonName == "" || (req.Usage != "server" && req.Usage != "client") {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	days := req.ValidityDays
	if days <= 0 {
		days = 397
	}
	cert, err := h.Manager.IssueCert(r.Context(), caID, req.CommonName, req.SANs, req.Usage, time.Duration(days)*24*time.Hour)
	if err != nil {
		h.Log.Warn("internal-ca: émission certificat", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(cert) //nolint:errcheck
}

func (h *InternalCAHandler) revokeCert(w http.ResponseWriter, r *http.Request, certID string) {
	if err := h.Manager.RevokeCert(r.Context(), certID); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
