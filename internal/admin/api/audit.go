// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/audit"
)

// AuditHandler expose le journal d'audit en lecture.
type AuditHandler struct {
	DB     *sql.DB
	Log    *slog.Logger
	Auditor *audit.Logger
}

func (h *AuditHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/export") {
		h.handleExport(w, r)
		return
	}
	h.handleSearch(w, r)
}

func (h *AuditHandler) handleSearch(w http.ResponseWriter, r *http.Request) {
	p := audit.SearchParams{
		Component: r.URL.Query().Get("component"),
		Action:    r.URL.Query().Get("action"),
		Actor:     r.URL.Query().Get("actor"),
		Severity:  r.URL.Query().Get("severity"),
	}
	if s := r.URL.Query().Get("from"); s != "" {
		p.From, _ = time.Parse(time.RFC3339, s)
	}
	if s := r.URL.Query().Get("to"); s != "" {
		p.To, _ = time.Parse(time.RFC3339, s)
	}
	p.Limit, _ = strconv.Atoi(r.URL.Query().Get("limit"))
	p.Offset, _ = strconv.Atoi(r.URL.Query().Get("offset"))
	if p.Limit == 0 {
		p.Limit = 50
	}

	entries, total, err := h.Auditor.Search(p)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"total":   total,
		"entries": entries,
	})
}

func (h *AuditHandler) handleExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	p := audit.SearchParams{
		Component: r.URL.Query().Get("component"),
		Action:    r.URL.Query().Get("action"),
		Actor:     r.URL.Query().Get("actor"),
		Severity:  r.URL.Query().Get("severity"),
	}
	if s := r.URL.Query().Get("from"); s != "" {
		p.From, _ = time.Parse(time.RFC3339, s)
	}
	if s := r.URL.Query().Get("to"); s != "" {
		p.To, _ = time.Parse(time.RFC3339, s)
	}

	data, ct, err := h.Auditor.Export(p, format)
	if err != nil {
		http.Error(w, "erreur export", http.StatusInternalServerError)
		return
	}
	filename := "audit." + format
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Write(data) //nolint:errcheck
}
