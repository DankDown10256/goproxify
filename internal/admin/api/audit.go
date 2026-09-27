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
	if strings.HasSuffix(r.URL.Path, "/histogram") {
		h.handleHistogram(w, r)
		return
	}
	if strings.HasSuffix(r.URL.Path, "/export") {
		h.handleExport(w, r)
		return
	}
	h.handleSearch(w, r)
}

// handleHistogram : mêmes filtres que la recherche, plus bucket=minute|hour|day (défaut : selon l'étendue, 24 h sans date).
func (h *AuditHandler) handleHistogram(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p := audit.SearchParams{Component: q.Get("component"), Action: q.Get("action"), Actor: q.Get("actor"), Severity: q.Get("severity")}
	p.From, _ = time.Parse(time.RFC3339, q.Get("from"))
	p.To, _ = time.Parse(time.RFC3339, q.Get("to"))
	now := time.Now()
	if p.From.IsZero() {
		p.From = now.Add(-24 * time.Hour)
	}
	end := p.To
	if end.IsZero() {
		end = now
	}
	bucket := q.Get("bucket")
	if bucket == "" {
		bucket = "hour"
		if end.Sub(p.From) <= 6*time.Hour {
			bucket = "minute"
		}
	}
	pts, err := h.Auditor.Histogram(p, bucket)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"bucket": bucket, "points": pts}) //nolint:errcheck
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
