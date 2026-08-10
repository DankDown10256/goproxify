// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"log/slog"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/logs"
)

// LogsHandler gère la consultation statique, l'export et le streaming SSE.
type LogsHandler struct {
	Log   *slog.Logger
	Store *logs.Store
	DB    *sql.DB
}

func (h *LogsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/logs")
	path = strings.TrimPrefix(path, "/")

	switch {
	case r.Method == http.MethodGet && path == "":
		h.list(w, r)
	case r.Method == http.MethodGet && path == "live":
		h.live(w, r)
	case r.Method == http.MethodGet && path == "export":
		h.export(w, r)
	case r.Method == http.MethodGet && path == "correlate":
		h.correlate(w, r)
	case r.Method == http.MethodGet && path == "settings":
		h.getSettings(w, r)
	case r.Method == http.MethodPut && path == "settings":
		h.putSettings(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *LogsHandler) list(w http.ResponseWriter, r *http.Request) {
	p := parseLogsParams(r)
	entries, total, err := h.Store.Search(p)
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"total": total, "page": p.Page, "page_size": p.PageSize, "entries": entries})
}

func (h *LogsHandler) live(w http.ResponseWriter, r *http.Request) {
	filter := parseLogsParams(r)
	h.Store.StreamSSE(w, r, filter)
}

func (h *LogsHandler) export(w http.ResponseWriter, r *http.Request) {
	p := parseLogsParams(r)
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}
	data, ct, err := h.Store.Export(p, format)
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	ts := time.Now().Format("20060102-150405")
	ext := "json"
	if format == "csv" {
		ext = "csv"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", "attachment; filename=logs-"+ts+"."+ext)
	w.Write(data) //nolint:errcheck
}

func parseLogsParams(r *http.Request) logs.SearchParams {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))
	return logs.SearchParams{
		Level:     q.Get("level"),
		Component: q.Get("component"),
		NodeName:  q.Get("node_name"),
		Domain:    q.Get("domain"),
		IP:        q.Get("ip"),
		Method:    q.Get("method"),
		Status:    q.Get("status"),
		Path:      q.Get("path"),
		Search:    q.Get("search"),
		DateFrom:  q.Get("date_from"),
		DateTo:    q.Get("date_to"),
		Kind:      q.Get("kind"),
		Page:      page,
		PageSize:  pageSize,
	}
}

func (h *LogsHandler) correlate(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	domain := q.Get("domain")
	tsStr := q.Get("ts")
	window, _ := strconv.Atoi(q.Get("window"))
	if window <= 0 {
		window = 30
	}
	at, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		at, err = time.Parse(time.RFC3339, tsStr)
		if err != nil {
			http.Error(w, "ts invalide (RFC3339 requis)", http.StatusBadRequest)
			return
		}
	}
	entries := h.Store.Correlate(domain, at, window)
	jsonOK(w, entries)
}

func (h *LogsHandler) getSettings(w http.ResponseWriter, r *http.Request) {
	retention, _ := strconv.Atoi(admindb.GetSetting(h.DB, "logs.retention_days", "30"))
	if retention == 0 {
		retention = 30
	}
	jsonOK(w, map[string]any{"retention_days": retention})
}

func (h *LogsHandler) putSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RetentionDays int `json:"retention_days"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if body.RetentionDays < 0 {
		writeErr(w, r, http.StatusBadRequest, "api.err.retention")
		return
	}
	admindb.SetSetting(h.DB, "logs.retention_days", strconv.Itoa(body.RetentionDays)) //nolint:errcheck
	w.WriteHeader(http.StatusNoContent)
}

func logsJSONErr(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
}
