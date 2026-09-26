// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"log/slog"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/logs"
	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// LogsSettingsPusher pousse les settings de logging vers les passerelles.
type LogsSettingsPusher interface {
	PushIPAnonymize(ctx context.Context, enabled bool)
	PushIPPseudonymize(ctx context.Context, enabled bool)
}

// LogsHandler gère la consultation statique, l'export et le streaming SSE.
type LogsHandler struct {
	Log     *slog.Logger
	Store   *logs.Store
	DB      *sql.DB
	Pusher  LogsSettingsPusher
	GDPRKey []byte // clé AES-GCM pour activer la pseudonymisation à chaud
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
	// RGPD : révélation IP pseudonymisée (scope gdpr:reveal requis)
	case r.Method == http.MethodPost && path == "reveal-ip":
		h.revealIP(w, r)
	// RGPD : effacement par IP ou utilisateur
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "by-ip/"):
		h.deleteByIP(w, r, strings.TrimPrefix(path, "by-ip/"))
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "by-user/"):
		h.deleteByUser(w, r, strings.TrimPrefix(path, "by-user/"))
	default:
		http.NotFound(w, r)
	}
}

func (h *LogsHandler) list(w http.ResponseWriter, r *http.Request) {
	p := parseLogsParams(r)
	entries, hasMore, err := h.Store.Search(p)
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	var lastID int64
	if len(entries) > 0 {
		lastID = entries[len(entries)-1].ID
	}
	jsonOK(w, map[string]any{"has_more": hasMore, "last_id": lastID, "page": p.Page, "page_size": p.PageSize, "entries": entries})
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
	beforeID, _ := strconv.ParseInt(q.Get("before_id"), 10, 64)
	return logs.SearchParams{
		Level:     q.Get("level"),
		Component: q.Get("component"),
		NodeName:  q.Get("node_name"),
		NodeID:    q.Get("node_id"),
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
		BeforeID:  beforeID,
	}
}

func (h *LogsHandler) correlate(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	requestID := q.Get("request_id")
	if requestID != "" {
		jsonOK(w, h.Store.CorrelateByRequestID(requestID))
		return
	}
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
	jsonOK(w, h.Store.Correlate(domain, at, window))
}

func (h *LogsHandler) getSettings(w http.ResponseWriter, r *http.Request) {
	parseInt := func(key string, def int) int {
		v := admindb.GetSetting(h.DB, key, "")
		if v == "" {
			return def
		}
		n := def
		strconv.Atoi(v) //nolint:errcheck
		if i, err := strconv.Atoi(v); err == nil {
			n = i
		}
		return n
	}
	accessDays, systemDays := h.Store.RetentionInfo()
	ipAnonymize := admindb.GetSetting(h.DB, "logs.ip_anonymize", "false") == "true"
	ipPseudonymize := admindb.GetSetting(h.DB, "logs.ip_pseudonymize", "false") == "true"
	jsonOK(w, map[string]any{
		"retention_access_days": parseInt("logs.retention_access_days", accessDays),
		"retention_system_days": parseInt("logs.retention_system_days", systemDays),
		"ip_anonymize":          ipAnonymize,
		"ip_pseudonymize":       ipPseudonymize,
		"defaults": map[string]any{
			"access_days": logs.DefaultRetentionAccessDays,
			"system_days": logs.DefaultRetentionSystemDays,
		},
	})
}

func (h *LogsHandler) putSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RetentionAccessDays int   `json:"retention_access_days"`
		RetentionSystemDays int   `json:"retention_system_days"`
		IPAnonymize         *bool `json:"ip_anonymize,omitempty"`
		IPPseudonymize      *bool `json:"ip_pseudonymize,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if body.RetentionAccessDays < 0 || body.RetentionSystemDays < 0 {
		writeErr(w, r, http.StatusBadRequest, "api.err.retention")
		return
	}
	if body.RetentionAccessDays > 0 {
		admindb.SetSetting(h.DB, "logs.retention_access_days", strconv.Itoa(body.RetentionAccessDays)) //nolint:errcheck
	}
	if body.RetentionSystemDays > 0 {
		admindb.SetSetting(h.DB, "logs.retention_system_days", strconv.Itoa(body.RetentionSystemDays)) //nolint:errcheck
	}
	h.Store.SetRetention(body.RetentionAccessDays, body.RetentionSystemDays)
	if body.IPAnonymize != nil {
		val := "false"
		if *body.IPAnonymize {
			val = "true"
		}
		admindb.SetSetting(h.DB, "logs.ip_anonymize", val) //nolint:errcheck
		if h.Pusher != nil {
			h.Pusher.PushIPAnonymize(r.Context(), *body.IPAnonymize)
		}
	}
	if body.IPPseudonymize != nil {
		val := "false"
		if *body.IPPseudonymize {
			val = "true"
		}
		admindb.SetSetting(h.DB, "logs.ip_pseudonymize", val) //nolint:errcheck
		if *body.IPPseudonymize && h.GDPRKey != nil {
			h.Store.SetPseudonymizeKey(h.GDPRKey)
		} else if !*body.IPPseudonymize {
			h.Store.SetPseudonymizeKey(nil)
		}
		if h.Pusher != nil {
			h.Pusher.PushIPPseudonymize(r.Context(), *body.IPPseudonymize)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// revealIP retourne l'IP réelle d'une entrée pseudonymisée.
// Nécessite le scope gdpr:reveal. Un motif (reason) est obligatoire. Chaque appel est audité.
func (h *LogsHandler) revealIP(w http.ResponseWriter, r *http.Request) {
	if !rbac.EffectiveHasScope(r.Context(), h.DB, rbac.ScopeGDPRReveal) {
		http.Error(w, "scope insuffisant: gdpr:reveal", http.StatusForbidden)
		return
	}
	var body struct {
		EntryID int64  `json:"entry_id"`
		Reason  string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if body.EntryID <= 0 {
		writeErr(w, r, http.StatusBadRequest, "api.err.missing_entry_id")
		return
	}
	if strings.TrimSpace(body.Reason) == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.reason_required")
		return
	}
	ip, err := h.Store.RevealIP(body.EntryID)
	if err != nil {
		logsJSONErr(w, err, http.StatusUnprocessableEntity)
		return
	}
	actor := adminauth.UserIDFromContext(r.Context())
	detail := fmt.Sprintf("entry_id=%d reason=%q", body.EntryID, body.Reason)
	_ = admindb.WriteAudit(h.DB, actor, "gdpr_reveal_ip", "logs", detail)
	h.Store.Write(logs.Entry{
		Level:     "warn",
		Component: "admin",
		Message:   fmt.Sprintf("RGPD révélation IP entrée #%d par %s — %s", body.EntryID, actor, body.Reason),
	})
	jsonOK(w, map[string]any{
		"entry_id":     body.EntryID,
		"ip":           ip,
		"requested_by": actor,
		"reason":       body.Reason,
		"ts":           time.Now().UTC().Format(time.RFC3339),
	})
}

// deleteByIP supprime tous les logs d'une IP (droit à l'effacement RGPD).
// Body JSON optionnel : {"reason": "demande RGPD article 17"}
func (h *LogsHandler) deleteByIP(w http.ResponseWriter, r *http.Request, ip string) {
	if ip == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.missing_ip")
		return
	}
	reason := parseDeletionReason(r)
	actor := adminauth.UserIDFromContext(r.Context())

	n, err := h.Store.DeleteByIP(ip)
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}

	detail := fmt.Sprintf("ip=%s deleted=%d reason=%q", ip, n, reason)
	_ = admindb.WriteAudit(h.DB, actor, "rgpd_erasure_ip", "logs", detail)
	h.Store.Write(logs.Entry{
		Level:     "info",
		Component: "admin",
		Message:   fmt.Sprintf("RGPD effacement IP %s : %d entrées supprimées par %s — %s", ip, n, actor, reason),
	})

	jsonOK(w, map[string]any{"deleted": n, "ip": ip})
}

// deleteByUser supprime tous les logs d'un utilisateur (droit à l'effacement RGPD).
// Body JSON optionnel : {"reason": "demande RGPD article 17"}
func (h *LogsHandler) deleteByUser(w http.ResponseWriter, r *http.Request, userID string) {
	if userID == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.missing_user")
		return
	}
	reason := parseDeletionReason(r)
	actor := adminauth.UserIDFromContext(r.Context())

	n, err := h.Store.DeleteByUserID(userID)
	if err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}

	detail := fmt.Sprintf("user_id=%s deleted=%d reason=%q", userID, n, reason)
	_ = admindb.WriteAudit(h.DB, actor, "rgpd_erasure_user", "logs", detail)
	h.Store.Write(logs.Entry{
		Level:     "info",
		Component: "admin",
		Message:   fmt.Sprintf("RGPD effacement utilisateur %s : %d entrées supprimées par %s — %s", userID, n, actor, reason),
	})

	jsonOK(w, map[string]any{"deleted": n, "user_id": userID})
}

// parseDeletionReason lit le champ "reason" du body JSON (optionnel).
func parseDeletionReason(r *http.Request) string {
	var body struct {
		Reason string `json:"reason"`
	}
	json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
	if body.Reason == "" {
		return "non précisé"
	}
	return body.Reason
}

func logsJSONErr(w http.ResponseWriter, err error, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()}) //nolint:errcheck
}
