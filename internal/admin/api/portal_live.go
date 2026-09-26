// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"strings"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/portal"
)

// PortalLiveSource expose les connexions pontées en cours, remontées par les passerelles.
type PortalLiveSource interface {
	PortalLive(edgeName string) []portal.LiveSession
	KillPortalSession(edgeName, id string) bool
}

func (h *PortalHandler) handleLiveSessions(w http.ResponseWriter, r *http.Request) {
	edge := portalEdgeParam(r)
	if edge == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.edge_required")
		return
	}
	if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/watch") {
		id := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/portal/sessions"), "/watch"), "/")
		if id == "" || strings.Contains(id, "/") {
			writeErr(w, r, http.StatusNotFound, "api.err.not_found")
			return
		}
		h.watchSession(w, r, edge, id)
		return
	}
	src, ok := h.Pusher.(PortalLiveSource)
	if !ok {
		writeErr(w, r, http.StatusNotImplemented, "api.err.internal")
		return
	}
	switch r.Method {
	case http.MethodGet:
		out := src.PortalLive(edge)
		if out == nil {
			out = []portal.LiveSession{}
		}
		jsonOK(w, map[string]any{"sessions": out})
	case http.MethodDelete:
		id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/portal/sessions"), "/")
		if id == "" {
			writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
			return
		}
		if !src.KillPortalSession(edge, id) {
			writeErr(w, r, http.StatusNotFound, "api.err.not_found")
			return
		}
		_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "terminate", "portal_session", id)
		w.WriteHeader(http.StatusNoContent)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}
