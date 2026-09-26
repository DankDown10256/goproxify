// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
)

var portalRecordingsClient = &http.Client{Timeout: 30 * time.Second}

// maxRecordingProxyBytes borne la réponse relayée au navigateur (l'enregistrement est limité à 8 Mio côté passerelle).
const maxRecordingProxyBytes = 16 << 20

// handleRecordings relaie la liste, la lecture et la suppression des enregistrements de sessions,
// qui restent stockés (chiffrés) sur la passerelle.
func (h *PortalHandler) handleRecordings(w http.ResponseWriter, r *http.Request) {
	edge := portalEdgeParam(r)
	if edge == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.edge_required")
		return
	}
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/portal/recordings"), "/")
	if id != "" && strings.Contains(id, "/") {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	target, ok := h.edgeTarget(r.Context(), edge)
	if !ok {
		writeErr(w, r, http.StatusBadGateway, "api.err.internal")
		return
	}
	path := "/internal/v1/portal/recordings"
	if id != "" {
		path += "/" + url.PathEscape(id)
	}
	switch {
	case r.Method == http.MethodGet:
	case r.Method == http.MethodDelete && id != "":
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, target.Endpoint+path, nil)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	req.Header.Set("Authorization", "Bearer "+target.Token)
	resp, err := portalRecordingsClient.Do(req)
	if err != nil {
		writeErr(w, r, http.StatusBadGateway, "api.err.internal")
		return
	}
	defer resp.Body.Close()

	actor := adminauth.ActorFromContext(r.Context())
	if resp.StatusCode == http.StatusOK && id != "" && r.Method == http.MethodGet {
		_ = admindb.WriteAudit(h.DB, actor, "view", "portal_recording", id)
	}
	if resp.StatusCode == http.StatusNoContent && r.Method == http.MethodDelete {
		_ = admindb.WriteAudit(h.DB, actor, "delete", "portal_recording", id)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, maxRecordingProxyBytes))
}

func (h *PortalHandler) edgeTarget(ctx context.Context, edge string) (edgeproxy.Target, bool) {
	targets, err := edgeproxy.ListTargets(ctx, h.DB)
	if err != nil {
		return edgeproxy.Target{}, false
	}
	for _, t := range targets {
		if t.NodeName == edge {
			return t, true
		}
	}
	return edgeproxy.Target{}, false
}

var portalWatchClient = &http.Client{} // flux sans limite de durée ; annulé avec la requête

// watchSession relaie le flux SSE de la sortie d'une connexion en cours (observation par un administrateur).
func (h *PortalHandler) watchSession(w http.ResponseWriter, r *http.Request, edge, id string) {
	flusher, ok := w.(http.Flusher)
	target, found := h.edgeTarget(r.Context(), edge)
	if !ok || !found {
		writeErr(w, r, http.StatusBadGateway, "api.err.internal")
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet,
		target.Endpoint+"/internal/v1/portal/sessions/"+url.PathEscape(id)+"/watch", nil)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	req.Header.Set("Authorization", "Bearer "+target.Token)
	resp, err := portalWatchClient.Do(req)
	if err != nil {
		writeErr(w, r, http.StatusBadGateway, "api.err.internal")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		writeErr(w, r, resp.StatusCode, "api.err.not_found")
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "watch", "portal_session", id)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			_, _ = w.Write(buf[:n])
			flusher.Flush()
		}
		if err != nil {
			return
		}
	}
}
