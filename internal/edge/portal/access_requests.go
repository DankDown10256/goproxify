// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"encoding/json"
	"net/http"
	"strings"
)

const (
	maxAccessReasonLen  = 500
	minAccessDurationMn = 5
	maxAccessDurationMn = 480
)

// handleRequestable liste les destinations du catalogue que l'utilisateur ne voit pas encore.
func (h *HTTPServer) handleRequestable(w http.ResponseWriter, r *http.Request, pt portalToken) {
	type item struct {
		ID   string     `json:"id"`
		Name string     `json:"name"`
		Kind TargetKind `json:"kind"`
	}
	tags := h.userTags(pt.UserID)
	out := []item{}
	for _, c := range h.store.Catalog() {
		if CatalogVisible(tags, c.Tags) {
			continue
		}
		if _, ok := h.grants.Expiry(pt.UserID, c.ID); ok {
			continue
		}
		out = append(out, item{ID: c.ID, Name: c.Name, Kind: c.Kind})
	}
	writeJSON(w, http.StatusOK, map[string]any{"targets": out, "enabled": h.onAccessRequest != nil})
}

// handleAccessRequest transmet à l'Admin une demande d'accès temporaire.
func (h *HTTPServer) handleAccessRequest(w http.ResponseWriter, r *http.Request, pt portalToken) {
	if h.onAccessRequest == nil {
		http.Error(w, "demandes d'accès indisponibles", http.StatusServiceUnavailable)
		return
	}
	var body struct {
		TargetID    string `json:"target_id"`
		Reason      string `json:"reason"`
		DurationMin int    `json:"duration_min"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "json invalide", http.StatusBadRequest)
		return
	}
	body.Reason = strings.TrimSpace(body.Reason)
	if body.Reason == "" || len(body.Reason) > maxAccessReasonLen {
		http.Error(w, "motif requis (500 caractères max)", http.StatusBadRequest)
		return
	}
	if body.DurationMin < minAccessDurationMn || body.DurationMin > maxAccessDurationMn {
		http.Error(w, "durée entre 5 et 480 minutes", http.StatusBadRequest)
		return
	}
	c, ok := h.store.FindCatalogTarget(body.TargetID)
	if !ok || CatalogVisible(h.userTags(pt.UserID), c.Tags) {
		http.Error(w, "cible introuvable ou déjà accessible", http.StatusNotFound)
		return
	}
	req := AccessRequest{
		UserID: pt.UserID, Username: pt.Username, TargetID: c.ID,
		Reason: body.Reason, DurationMin: body.DurationMin,
	}
	if err := h.onAccessRequest(req); err != nil {
		http.Error(w, "administrateur injoignable", http.StatusBadGateway)
		return
	}
	h.emitAudit(AuditEvent{Actor: pt.Username, TargetID: c.ID, Success: true, Detail: "access_requested"})
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "pending"})
}
