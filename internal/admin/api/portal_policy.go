// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/portal"
)

// handlePolicy lit ou remplace la politique d'accès du portail (plages horaires, IP, inactivité).
// Elle est enregistrée avec la config du portail mais se modifie séparément du formulaire Réglages.
func (h *PortalHandler) handlePolicy(w http.ResponseWriter, r *http.Request) {
	edge := portalEdgeParam(r)
	if edge == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.edge_required")
		return
	}
	scope := h.scope(edge)
	cfg := loadPortalConfig(h.DB, scope)
	switch r.Method {
	case http.MethodGet:
		p := portal.Policy{}
		if cfg.Policy != nil {
			p = *cfg.Policy
		}
		jsonOK(w, p)
	case http.MethodPut:
		var p portal.Policy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
			return
		}
		if err := p.Validate(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cfg.Policy = &p
		cfg.Users, cfg.Grants = nil, nil // calculés à l'envoi, pas stockés
		raw, err := json.Marshal(cfg)
		if err != nil {
			writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
			return
		}
		if err := admindb.SetSetting(h.DB, settingPortalConfigPrefix+scope, string(raw)); err != nil {
			writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
			return
		}
		_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "update", "portal_policy", scope)
		h.pushScope(r.Context(), scope)
		jsonOK(w, p)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}
