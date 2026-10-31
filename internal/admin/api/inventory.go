// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/admin/vulnscan"
	"github.com/vincamok/goproxify/internal/edge/logapi"
)

// Inventory retourne, par passerelle, les applications reconnues derrière ses proxies : produit, version, identifiant CPE, et ce qui les
// a fait reconnaître (l'image du conteneur annoncée par l'Agent). Un produit sans CPE ou sans version est listé sans être cherché dans NVD.
// route (identifiant ou hôte) restreint à un proxy.
func Inventory(ctx context.Context, db *sql.DB, edge *prismedge.Source, edgeParam, route string) (map[string]any, error) {
	if edge == nil {
		return nil, errNoGatewayToReplay
	}
	gws, meta, err := edge.Inventory(ctx, gatewayName(ctx, db, edgeParam), route)
	if err != nil {
		return nil, err
	}
	ov := vulnscan.LoadOverrides(ctx, db)
	var all []logapi.InventoryEntry
	for i := range gws {
		gws[i].Entries = vulnscan.ApplyOverrides(gws[i].Entries, ov)
		all = append(all, gws[i].Entries...)
	}
	return withMeta(map[string]any{"gateways": gws, "coverage": vulnscan.BuildCoverage(all)}, meta), nil
}

// getCPEOverrides : GET /api/v1/security/cpe-overrides — les identifiants CPE que l'administrateur a donnés aux produits que la table
// embarquée ne couvre pas.
func (h *SecurityHandler) getCPEOverrides(w http.ResponseWriter, r *http.Request) {
	ov := vulnscan.LoadOverrides(r.Context(), h.DB)
	if ov == nil {
		ov = []vulnscan.Override{}
	}
	jsonOK(w, map[string]any{"overrides": ov})
}

// putCPEOverrides : PUT /api/v1/security/cpe-overrides — remplace la liste ({"overrides": [{"match", "cpe"}]}).
func (h *SecurityHandler) putCPEOverrides(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Overrides []vulnscan.Override `json:"overrides"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	list, err := vulnscan.ValidateOverrides(body.Overrides)
	if err != nil {
		secJSONErr(w, err, http.StatusBadRequest)
		return
	}
	if err := vulnscan.SaveOverrides(r.Context(), h.DB, list); err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *SecurityHandler) getInventory(w http.ResponseWriter, r *http.Request) {
	out, err := Inventory(r.Context(), h.DB, h.Edge, r.URL.Query().Get("edge"), strings.TrimSpace(r.URL.Query().Get("route")))
	if err != nil {
		secJSONErr(w, err, http.StatusBadGateway)
		return
	}
	jsonOK(w, out)
}
