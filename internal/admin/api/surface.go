// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/prismedge"
)

// gatewayName traduit ?edge= (identifiant du jeton ou nom du nœud) en nom de nœud.
func gatewayName(ctx context.Context, db *sql.DB, edgeParam string) string {
	if edgeParam == "" {
		return ""
	}
	var name string
	if db.QueryRowContext(ctx, `SELECT node_name FROM tokens WHERE id=? OR node_name=? LIMIT 1`, edgeParam, edgeParam).Scan(&name) == nil && name != "" {
		return name
	}
	return edgeParam
}

func withMeta(out map[string]any, meta prismedge.Meta) map[string]any {
	if meta.Degraded() {
		out["partial"], out["unreachable"] = meta.Partial, meta.Unreachable
	}
	return out
}

// SurfaceList retourne, par passerelle, les proxies dont elle apprend la surface (ADR 0016).
func SurfaceList(ctx context.Context, db *sql.DB, edge *prismedge.Source, edgeParam string) (map[string]any, error) {
	if edge == nil {
		return nil, errNoGatewayToReplay
	}
	gws, meta, err := edge.SurfaceList(ctx, gatewayName(ctx, db, edgeParam))
	if err != nil {
		return nil, err
	}
	return withMeta(map[string]any{"gateways": gws}, meta), nil
}

// SurfaceReport retourne, par passerelle, le rapport de surface d'un proxy (identifiant ou hôte). Une passerelle sans profil
// pour ce proxy rend un rapport nul.
func SurfaceReport(ctx context.Context, db *sql.DB, edge *prismedge.Source, edgeParam, route string) (map[string]any, error) {
	if edge == nil {
		return nil, errNoGatewayToReplay
	}
	gws, meta, err := edge.SurfaceReport(ctx, gatewayName(ctx, db, edgeParam), route)
	if err != nil {
		return nil, err
	}
	return withMeta(map[string]any{"gateways": gws}, meta), nil
}

// SurfaceProposals retourne, par passerelle, les réglages que le profil de surface d'un proxy permet de proposer. Rien n'est
// appliqué : chaque proposition porte la commande qui la pose.
func SurfaceProposals(ctx context.Context, db *sql.DB, edge *prismedge.Source, edgeParam, route string) (map[string]any, error) {
	if edge == nil {
		return nil, errNoGatewayToReplay
	}
	gws, meta, err := edge.SurfaceProposals(ctx, gatewayName(ctx, db, edgeParam), route)
	if err != nil {
		return nil, err
	}
	return withMeta(map[string]any{"gateways": gws}, meta), nil
}

// SurfaceOpenAPI retourne, par passerelle, la politique OpenAPI (réglage `openapi` du proxy, en mode detect) générée à partir du
// profil de surface d'un proxy. Rien n'est appliqué.
func SurfaceOpenAPI(ctx context.Context, db *sql.DB, edge *prismedge.Source, edgeParam, route string, lowSupport bool) (map[string]any, error) {
	if edge == nil {
		return nil, errNoGatewayToReplay
	}
	gws, meta, err := edge.SurfaceOpenAPI(ctx, gatewayName(ctx, db, edgeParam), route, lowSupport)
	if err != nil {
		return nil, err
	}
	return withMeta(map[string]any{"gateways": gws}, meta), nil
}

// SurfaceReset efface le profil d'un proxy sur chaque passerelle : l'apprentissage repart de zéro.
func SurfaceReset(ctx context.Context, db *sql.DB, edge *prismedge.Source, edgeParam, route string) (map[string]any, error) {
	if edge == nil {
		return nil, errNoGatewayToReplay
	}
	gws, meta, err := edge.SurfaceReset(ctx, gatewayName(ctx, db, edgeParam), route)
	if err != nil {
		return nil, err
	}
	return withMeta(map[string]any{"gateways": gws}, meta), nil
}

func (h *SecurityHandler) getSurface(w http.ResponseWriter, r *http.Request) {
	out, err := SurfaceList(r.Context(), h.DB, h.Edge, r.URL.Query().Get("edge"))
	if err != nil {
		secJSONErr(w, err, http.StatusBadGateway)
		return
	}
	jsonOK(w, out)
}

func (h *SecurityHandler) getSurfaceReport(w http.ResponseWriter, r *http.Request) {
	route := strings.TrimSpace(r.URL.Query().Get("route"))
	if route == "" {
		http.Error(w, "route requis (identifiant ou hôte du proxy)", http.StatusBadRequest)
		return
	}
	out, err := SurfaceReport(r.Context(), h.DB, h.Edge, r.URL.Query().Get("edge"), route)
	if err != nil {
		secJSONErr(w, err, http.StatusBadGateway)
		return
	}
	jsonOK(w, out)
}

func (h *SecurityHandler) getSurfaceProposals(w http.ResponseWriter, r *http.Request) {
	route := strings.TrimSpace(r.URL.Query().Get("route"))
	if route == "" {
		http.Error(w, "route requis (identifiant ou hôte du proxy)", http.StatusBadRequest)
		return
	}
	out, err := SurfaceProposals(r.Context(), h.DB, h.Edge, r.URL.Query().Get("edge"), route)
	if err != nil {
		secJSONErr(w, err, http.StatusBadGateway)
		return
	}
	jsonOK(w, out)
}

func (h *SecurityHandler) getSurfaceOpenAPI(w http.ResponseWriter, r *http.Request) {
	route := strings.TrimSpace(r.URL.Query().Get("route"))
	if route == "" {
		http.Error(w, "route requis (identifiant ou hôte du proxy)", http.StatusBadRequest)
		return
	}
	out, err := SurfaceOpenAPI(r.Context(), h.DB, h.Edge, r.URL.Query().Get("edge"), route, r.URL.Query().Get("include_low_support") == "1")
	if err != nil {
		secJSONErr(w, err, http.StatusBadGateway)
		return
	}
	jsonOK(w, out)
}

func (h *SecurityHandler) resetSurface(w http.ResponseWriter, r *http.Request) {
	route := strings.TrimSpace(r.URL.Query().Get("route"))
	if route == "" {
		http.Error(w, "route requis (identifiant ou hôte du proxy)", http.StatusBadRequest)
		return
	}
	out, err := SurfaceReset(r.Context(), h.DB, h.Edge, r.URL.Query().Get("edge"), route)
	if err != nil {
		secJSONErr(w, err, http.StatusBadGateway)
		return
	}
	jsonOK(w, out)
}
