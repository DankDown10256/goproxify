// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/edge/surface"
)

// Suggestions d'ajout à la politique (ADR 0016, étape 5). Le mode `learn` reste actif une fois la politique posée : les chemins et
// méthodes hors politique qui reviennent de plusieurs clients ordinaires sur plusieurs jours sont proposés à l'ajout. La politique
// ne s'élargit jamais seule : l'administrateur accepte, et l'acceptation ne fait qu'ajouter, jamais retirer.

// GatewaySuggestions : les ajouts qu'une passerelle suggère pour un proxy (le profil qu'elle rend est celui de son groupe HA).
type GatewaySuggestions struct {
	NodeID      string               `json:"node_id"`
	NodeName    string               `json:"node_name"`
	Members     int                  `json:"members"`
	Converged   bool                 `json:"converged"`
	Suggestions []surface.Suggestion `json:"suggestions"`
}

// SurfaceSuggestions retourne, par passerelle, les ajouts suggérés à la politique d'un proxy.
func SurfaceSuggestions(ctx context.Context, db *sql.DB, edge *prismedge.Source, edgeParam, route string) (map[string]any, error) {
	if edge == nil {
		return nil, errNoGatewayToReplay
	}
	gws, meta, err := edge.SurfaceReport(ctx, gatewayName(ctx, db, edgeParam), route)
	if err != nil {
		return nil, err
	}
	out := []GatewaySuggestions{}
	for _, g := range gws {
		if g.Report == nil {
			continue
		}
		sg := g.Report.Suggestions
		if sg == nil {
			sg = []surface.Suggestion{}
		}
		out = append(out, GatewaySuggestions{NodeID: g.NodeID, NodeName: g.NodeName, Members: g.Report.Members, Converged: g.Report.Convergence.Converged, Suggestions: sg})
	}
	return withMeta(map[string]any{"gateways": out}, meta), nil
}

// AcceptRequest désigne les suggestions à ajouter à la politique : par clé, ou toutes celles de confiance haute.
type AcceptRequest struct {
	Keys    []string `json:"keys,omitempty"`
	AllHigh bool     `json:"all_high,omitempty"`
	DryRun  bool     `json:"dry_run,omitempty"`
}

// AcceptedPath est un ajout fait à la politique.
type AcceptedPath struct {
	Key    string `json:"key"`
	Method string `json:"method"`
	Path   string `json:"path"`
}

// AcceptSkipped est une suggestion qui n'a pas été ajoutée, avec la raison.
type AcceptSkipped struct {
	Key    string `json:"key"`
	Reason string `json:"reason"`
}

// AcceptResult est le résultat de l'acceptation de suggestions.
type AcceptResult struct {
	Route    string          `json:"route"`
	Applied  bool            `json:"applied"`
	DryRun   bool            `json:"dry_run,omitempty"`
	Added    []AcceptedPath  `json:"added"`
	Skipped  []AcceptSkipped `json:"skipped"`
	Blockers []string        `json:"blockers"`
	Warnings []string        `json:"warnings"`
	// Spec est la spécification de la politique après l'ajout (ou qu'il donnerait).
	Spec json.RawMessage `json:"spec,omitempty"`
	// Forgotten : violations effacées des profils des passerelles, la politique les couvrant désormais.
	Forgotten int `json:"forgotten"`
}

// AcceptSurface ajoute à la spécification openapi du proxy les suggestions demandées. Seule une suggestion actuelle du profil peut
// être ajoutée (pas un chemin quelconque). La spécification doit être en JSON (celle que l'assistant génère) : un texte YAML ne se
// réécrit pas sans perdre sa mise en forme.
func AcceptSurface(ctx context.Context, db *sql.DB, edge *prismedge.Source, w ProxyConfigWriter, actor, edgeParam, route string, req AcceptRequest) (AcceptResult, error) {
	res := AcceptResult{Route: route, DryRun: req.DryRun, Added: []AcceptedPath{}, Skipped: []AcceptSkipped{}, Blockers: []string{}, Warnings: []string{}}
	if edge == nil {
		return res, errNoGatewayToReplay
	}
	if len(req.Keys) == 0 && !req.AllHigh {
		return res, errors.New("indiquez les suggestions à ajouter (keys) ou all_high")
	}
	rep, err := bestSurfaceReport(ctx, db, edge, edgeParam, route)
	if err != nil {
		return res, err
	}
	if rep == nil {
		res.Blockers = append(res.Blockers, "aucun profil de surface pour ce proxy")
		return res, errEnforceRefused
	}
	byKey := map[string]surface.Suggestion{}
	for _, s := range rep.Suggestions {
		byKey[s.Key] = s
	}
	var chosen []surface.Suggestion
	seen := map[string]bool{}
	take := func(s surface.Suggestion) {
		if !seen[s.Key] {
			seen[s.Key] = true
			chosen = append(chosen, s)
		}
	}
	if req.AllHigh {
		for _, s := range rep.Suggestions {
			if s.Confidence == "high" {
				take(s)
			}
		}
	}
	for _, k := range req.Keys {
		if s, ok := byKey[k]; ok {
			take(s)
		} else {
			res.Skipped = append(res.Skipped, AcceptSkipped{Key: k, Reason: "n'est pas (ou plus) une suggestion du profil"})
		}
	}
	if len(chosen) == 0 {
		res.Blockers = append(res.Blockers, "aucune suggestion à ajouter")
		return res, errEnforceRefused
	}

	var covered []string
	id, err := w.MutateProxyConfig(ctx, route, actor, func(cfg map[string]any) error {
		oa, _ := cfg["openapi"].(map[string]any)
		if oa == nil || oa["enabled"] != true || oa["spec"] == nil {
			res.Blockers = append(res.Blockers, "ce proxy n'a pas de politique openapi active")
			return errEnforceRefused
		}
		spec, perr := surface.ParseSpec(oa["spec"])
		if perr != nil {
			res.Blockers = append(res.Blockers, perr.Error())
			return errEnforceRefused
		}
		for _, s := range chosen {
			changed, aerr := surface.AddToSpec(spec, s.Method, s.Path)
			switch {
			case aerr != nil:
				res.Skipped = append(res.Skipped, AcceptSkipped{Key: s.Key, Reason: aerr.Error()})
			case !changed:
				res.Skipped = append(res.Skipped, AcceptSkipped{Key: s.Key, Reason: "déjà dans la politique"})
				covered = append(covered, s.Key) // couverte : son compte est à effacer aussi
			default:
				res.Added = append(res.Added, AcceptedPath{Key: s.Key, Method: s.Method, Path: s.Path})
			}
		}
		if len(res.Added) == 0 && len(covered) == 0 {
			res.Blockers = append(res.Blockers, "rien à ajouter")
			return errEnforceRefused
		}
		res.Spec, _ = json.Marshal(spec)
		if req.DryRun {
			return errEnforceDryRun
		}
		oa["spec"] = spec
		return nil
	})
	switch {
	case errors.Is(err, errEnforceDryRun):
		return res, nil
	case err != nil:
		return res, err
	}
	res.Applied, res.Route = true, id

	keys := make([]string, 0, len(res.Added)+len(res.Skipped))
	var detail []string
	for _, a := range res.Added {
		keys = append(keys, a.Key)
		detail = append(detail, a.Method+" "+a.Path)
	}
	keys = append(keys, covered...)
	if gws, _, ferr := edge.SurfaceForget(ctx, "", route, keys); ferr != nil {
		res.Warnings = append(res.Warnings, "les violations n'ont pas pu être effacées des profils : "+ferr.Error())
	} else {
		best := 0
		for _, g := range gws {
			if g.Forgotten > best {
				best = g.Forgotten
			}
		}
		res.Forgotten = best
	}
	_ = admindb.WriteAudit(db, actor, "surface_accept", "proxy:"+id, strings.Join(detail, " ; "))
	return res, nil
}

func (h *SecurityHandler) getSurfaceSuggestions(w http.ResponseWriter, r *http.Request) {
	route := strings.TrimSpace(r.URL.Query().Get("route"))
	if route == "" {
		http.Error(w, "route requis (identifiant ou hôte du proxy)", http.StatusBadRequest)
		return
	}
	out, err := SurfaceSuggestions(r.Context(), h.DB, h.Edge, r.URL.Query().Get("edge"), route)
	if err != nil {
		secJSONErr(w, err, http.StatusBadGateway)
		return
	}
	jsonOK(w, out)
}

func (h *SecurityHandler) acceptSurface(w http.ResponseWriter, r *http.Request) {
	route := strings.TrimSpace(r.URL.Query().Get("route"))
	var req AcceptRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<18)).Decode(&req); err != nil || route == "" {
		http.Error(w, "route (paramètre) et keys ou all_high (corps JSON) requis", http.StatusBadRequest)
		return
	}
	if h.Proxies == nil {
		http.Error(w, "écriture des proxies indisponible", http.StatusNotImplemented)
		return
	}
	res, err := AcceptSurface(r.Context(), h.DB, h.Edge, h.Proxies, auth.UserIDFromContext(r.Context()), r.URL.Query().Get("edge"), route, req)
	w.Header().Set("Content-Type", "application/json")
	switch {
	case err == nil:
	case errors.Is(err, errEnforceRefused):
		w.WriteHeader(http.StatusConflict)
	default:
		w.WriteHeader(EnforceStatus(err))
		res.Warnings = append(res.Warnings, err.Error())
	}
	_ = json.NewEncoder(w).Encode(res)
}
