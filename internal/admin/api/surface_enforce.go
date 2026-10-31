// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/edge/surface"
)

// Passage en block de la politique de surface, type de violation par type de violation (ADR 0016, étape 4). Le contrôle
// `openapi` du proxy refuse alors ces violations-là (`block_reasons`) et laisse passer, en les comptant, les autres. Les
// garde-fous sont ici, pas dans le contrôle : refuser une violation à laquelle le profil n'a pas encore appris à répondre
// coupe des clients légitimes.

// ProxyConfigWriter relit la configuration d'un proxy (identifiant ou hôte), la fait modifier par mutate, l'enregistre et la
// pousse aux passerelles. Une erreur de mutate annule tout.
type ProxyConfigWriter interface {
	MutateProxyConfig(ctx context.Context, ref, actor string, mutate func(cfg map[string]any) error) (id string, err error)
}

var (
	errEnforceRefused = errors.New("passage en block refusé")
	errEnforceDryRun  = errors.New("simulation")
)

// EnforceImpact dit, pour une raison, ce que le profil a vu : de quoi mesurer ce que le refus couperait.
type EnforceImpact struct {
	Reason string `json:"reason"`
	// Total : requêtes de ce type vues hors de la politique ; Legit : parmi elles, celles qui ont réussi depuis une IP propre
	// (donc des clients légitimes que le refus couperait) ; Blocked : celles déjà refusées.
	Total   int64 `json:"total"`
	Legit   int64 `json:"legit"`
	Blocked int64 `json:"blocked"`
	// LikelyLegit : les chemins probablement légitimes qui manquent à la politique, à ajouter avant de refuser.
	LikelyLegit []string `json:"likely_legit,omitempty"`
}

// EnforceResult est le résultat d'un passage en block, d'une simulation ou d'un retour en detect.
type EnforceResult struct {
	Route   string `json:"route"`
	Applied bool   `json:"applied"`
	DryRun  bool   `json:"dry_run,omitempty"`
	// Forced : l'administrateur a passé outre les garde-fous (consigné à l'audit).
	Forced bool `json:"forced,omitempty"`
	// Mode, UnknownPaths et BlockReasons : l'état du contrôle openapi après l'opération (ou qu'elle donnerait).
	Mode         string          `json:"mode,omitempty"`
	UnknownPaths string          `json:"unknown_paths,omitempty"`
	BlockReasons []string        `json:"block_reasons"`
	Blockers     []string        `json:"blockers"`
	Warnings     []string        `json:"warnings"`
	Impact       []EnforceImpact `json:"impact"`
}

// EnforceRequest demande le refus des violations de ces types.
type EnforceRequest struct {
	Reasons []string `json:"reasons"`
	// Force passe outre les garde-fous qui peuvent l'être (profil pas convergé, chemins probablement légitimes à ajouter).
	Force bool `json:"force,omitempty"`
	// DryRun calcule le résultat sans rien écrire.
	DryRun bool `json:"dry_run,omitempty"`
}

func normalizeReasons(in []string) ([]string, error) {
	known := map[string]bool{}
	for _, r := range surface.ViolationReasons {
		known[r] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range in {
		r = strings.TrimSpace(r)
		if r == "" || seen[r] {
			continue
		}
		if !known[r] {
			return nil, fmt.Errorf("raison inconnue %q (attendu : %s)", r, strings.Join(surface.ViolationReasons, ", "))
		}
		seen[r] = true
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("au moins une raison est requise (%s)", strings.Join(surface.ViolationReasons, ", "))
	}
	sort.Strings(out)
	return out, nil
}

// bestSurfaceReport rend le rapport qui réunit le plus de membres du groupe : chaque membre d'un groupe HA rend déjà la fusion.
func bestSurfaceReport(ctx context.Context, db *sql.DB, edge *prismedge.Source, edgeParam, route string) (*surface.Report, error) {
	gws, _, err := edge.SurfaceReport(ctx, gatewayName(ctx, db, edgeParam), route)
	if err != nil {
		return nil, err
	}
	var best *surface.Report
	for _, g := range gws {
		if g.Report == nil {
			continue
		}
		if best == nil || g.Report.Members > best.Members || (g.Report.Members == best.Members && g.Report.Learned > best.Learned) {
			best = g.Report
		}
	}
	return best, nil
}

func strSlice(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// EnforceSurface fait refuser par le contrôle openapi du proxy les violations des types demandés. Les garde-fous : une politique
// openapi active, un profil convergé, aucun chemin probablement légitime à ajouter pour ces types. Force passe outre les deux
// derniers (consigné à l'audit), jamais le premier.
func EnforceSurface(ctx context.Context, db *sql.DB, edge *prismedge.Source, w ProxyConfigWriter, actor, edgeParam, route string, req EnforceRequest) (EnforceResult, error) {
	res := EnforceResult{Route: route, DryRun: req.DryRun, BlockReasons: []string{}, Blockers: []string{}, Warnings: []string{}, Impact: []EnforceImpact{}}
	reasons, err := normalizeReasons(req.Reasons)
	if err != nil {
		return res, err
	}
	if edge == nil {
		return res, errNoGatewayToReplay
	}
	rep, err := bestSurfaceReport(ctx, db, edge, edgeParam, route)
	if err != nil {
		return res, err
	}
	if rep == nil {
		res.Blockers = append(res.Blockers, "aucun profil de surface pour ce proxy : activez l'apprentissage (learn) et générez la politique d'abord")
		return res, errEnforceRefused
	}
	id, err := w.MutateProxyConfig(ctx, route, actor, func(cfg map[string]any) error {
		oa, _ := cfg["openapi"].(map[string]any)
		if oa == nil || oa["enabled"] != true || oa["spec"] == nil {
			res.Blockers = append(res.Blockers, "ce proxy n'a pas de politique openapi active : générez-la (en detect) et enregistrez-la d'abord")
			return errEnforceRefused
		}
		if oa["mode"] == "block" {
			res.Warnings = append(res.Warnings, "le contrôle openapi est en mode block, qui refuse tout : il repasse en detect avec la seule liste demandée")
		}
		forceable := forceableBlockers(rep, reasons, &res)
		if len(forceable) > 0 {
			if !req.Force {
				res.Blockers = append(res.Blockers, forceable...)
				return errEnforceRefused
			}
			res.Forced = true
			res.Warnings = append(res.Warnings, "garde-fous passés outre : "+strings.Join(forceable, " ; "))
		}
		res.Mode, res.BlockReasons = "detect", reasons
		res.UnknownPaths, _ = oa["unknown_paths"].(string)
		if (contains(reasons, "unknown_path") || contains(reasons, "unknown_method")) && res.UnknownPaths != "block" {
			res.UnknownPaths = "block"
			res.Warnings = append(res.Warnings, "unknown_paths passe à block : sans cela les chemins et méthodes inconnus ne sont pas des violations")
		}
		if req.DryRun {
			return errEnforceDryRun
		}
		oa["mode"], oa["block_reasons"], oa["unknown_paths"] = "detect", stringsToAny(reasons), res.UnknownPaths
		return nil
	})
	switch {
	case errors.Is(err, errEnforceDryRun):
		return res, nil
	case err != nil:
		return res, err
	}
	res.Applied, res.Route = true, id
	detail := "refus: " + strings.Join(reasons, ",")
	action := "surface_enforce"
	if res.Forced {
		action, detail = "surface_enforce_forced", detail+" ; "+strings.Join(res.Warnings, " ; ")
	}
	_ = admindb.WriteAudit(db, actor, action, "proxy:"+id, detail)
	return res, nil
}

// forceableBlockers liste les garde-fous que Force peut passer, et remplit l'impact par raison.
func forceableBlockers(rep *surface.Report, reasons []string, res *EnforceResult) []string {
	var out []string
	if !rep.Convergence.Converged {
		out = append(out, "profil pas encore fiable ("+strings.Join(rep.Convergence.Reasons, " ; ")+")")
	}
	for _, r := range reasons {
		imp := EnforceImpact{Reason: r}
		for _, t := range rep.ViolationTotals {
			if t.Name == r {
				imp.Total = t.Count
			}
		}
		for _, b := range rep.BlockedTotals {
			if b.Name == r {
				imp.Blocked = b.Count
			}
		}
		for _, v := range rep.Violations {
			if v.Reason != r {
				continue
			}
			imp.Legit += v.Legit
			if v.LikelyLegit {
				imp.LikelyLegit = append(imp.LikelyLegit, v.Method+" "+v.Path)
			}
		}
		if len(imp.LikelyLegit) > 0 {
			out = append(out, fmt.Sprintf("%s : %d chemin(s) probablement légitime(s) manquent à la politique (%s)", r, len(imp.LikelyLegit), strings.Join(firstN(imp.LikelyLegit, 3), ", ")))
		}
		if imp.Legit > 0 && len(imp.LikelyLegit) == 0 {
			res.Warnings = append(res.Warnings, fmt.Sprintf("%s : %d requête(s) de ce type ont réussi depuis des IP propres et seraient refusées", r, imp.Legit))
		}
		res.Impact = append(res.Impact, imp)
	}
	if rep.Overflow > 0 || rep.ViolationsOverflow > 0 {
		out = append(out, "le profil a débordé : des chemins n'ont pas pu être retenus et seraient refusés à tort")
	}
	return out
}

// RelaxSurface remet le contrôle openapi du proxy en detect : plus rien n'est refusé, les violations restent comptées.
func RelaxSurface(ctx context.Context, db *sql.DB, w ProxyConfigWriter, actor, route string) (EnforceResult, error) {
	res := EnforceResult{Route: route, BlockReasons: []string{}, Blockers: []string{}, Warnings: []string{}, Impact: []EnforceImpact{}, Mode: "detect"}
	id, err := w.MutateProxyConfig(ctx, route, actor, func(cfg map[string]any) error {
		oa, _ := cfg["openapi"].(map[string]any)
		if oa == nil || oa["enabled"] != true {
			res.Blockers = append(res.Blockers, "ce proxy n'a pas de politique openapi active")
			return errEnforceRefused
		}
		res.UnknownPaths, _ = oa["unknown_paths"].(string)
		oa["mode"] = "detect"
		delete(oa, "block_reasons")
		return nil
	})
	if err != nil {
		return res, err
	}
	res.Applied, res.Route = true, id
	_ = admindb.WriteAudit(db, actor, "surface_relax", "proxy:"+id, "retour en detect")
	return res, nil
}

func contains(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

func firstN(list []string, n int) []string {
	if len(list) > n {
		return list[:n]
	}
	return list
}

func stringsToAny(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// EnforceStatus traduit l'erreur d'un passage en block en code HTTP : un refus des garde-fous est un conflit (409), pas une panne.
func EnforceStatus(err error) int {
	switch {
	case errors.Is(err, errEnforceRefused):
		return http.StatusConflict
	case errors.Is(err, errNoGatewayToReplay):
		return http.StatusBadGateway
	}
	return http.StatusBadRequest
}

func (h *SecurityHandler) enforceSurface(w http.ResponseWriter, r *http.Request) {
	route := strings.TrimSpace(r.URL.Query().Get("route"))
	var req EnforceRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil || route == "" {
		http.Error(w, "route (paramètre) et reasons (corps JSON) requis", http.StatusBadRequest)
		return
	}
	if h.Proxies == nil {
		http.Error(w, "écriture des proxies indisponible", http.StatusNotImplemented)
		return
	}
	res, err := EnforceSurface(r.Context(), h.DB, h.Edge, h.Proxies, auth.UserIDFromContext(r.Context()), r.URL.Query().Get("edge"), route, req)
	h.writeEnforce(w, res, err)
}

func (h *SecurityHandler) relaxSurface(w http.ResponseWriter, r *http.Request) {
	route := strings.TrimSpace(r.URL.Query().Get("route"))
	if route == "" {
		http.Error(w, "route requis (identifiant ou hôte du proxy)", http.StatusBadRequest)
		return
	}
	if h.Proxies == nil {
		http.Error(w, "écriture des proxies indisponible", http.StatusNotImplemented)
		return
	}
	res, err := RelaxSurface(r.Context(), h.DB, h.Proxies, auth.UserIDFromContext(r.Context()), route)
	h.writeEnforce(w, res, err)
}

func (h *SecurityHandler) writeEnforce(w http.ResponseWriter, res EnforceResult, err error) {
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
