// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/api"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
)

func surfaceTools() []map[string]any {
	return []map[string]any{{
		"name": "get_proxy_surface",
		"description": "Apprentissage de la surface d'un proxy (ADR 0016) : ce que son trafic légitime utilise réellement. Sans `proxy`, liste par passerelle " +
			"les proxies en apprentissage (requêtes vues et apprises, gabarits de chemin, convergence). Avec `proxy` (identifiant ou hôte), rapport complet : " +
			"méthodes, gabarits de chemin (/api/users/{int}) avec méthodes, statuts, types de contenu, taille des corps, paramètres, clients distincts et " +
			"jours de présence, en-têtes, pays et AS des clients, requêtes exclues (IP suspecte) ou en échec, et indicateur de convergence (un profil n'est fiable " +
			"qu'après 7 jours, 1 000 requêtes et 48 h sans nouveau gabarit). Un gabarit `low_support` a peu de clients ou de jours : à confirmer. Le mode `learn` " +
			"est activé par proxy (champ surface.mode) et ne bloque rien ; une passerelle d'un groupe HA rend le profil fusionné de ses pairs.",
		"inputSchema": schema(
			opt("proxy", "string", "Identifiant ou hôte du proxy ; vide = liste des proxies en apprentissage"),
			opt("edge", "string", "Passerelle (nom du nœud ou id du token) ; défaut : toutes"),
		),
	}, {
		"name": "get_proxy_surface_proposals",
		"description": "Réglages que le profil de surface d'un proxy permet de proposer (ADR 0016, étape 2) : max_body_size, rate_limit, geo_ip, ip_filter, cors. " +
			"Chaque proposition donne la valeur à poser, la commande qui la pose, ce que le profil a vu (justification), ce qu'elle aurait refusé sur le trafic appris " +
			"(would_refuse sur of, quand c'est mesurable), et ses limites (cautions). Un réglage que le proxy a déjà n'est jamais remplacé ; un réglage que le profil " +
			"ne permet pas de proposer est dans skipped avec sa raison. Tant que convergence.converged est faux, le profil n'est pas fiable : attendre. Ne modifie rien ; " +
			"pour appliquer, update_proxy avec options (même clé, même valeur).",
		"inputSchema": schema(
			req("proxy", "string", "Identifiant ou hôte du proxy"),
			opt("edge", "string", "Passerelle (nom du nœud ou id du token) ; défaut : toutes"),
		),
	}, {
		"name": "get_proxy_surface_openapi",
		"description": "Politique positive d'un proxy (ADR 0016, étape 3) : une spécification OpenAPI générée à partir de son profil de surface, sous la forme du " +
			"réglage `openapi` du proxy, en mode detect (rien n'est refusé, les requêtes hors de la politique sont comptées et listées dans le rapport de surface). " +
			"Contient les chemins (/api/users/{users_id}), méthodes, paramètres typés et types de contenu appris ; pas les corps. Les chemins vus par trop peu de clients " +
			"ou de jours sont dans excluded (include_low_support=true pour les garder). Tant que `ready` est faux, le profil n'est pas fiable. Ne modifie rien : pour poser " +
			"la politique, update_proxy avec options {\"openapi\": <config>}.",
		"inputSchema": schema(
			req("proxy", "string", "Identifiant ou hôte du proxy"),
			opt("include_low_support", "boolean", "Garder aussi les chemins à faible soutien (défaut : non)"),
			opt("edge", "string", "Passerelle (nom du nœud ou id du token) ; défaut : toutes"),
		),
	}, {
		"name": "get_app_inventory",
		"description": "Applications que chaque passerelle reconnaît derrière ses proxies (ADR 0017) : produit, version, identifiant CPE et l'image du conteneur qui les a fait " +
			"reconnaître (annoncée par l'Agent, donc seulement pour les proxies créés par labels). C'est ce que le scanner de vulnérabilités cherche dans NVD : un produit sans " +
			"version (étiquette latest) est sondé sur le backend, un produit sans CPE sûr est listé sans être cherché. Ne modifie rien.",
		"inputSchema": schema(
			opt("proxy", "string", "Identifiant ou hôte du proxy ; vide = tous"),
			opt("edge", "string", "Passerelle (nom du nœud ou id du token) ; défaut : toutes"),
		),
	}, {
		"name": "get_proxy_surface_suggestions",
		"description": "Ajouts suggérés à la politique de surface d'un proxy (ADR 0016, étape 5). Le mode learn reste actif une fois la politique posée : un chemin ou une " +
			"méthode hors politique (unknown_path, unknown_method) qui revient de plusieurs clients propres sur plusieurs jours est suggéré, avec sa preuve. Confiance haute : " +
			"le backend a servi ces requêtes (5 au moins, 3 clients propres, 2 jours). Confiance basse : le contrôle les refuse, seuls des clients propres reviennent " +
			"(5 clients, 3 jours) ; un scanner distribué ressemble à cela, à examiner. Les chemins de scanner connus (.env, wp-login…) ne sont jamais suggérés. " +
			"Ne modifie rien ; la politique ne s'élargit jamais seule : accept_proxy_surface_suggestions.",
		"inputSchema": schema(
			req("proxy", "string", "Identifiant ou hôte du proxy"),
			opt("edge", "string", "Passerelle (nom du nœud ou id du token) ; défaut : toutes"),
		),
	}, {
		"name": "accept_proxy_surface_suggestions",
		"description": "Ajoute des suggestions à la politique openapi d'un proxy (ADR 0016, étape 5) : le chemin ou la méthode est ajouté à la spécification, rien n'est retiré, " +
			"et les violations correspondantes sont effacées du profil. Seules les suggestions actuelles du profil (clés de get_proxy_surface_suggestions) peuvent être ajoutées. " +
			"`all_high` ajoute toutes celles de confiance haute. La spécification doit être en JSON (celle que get_proxy_surface_openapi génère) ; un texte YAML est refusé, sans " +
			"rien modifier. `dry_run` calcule sans écrire. Un refus ne modifie rien et dit pourquoi (blockers).",
		"inputSchema": schema(
			req("proxy", "string", "Identifiant ou hôte du proxy"),
			opt("keys", "array", "Clés des suggestions à ajouter (« raison MÉTHODE chemin », telles que rendues par get_proxy_surface_suggestions)"),
			opt("all_high", "boolean", "Ajouter toutes les suggestions de confiance haute"),
			opt("dry_run", "boolean", "Calculer le résultat sans rien écrire"),
			opt("edge", "string", "Passerelle (nom du nœud ou id du token) ; défaut : toutes"),
		),
	}, {
		"name": "enforce_proxy_surface",
		"description": "Passe en block la politique de surface d'un proxy, type de violation par type de violation (ADR 0016, étape 4) : le contrôle openapi du proxy " +
			"refuse alors les violations de ces types (`reasons` : unknown_path, unknown_method, invalid_param, invalid_body, unsupported_media, too_large) et laisse " +
			"passer, en les comptant, les autres. Garde-fous : le proxy doit avoir une politique openapi active (get_proxy_surface_openapi, à poser en detect d'abord) " +
			"et un profil ; le profil doit être convergé ; aucun chemin probablement légitime (`likely_legit` dans get_proxy_surface) ne doit manquer pour ces types. " +
			"Un refus des garde-fous ne modifie rien et dit lesquels (blockers). `force` passe outre le profil non convergé et les chemins à ajouter (consigné à l'audit), " +
			"jamais l'absence de politique ou de profil. `dry_run` calcule sans écrire. Retour en detect : relax_proxy_surface.",
		"inputSchema": schema(
			req("proxy", "string", "Identifiant ou hôte du proxy"),
			req("reasons", "array", "Types de violation à refuser : unknown_path, unknown_method, invalid_param, invalid_body, unsupported_media, too_large"),
			opt("dry_run", "boolean", "Calculer le résultat sans rien écrire"),
			opt("force", "boolean", "Passer outre les garde-fous qui peuvent l'être (consigné à l'audit)"),
			opt("edge", "string", "Passerelle (nom du nœud ou id du token) ; défaut : toutes"),
		),
	}, {
		"name": "relax_proxy_surface",
		"description": "Remet le contrôle openapi d'un proxy en detect : plus rien n'est refusé, les violations restent comptées et listées dans le rapport de surface. " +
			"La politique (spécification) est conservée.",
		"inputSchema": schema(
			req("proxy", "string", "Identifiant ou hôte du proxy"),
		),
	}, {
		"name": "reset_proxy_surface",
		"description": "Efface le profil de surface d'un proxy sur toutes les passerelles (ou sur `edge`) : l'apprentissage repart de zéro. À faire quand " +
			"l'application a changé. N'affecte pas le trafic ni la configuration du proxy.",
		"inputSchema": schema(
			req("proxy", "string", "Identifiant ou hôte du proxy"),
			opt("edge", "string", "Passerelle (nom du nœud ou id du token) ; défaut : toutes"),
		),
	}}
}

func init() { tools = append(tools, surfaceTools()...) }

func (h *Handler) toolGetProxySurface(r *http.Request, args map[string]any) (any, error) {
	edgeID, _ := args["edge"].(string)
	route, _ := args["proxy"].(string)
	src := &prismedge.Source{DB: h.DB}
	if strings.TrimSpace(route) == "" {
		return api.SurfaceList(r.Context(), h.DB, src, edgeID)
	}
	return api.SurfaceReport(r.Context(), h.DB, src, edgeID, strings.TrimSpace(route))
}

func (h *Handler) toolGetProxySurfaceProposals(r *http.Request, args map[string]any) (any, error) {
	edgeID, _ := args["edge"].(string)
	route, _ := args["proxy"].(string)
	if strings.TrimSpace(route) == "" {
		return nil, fmt.Errorf("proxy requis (identifiant ou hôte)")
	}
	return api.SurfaceProposals(r.Context(), h.DB, &prismedge.Source{DB: h.DB}, edgeID, strings.TrimSpace(route))
}

func (h *Handler) toolGetProxySurfaceOpenAPI(r *http.Request, args map[string]any) (any, error) {
	edgeID, _ := args["edge"].(string)
	route, _ := args["proxy"].(string)
	low, _ := args["include_low_support"].(bool)
	if strings.TrimSpace(route) == "" {
		return nil, fmt.Errorf("proxy requis (identifiant ou hôte)")
	}
	return api.SurfaceOpenAPI(r.Context(), h.DB, &prismedge.Source{DB: h.DB}, edgeID, strings.TrimSpace(route), low)
}

func (h *Handler) toolResetProxySurface(r *http.Request, args map[string]any) (any, error) {
	edgeID, _ := args["edge"].(string)
	route, _ := args["proxy"].(string)
	if strings.TrimSpace(route) == "" {
		return nil, fmt.Errorf("proxy requis (identifiant ou hôte)")
	}
	return api.SurfaceReset(r.Context(), h.DB, &prismedge.Source{DB: h.DB}, edgeID, strings.TrimSpace(route))
}

// MutateProxyConfig écrit la configuration d'un proxy par le chemin de update_proxy : relue sur les passerelles, modifiée, publiée.
func (h *Handler) MutateProxyConfig(ctx context.Context, ref, actor string, mutate func(cfg map[string]any) error) (string, error) {
	id, name, cfgJSON, enabled, err := h.resolveProxyID(ctx, ref)
	if err != nil {
		return "", err
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		return id, err
	}
	if err := mutate(cfg); err != nil {
		return id, err
	}
	cfg["id"] = id
	cfg["updated_at"] = time.Now().UTC()
	out, err := json.Marshal(cfg)
	if err != nil {
		return id, err
	}
	if err := h.publishToEdges(ctx, id, name, enabled == 1, out, actor); err != nil {
		return id, err
	}
	_ = admindb.WriteAudit(h.DB, actor, "update", "proxy:"+id, name)
	return id, nil
}

func (h *Handler) toolEnforceProxySurface(r *http.Request, args map[string]any) (any, error) {
	route, _ := args["proxy"].(string)
	if strings.TrimSpace(route) == "" {
		return nil, fmt.Errorf("proxy requis (identifiant ou hôte)")
	}
	var req api.EnforceRequest
	if list, ok := args["reasons"].([]any); ok {
		for _, e := range list {
			if s, ok := e.(string); ok {
				req.Reasons = append(req.Reasons, s)
			}
		}
	}
	req.Force, _ = args["force"].(bool)
	req.DryRun, _ = args["dry_run"].(bool)
	edgeID, _ := args["edge"].(string)
	res, err := api.EnforceSurface(r.Context(), h.DB, &prismedge.Source{DB: h.DB}, h, adminauth.ActorFromContext(r.Context()), edgeID, strings.TrimSpace(route), req)
	if err != nil && api.EnforceStatus(err) == http.StatusConflict {
		// Un refus des garde-fous est une réponse, pas une panne : le résultat dit lesquels.
		return res, nil
	}
	if err != nil {
		return nil, errors.New(err.Error())
	}
	return res, nil
}

func (h *Handler) toolRelaxProxySurface(r *http.Request, args map[string]any) (any, error) {
	route, _ := args["proxy"].(string)
	if strings.TrimSpace(route) == "" {
		return nil, fmt.Errorf("proxy requis (identifiant ou hôte)")
	}
	res, err := api.RelaxSurface(r.Context(), h.DB, h, adminauth.ActorFromContext(r.Context()), strings.TrimSpace(route))
	if err != nil && api.EnforceStatus(err) == http.StatusConflict {
		return res, nil
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (h *Handler) toolGetProxySurfaceSuggestions(r *http.Request, args map[string]any) (any, error) {
	edgeID, _ := args["edge"].(string)
	route, _ := args["proxy"].(string)
	if strings.TrimSpace(route) == "" {
		return nil, fmt.Errorf("proxy requis (identifiant ou hôte)")
	}
	return api.SurfaceSuggestions(r.Context(), h.DB, &prismedge.Source{DB: h.DB}, edgeID, strings.TrimSpace(route))
}

func (h *Handler) toolAcceptProxySurfaceSuggestions(r *http.Request, args map[string]any) (any, error) {
	route, _ := args["proxy"].(string)
	if strings.TrimSpace(route) == "" {
		return nil, fmt.Errorf("proxy requis (identifiant ou hôte)")
	}
	var req api.AcceptRequest
	if list, ok := args["keys"].([]any); ok {
		for _, e := range list {
			if s, ok := e.(string); ok {
				req.Keys = append(req.Keys, s)
			}
		}
	}
	req.AllHigh, _ = args["all_high"].(bool)
	req.DryRun, _ = args["dry_run"].(bool)
	edgeID, _ := args["edge"].(string)
	res, err := api.AcceptSurface(r.Context(), h.DB, &prismedge.Source{DB: h.DB}, h, adminauth.ActorFromContext(r.Context()), edgeID, strings.TrimSpace(route), req)
	if err != nil && api.EnforceStatus(err) == http.StatusConflict {
		return res, nil
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (h *Handler) toolGetAppInventory(r *http.Request, args map[string]any) (any, error) {
	edgeID, _ := args["edge"].(string)
	route, _ := args["proxy"].(string)
	return api.Inventory(r.Context(), h.DB, &prismedge.Source{DB: h.DB}, edgeID, strings.TrimSpace(route))
}
