// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/api"
)

func (h *Handler) nodesHandler() *api.NodesHandler {
	return &api.NodesHandler{DB: h.DB, Log: h.Log}
}

func (h *Handler) declaredNodesHandler() *api.DeclaredNodesHandler {
	return &api.DeclaredNodesHandler{DB: h.DB, Log: h.Log}
}

func (h *Handler) bootstrapHandler() *api.BootstrapHandler {
	return &api.BootstrapHandler{
		DB:               h.DB,
		Log:              h.Log,
		ResolvePublicURL: h.ResolvePublicURL,
	}
}

func (h *Handler) callNodes(r *http.Request, method, path string, body any) (any, error) {
	return h.callHandler(r, h.nodesHandler(), method, path, body)
}

func (h *Handler) callDeclared(r *http.Request, method, path string, body any) (any, error) {
	return h.callHandler(r, h.declaredNodesHandler(), method, path, body)
}

func infraTools() []map[string]any {
	return []map[string]any{
		{
			"name":        "get_topology_live",
			"description": "État temps réel de la topologie : pour chaque nœud passerelle/Agent, santé, CPU/mémoire, débit (req/s sur 60 s), taux de refus (403/429) et d'erreurs 5xx, score de risque 0-100 avec le facteur dominant (offline, blocked, errors, resources), plus le nombre de bans actifs.",
			"inputSchema": schema(),
		},
		{
			"name":        "get_architecture",
			"description": "Architecture déclarée (architecture.json, référentiel de la topologie) : nœuds passerelle/Agent avec leur hôte, région et capacités (HA, TLS, Docker, Portainer…), plus les domaines et, par groupe HA, la version de sa fiche (`groups`). Sans argument : l'architecture courante ; avec `version` : une version conservée (voir `goproxify architecture versions`).",
			"inputSchema": schema(
				opt("version", "string", "Nom d'une version conservée (architecture-….json) ; vide = version courante"),
			),
		},
		{
			"name":        "list_discovery_sources",
			"description": "Sources de découverte de l'Agent (Docker/Podman, Portainer, Kubernetes, Consul, Nomad, etcd, Amazon ECS) avec leurs champs de configuration (clé, secret, requis) pour la section sources.<type> de agent.json.",
			"inputSchema": schema(),
		},
		{
			"name":        "list_declared_nodes",
			"description": "Liste les nœuds déclarés (wizard architecture / Infrastructure) pas encore connectés.",
			"inputSchema": schema(),
		},
		{
			"name":        "create_declared_node",
			"description": "Déclare un nœud passerelle ou Agent (upsert par rôle+nom) pour le suivi wizard / auto-accept.",
			"inputSchema": schema(
				req("role", "string", "edge ou agent"),
				req("name", "string", "Nom du nœud"),
				opt("region", "string", "Région"),
				opt("environment", "string", "Environnement"),
				opt("config", "object", "Config JSON libre (placement, options…)"),
			),
		},
		{
			"name":        "delete_declared_node",
			"description": "Supprime un nœud déclaré par son ID (dn_…).",
			"inputSchema": schema(req("id", "string", "ID du nœud déclaré")),
		},
		{
			"name":        "create_bootstrap_ticket",
			"description": "Crée un ticket bootstrap (QR + lien /i/{token} + curl|bash) ancré à la passerelle pour intégrer un hôte.",
			"inputSchema": schema(
				opt("host_name", "string", "Nom de l'hôte (affichage)"),
				opt("edge_endpoint", "string", "Endpoint passerelle cible (ex: http://edge:8000)"),
				opt("payload", "object", "Payload JSON (compose/.env dérivés côté UI)"),
				opt("ttl_hours", "number", "TTL en heures (1–168, défaut 24)"),
				opt("auto_accept", "boolean", "Auto-accept des nœuds déclarés liés (défaut true)"),
				opt("node_names", "array", "Noms de nœuds à lier pour l'auto-accept"),
			),
		},
		{
			"name":        "list_hosts",
			"description": "Liste les hôtes déclarés dans architecture.json (adresse, rôles, groupe HA), leur état (pending, partial, joined), leurs nœuds et le ticket d'installation en cours.",
			"inputSchema": schema(),
		},
		{
			"name":        "create_host_join_ticket",
			"description": "Crée pour un hôte déclaré un ticket d'installation de 15 minutes (remplace le précédent) : jeton, adresse où le launcher récupère la description de l'hôte, et empreinte du certificat de l'Admin à vérifier. Refusé si l'hôte est déjà intégré.",
			"inputSchema": schema(req("host", "string", "Nom de l'hôte déclaré")),
		},
		{
			"name":        "accept_node",
			"description": "Accepte un nœud passerelle/Agent en attente (pending_nodes) après présentation du pairing secret.",
			"inputSchema": schema(req("id", "string", "ID du nœud pending")),
		},
		{
			"name":        "reject_node",
			"description": "Rejette un nœud en attente d'acceptation.",
			"inputSchema": schema(req("id", "string", "ID du nœud pending")),
		},
	}
}

func (h *Handler) toolListDeclaredNodes(r *http.Request) (any, error) {
	return h.callDeclared(r, http.MethodGet, "/api/v1/declared-nodes", nil)
}

func (h *Handler) toolGetArchitecture(args map[string]any) (any, error) {
	if h.ArchStore == nil {
		return nil, fmt.Errorf("architecture.json indisponible (persistance disque désactivée)")
	}
	if v := argStr(args, "version"); v != "" {
		return h.ArchStore.Version(v)
	}
	return h.ArchStore.Get()
}

func (h *Handler) toolListHosts(r *http.Request) (any, error) {
	if h.Hosts == nil {
		return nil, fmt.Errorf("hôtes indisponibles")
	}
	return h.Hosts.List(r)
}

func (h *Handler) toolCreateHostJoinTicket(r *http.Request, args map[string]any) (any, error) {
	if h.Hosts == nil {
		return nil, fmt.Errorf("hôtes indisponibles")
	}
	host := argStr(args, "host")
	if host == "" {
		return nil, fmt.Errorf("host requis")
	}
	return h.Hosts.CreateTicket(r, host)
}

func (h *Handler) toolCreateDeclaredNode(r *http.Request, args map[string]any) (any, error) {
	role := strings.ToLower(argStr(args, "role"))
	name := argStr(args, "name")
	if role == "" || name == "" {
		return nil, fmt.Errorf("role et name requis")
	}
	body := map[string]any{
		"role":        role,
		"name":        name,
		"region":      argStr(args, "region"),
		"environment": argStr(args, "environment"),
	}
	if cfg, ok := args["config"]; ok && cfg != nil {
		body["config"] = cfg
	}
	return h.callDeclared(r, http.MethodPost, "/api/v1/declared-nodes", body)
}

func (h *Handler) toolDeleteDeclaredNode(r *http.Request, args map[string]any) (any, error) {
	id := argStr(args, "id")
	if id == "" {
		return nil, fmt.Errorf("id requis")
	}
	return h.callDeclared(r, http.MethodDelete, "/api/v1/declared-nodes/"+id, nil)
}

func (h *Handler) toolCreateBootstrapTicket(r *http.Request, args map[string]any) (any, error) {
	body := map[string]any{}
	if v := argStr(args, "host_name"); v != "" {
		body["host_name"] = v
	}
	if v := argStr(args, "edge_endpoint"); v != "" {
		body["edge_endpoint"] = v
	}
	if ttl := argInt(args, "ttl_hours", 0); ttl > 0 {
		body["ttl_hours"] = ttl
	}
	if b := argBoolPtr(args, "auto_accept"); b != nil {
		body["auto_accept"] = *b
	}
	if names := argStringSlice(args, "node_names"); names != nil {
		body["node_names"] = names
	}
	if payload, ok := args["payload"]; ok && payload != nil {
		body["payload"] = payload
	} else {
		body["payload"] = map[string]any{}
	}
	bh := h.bootstrapHandler()
	return h.callHandler(r, http.HandlerFunc(bh.ServeCreate), http.MethodPost, "/api/v1/bootstrap-tickets", body)
}

func (h *Handler) toolAcceptNode(r *http.Request, args map[string]any) (any, error) {
	id := argStr(args, "id")
	if id == "" {
		return nil, fmt.Errorf("id requis")
	}
	return h.callNodes(r, http.MethodPost, "/api/v1/nodes/"+id+"/accept", nil)
}

func (h *Handler) toolRejectNode(r *http.Request, args map[string]any) (any, error) {
	id := argStr(args, "id")
	if id == "" {
		return nil, fmt.Errorf("id requis")
	}
	return h.callNodes(r, http.MethodPost, "/api/v1/nodes/"+id+"/reject", nil)
}

func (h *Handler) toolGetTopologyLive(r *http.Request) (any, error) {
	return h.callNodes(r, http.MethodGet, "/api/v1/nodes/live", nil)
}
