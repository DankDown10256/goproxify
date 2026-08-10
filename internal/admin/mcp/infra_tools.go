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
			"name":        "list_declared_nodes",
			"description": "Liste les nœuds déclarés (wizard architecture / Infrastructure) pas encore connectés.",
			"inputSchema": schema(),
		},
		{
			"name":        "create_declared_node",
			"description": "Déclare un nœud Core ou Agent (upsert par rôle+nom) pour le suivi wizard / auto-accept.",
			"inputSchema": schema(
				req("role", "string", "core ou agent"),
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
			"description": "Crée un ticket bootstrap (QR + lien /i/{token} + curl|bash) ancré au Core pour intégrer un hôte.",
			"inputSchema": schema(
				opt("host_name", "string", "Nom de l'hôte (affichage)"),
				opt("core_endpoint", "string", "Endpoint Core cible (ex: http://core:8000)"),
				opt("payload", "object", "Payload JSON (compose/.env dérivés côté UI)"),
				opt("ttl_hours", "number", "TTL en heures (1–168, défaut 24)"),
				opt("auto_accept", "boolean", "Auto-accept des nœuds déclarés liés (défaut true)"),
				opt("node_names", "array", "Noms de nœuds à lier pour l'auto-accept"),
			),
		},
		{
			"name":        "accept_node",
			"description": "Accepte un nœud Core/Agent en attente (pending_nodes) après présentation du pairing secret.",
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
	if v := argStr(args, "core_endpoint"); v != "" {
		body["core_endpoint"] = v
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
