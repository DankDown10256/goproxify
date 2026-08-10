// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package mcp implémente un serveur MCP (Model Context Protocol) pour Goproxify.
// Il expose les ressources et outils de l'Administration via JSON-RPC 2.0 over HTTP.
// Spec: https://spec.modelcontextprotocol.io
package mcp

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/rbac"
)

const mcpVersion = "2025-03-26"

// AgentInfo décrit un Agent vu via le plan de contrôle WS.
type AgentInfo struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Version string    `json:"version"`
	Status  string    `json:"status"`
	SeenAt  time.Time `json:"seen_at"`
}

// Handler implémente http.Handler pour le endpoint MCP.
type Handler struct {
	DB     *sql.DB
	Log    *slog.Logger
	Pusher RoutePusher // optionnel — push vers les Cores après create/delete/update
	// Access (optionnel) — push config / templates portail vers les Cores.
	Access          AccessPusher
	AccessTemplates AccessTemplatesPusher
	// Agents (optionnel) — registre en mémoire Admin ; callbacks WS.
	ListAgents   func() []AgentInfo
	ApproveAgent func(agentID string)
	RevokeAgent  func(agentID string)
	// OnBansChange (optionnel) — push_bans vers les Cores après create/delete ban.
	OnBansChange func()
	// ResolvePublicURL (optionnel) — base publique Admin pour les tickets bootstrap (QR / curl|bash).
	ResolvePublicURL func(r *http.Request) string
}

// RoutePusher est implémenté par corews.Manager / corepush.Pusher (évite un import cyclique).
type RoutePusher interface {
	PushRoutes(ctx context.Context)
	DeleteRoute(ctx context.Context, id string)
}

// --- JSON-RPC 2.0 types --------------------------------------------------

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      any       `json:"id,omitempty"`
	Result  any       `json:"result,omitempty"`
	Error   *rpcError `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func errResp(id any, code int, msg string) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

func okResp(id any, result any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

// ServeHTTP gère POST /mcp (requêtes JSON-RPC) et GET /mcp/sse (stream SSE).
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/mcp")
	path = strings.TrimPrefix(path, "/")

	if r.Method == http.MethodGet && path == "sse" {
		h.serveSSE(w, r)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "méthode non supportée", http.StatusMethodNotAllowed)
		return
	}

	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		json.NewEncoder(w).Encode(errResp(nil, -32700, "parse error")) //nolint:errcheck
		return
	}

	w.Header().Set("Content-Type", "application/json")
	var resp rpcResponse
	switch req.Method {
	case "initialize":
		resp = h.handleInitialize(req)
	case "tools/list":
		resp = h.handleToolsList(req)
	case "tools/call":
		resp = h.handleToolsCall(req, r)
	case "resources/list":
		resp = h.handleResourcesList(req)
	case "resources/read":
		resp = h.handleResourcesRead(req, r)
	case "prompts/list":
		resp = okResp(req.ID, map[string]any{"prompts": []any{}})
	default:
		resp = errResp(req.ID, -32601, "method not found: "+req.Method)
	}
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

// --- initialize ----------------------------------------------------------

func (h *Handler) handleInitialize(req rpcRequest) rpcResponse {
	return okResp(req.ID, map[string]any{
		"protocolVersion": mcpVersion,
		"capabilities": map[string]any{
			"tools":     map[string]any{"listChanged": false},
			"resources": map[string]any{"listChanged": false},
		},
		"serverInfo": map[string]any{
			"name":    "goproxify",
			"version": "0.2.15",
		},
	})
}

// --- Schema helpers ------------------------------------------------------

// param décrit un paramètre d'outil MCP.
type param struct {
	name, typ, desc string
	required        bool
}

func req(name, typ, desc string) param { return param{name, typ, desc, true} }
func opt(name, typ, desc string) param { return param{name, typ, desc, false} }

// schema construit un inputSchema JSON Schema à partir de paramètres typés.
func schema(params ...param) map[string]any {
	props := map[string]any{}
	var required []string
	for _, p := range params {
		props[p.name] = map[string]any{"type": p.typ, "description": p.desc}
		if p.required {
			required = append(required, p.name)
		}
	}
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

// --- tools/list ----------------------------------------------------------

var tools = []map[string]any{
	// Proxies
	{
		"name":        "list_proxies",
		"description": "Liste toutes les routes proxy (HTTP, TCP, UDP) configurées.",
		"inputSchema": schema(),
	},
	{
		"name":        "get_proxy",
		"description": "Retourne la configuration complète d'un proxy par son ID ou son domaine.",
		"inputSchema": schema(req("id", "string", "ID ou domaine du proxy")),
	},
	{
		"name":        "create_proxy",
		"description": "Crée une nouvelle route proxy (HTTP/TCP/UDP). Retourne l'ID créé.",
		"inputSchema": schema(
			req("host", "string", "Domaine (ex: app.example.com)"),
			req("backend", "string", "URL du backend (ex: http://10.0.0.5:3000)"),
			opt("tls_enabled", "boolean", "Active HTTPS (défaut: false)"),
			opt("type", "string", "Type de route: http (défaut), tcp, udp"),
			opt("lb", "string", "Load balancing: round_robin (défaut), weighted, adaptive"),
		),
	},
	{
		"name":        "update_proxy",
		"description": "Met à jour un proxy existant (host, backend, tls, lb, enabled).",
		"inputSchema": schema(
			req("id", "string", "ID, nom ou domaine du proxy"),
			opt("host", "string", "Nouveau domaine"),
			opt("backend", "string", "Nouvelle URL backend (remplace la liste backends)"),
			opt("tls_enabled", "boolean", "Active ou désactive HTTPS"),
			opt("lb", "string", "Load balancing: round_robin, weighted, adaptive"),
			opt("enabled", "boolean", "Active ou désactive la route"),
		),
	},
	{
		"name":        "set_proxy_enabled",
		"description": "Active ou désactive un proxy sans modifier sa configuration.",
		"inputSchema": schema(
			req("id", "string", "ID, nom ou domaine du proxy"),
			req("enabled", "boolean", "true = activer, false = désactiver"),
		),
	},
	{
		"name":        "delete_proxy",
		"description": "Supprime un proxy par son ID.",
		"inputSchema": schema(req("id", "string", "ID du proxy à supprimer")),
	},
	// Nœuds / Agents
	{
		"name":        "list_nodes",
		"description": "Liste les nœuds Core et Agent avec leurs métriques (CPU, mémoire, statut).",
		"inputSchema": schema(),
	},
	{
		"name":        "list_agents",
		"description": "Liste les Agents vus via WebSocket (pending, approved, revoked).",
		"inputSchema": schema(),
	},
	{
		"name":        "approve_agent",
		"description": "Approuve un Agent en attente (envoie approve_agent aux Cores via WS).",
		"inputSchema": schema(req("id", "string", "ID de l'Agent à approuver")),
	},
	{
		"name":        "revoke_agent",
		"description": "Révoque un Agent (ferme la session WS et invalide le HMAC).",
		"inputSchema": schema(req("id", "string", "ID de l'Agent à révoquer")),
	},
	// Alertes
	{
		"name":        "list_alerts",
		"description": "Liste les règles d'alerting configurées avec leurs déclencheurs et canaux.",
		"inputSchema": schema(),
	},
	// Métriques
	{
		"name":        "get_metrics",
		"description": "Retourne les KPIs de trafic des dernières 24h (requêtes, erreurs, latence).",
		"inputSchema": schema(opt("proxy", "string", "Filtrer par domaine proxy (laisser vide pour tout le trafic)")),
	},
	// Sauvegardes
	{
		"name":        "list_backups",
		"description": "Liste les snapshots de sauvegarde disponibles (20 derniers).",
		"inputSchema": schema(),
	},
	// Utilisateurs
	{
		"name":        "list_users",
		"description": "Liste les utilisateurs enregistrés avec leur rôle (sans données sensibles).",
		"inputSchema": schema(),
	},
	// Snippets
	{
		"name":        "list_snippets",
		"description": "Liste les snippets middleware réutilisables (headers, rate-limit, auth…).",
		"inputSchema": schema(),
	},
	// Domaines
	{
		"name":        "list_domains",
		"description": "Liste les domaines gérés avec leur fournisseur DNS et état du certificat.",
		"inputSchema": schema(),
	},
	// Certificats
	{
		"name":        "list_certs",
		"description": "Liste les certificats TLS avec leur domaine, émetteur et date d'expiration.",
		"inputSchema": schema(),
	},
	// Logs
	{
		"name":        "list_logs",
		"description": "Retourne les derniers logs d'accès (100 entrées max).",
		"inputSchema": schema(
			opt("domain", "string", "Filtrer par domaine proxy"),
			opt("level", "string", "Filtrer par niveau (info, warn, error)"),
		),
	},
	// Équipes
	{
		"name":        "list_teams",
		"description": "Liste les équipes et leur nombre de membres.",
		"inputSchema": schema(),
	},
	// Audit
	{
		"name":        "get_audit_log",
		"description": "Retourne le journal d'audit des actions administratives récentes.",
		"inputSchema": schema(opt("limit", "number", "Nombre d'entrées à retourner (défaut: 50, max: 200)")),
	},
	// Sécurité
	{
		"name":        "get_security_overview",
		"description": "Vue d'ensemble sécurité : bans actifs, menaces CrowdSec, CVE ouvertes, certs expirants.",
		"inputSchema": schema(),
	},
	{
		"name":        "list_security_bans",
		"description": "Liste les bans IP (Fail2Ban, CrowdSec, natif).",
		"inputSchema": schema(
			opt("ip", "string", "Filtrer par IP (sous-chaîne)"),
			opt("source", "string", "Filtrer par source: native, fail2ban, crowdsec"),
			opt("active_only", "boolean", "Si true, uniquement les bans non expirés"),
		),
	},
	{
		"name":        "create_security_ban",
		"description": "Crée un ban IP natif (permanent par défaut). Pousse les bans aux Cores.",
		"inputSchema": schema(
			req("ip", "string", "Adresse IP à bannir"),
			opt("reason", "string", "Motif du ban"),
			opt("domain", "string", "Domaine ciblé (vide = global)"),
			opt("expires_at", "string", "Expiration RFC3339 ; omit = permanent"),
		),
	},
	{
		"name":        "delete_security_ban",
		"description": "Supprime un ban par son ID et resynchronise les Cores.",
		"inputSchema": schema(req("id", "string", "ID du ban")),
	},
	{
		"name":        "list_security_threats",
		"description": "Liste les décisions CrowdSec synchronisées (security_threats).",
		"inputSchema": schema(opt("limit", "number", "Nombre d'entrées (défaut: 100, max: 500)")),
	},
	{
		"name":        "list_security_cves",
		"description": "Liste les CVE détectées sur les backends.",
		"inputSchema": schema(
			opt("status", "string", "Filtrer: open, ignored, resolved"),
			opt("critical_only", "boolean", "Si true, CVSS >= 7 uniquement"),
		),
	},
}

func init() {
	tools = append(tools, portalTools()...)
	tools = append(tools, infraTools()...)
}

func (h *Handler) handleToolsList(req rpcRequest) rpcResponse {
	return okResp(req.ID, map[string]any{"tools": tools})
}

// --- tools/call ----------------------------------------------------------

func (h *Handler) handleToolsCall(req rpcRequest, r *http.Request) rpcResponse {
	var p struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return errResp(req.ID, -32602, "invalid params")
	}
	if p.Arguments == nil {
		p.Arguments = map[string]any{}
	}

	if scope := rbac.ToolRequiredScope(p.Name); scope != "" {
		if !rbac.EffectiveHasScope(r.Context(), h.DB, scope) {
			return okResp(req.ID, map[string]any{
				"content": []map[string]any{{"type": "text", "text": "Erreur: scope insuffisant: " + scope}},
				"isError": true,
			})
		}
	}

	var result any
	var toolErr error

	switch p.Name {
	case "list_proxies":
		result, toolErr = h.toolListProxies(r)
	case "get_proxy":
		id, _ := p.Arguments["id"].(string)
		result, toolErr = h.toolGetProxy(r, id)
	case "create_proxy":
		result, toolErr = h.toolCreateProxy(r, p.Arguments)
	case "update_proxy":
		result, toolErr = h.toolUpdateProxy(r, p.Arguments)
	case "set_proxy_enabled":
		result, toolErr = h.toolSetProxyEnabled(r, p.Arguments)
	case "delete_proxy":
		id, _ := p.Arguments["id"].(string)
		result, toolErr = h.toolDeleteProxy(r, id)
	case "list_nodes":
		result, toolErr = h.toolListNodes(r)
	case "list_agents":
		result, toolErr = h.toolListAgents()
	case "approve_agent":
		id, _ := p.Arguments["id"].(string)
		result, toolErr = h.toolApproveAgent(id)
	case "revoke_agent":
		id, _ := p.Arguments["id"].(string)
		result, toolErr = h.toolRevokeAgent(id)
	case "list_alerts":
		result, toolErr = h.toolListAlerts(r)
	case "get_metrics":
		proxy, _ := p.Arguments["proxy"].(string)
		result, toolErr = h.toolGetMetrics(r, proxy)
	case "list_backups":
		result, toolErr = h.toolListBackups(r)
	case "list_users":
		result, toolErr = h.toolListUsers(r)
	case "list_snippets":
		result, toolErr = h.toolListSnippets(r)
	case "list_domains":
		result, toolErr = h.toolListDomains(r)
	case "list_certs":
		result, toolErr = h.toolListCerts(r)
	case "list_logs":
		domain, _ := p.Arguments["domain"].(string)
		level, _ := p.Arguments["level"].(string)
		result, toolErr = h.toolListLogs(r, domain, level)
	case "list_teams":
		result, toolErr = h.toolListTeams(r)
	case "get_audit_log":
		limit := 50
		if v, ok := p.Arguments["limit"].(float64); ok && v > 0 {
			limit = int(v)
			if limit > 200 {
				limit = 200
			}
		}
		result, toolErr = h.toolGetAuditLog(r, limit)
	case "get_security_overview":
		result, toolErr = h.toolGetSecurityOverview(r)
	case "list_security_bans":
		result, toolErr = h.toolListSecurityBans(r, p.Arguments)
	case "create_security_ban":
		result, toolErr = h.toolCreateSecurityBan(r, p.Arguments)
	case "delete_security_ban":
		id, _ := p.Arguments["id"].(string)
		result, toolErr = h.toolDeleteSecurityBan(r, id)
	case "list_security_threats":
		result, toolErr = h.toolListSecurityThreats(r, p.Arguments)
	case "list_security_cves":
		result, toolErr = h.toolListSecurityCVEs(r, p.Arguments)
	case "get_portal_config":
		result, toolErr = h.toolGetPortalConfig(r, p.Arguments)
	case "update_portal_config":
		result, toolErr = h.toolUpdatePortalConfig(r, p.Arguments)
	case "push_portal":
		result, toolErr = h.toolPushPortal(r, p.Arguments)
	case "list_portal_destinations":
		result, toolErr = h.toolListPortalDestinations(r, p.Arguments)
	case "create_portal_destination":
		result, toolErr = h.toolCreatePortalDestination(r, p.Arguments)
	case "update_portal_destination":
		result, toolErr = h.toolUpdatePortalDestination(r, p.Arguments)
	case "delete_portal_destination":
		result, toolErr = h.toolDeletePortalDestination(r, p.Arguments)
	case "preview_portal_destinations":
		result, toolErr = h.toolPreviewPortalDestinations(r, p.Arguments)
	case "list_portal_users":
		result, toolErr = h.toolListPortalUsers(r, p.Arguments)
	case "invite_portal_user":
		result, toolErr = h.toolInvitePortalUser(r, p.Arguments)
	case "update_portal_user":
		result, toolErr = h.toolUpdatePortalUser(r, p.Arguments)
	case "delete_portal_user":
		result, toolErr = h.toolDeletePortalUser(r, p.Arguments)
	case "resend_portal_invite":
		result, toolErr = h.toolResendPortalInvite(r, p.Arguments)
	case "list_portal_audit":
		result, toolErr = h.toolListPortalAudit(r, p.Arguments)
	case "list_portal_templates":
		result, toolErr = h.toolListPortalTemplates(r)
	case "get_portal_template":
		result, toolErr = h.toolGetPortalTemplate(r, p.Arguments)
	case "upsert_portal_template":
		result, toolErr = h.toolUpsertPortalTemplate(r, p.Arguments)
	case "delete_portal_template":
		result, toolErr = h.toolDeletePortalTemplate(r, p.Arguments)
	case "push_portal_templates":
		result, toolErr = h.toolPushPortalTemplates(r)
	case "list_declared_nodes":
		result, toolErr = h.toolListDeclaredNodes(r)
	case "create_declared_node":
		result, toolErr = h.toolCreateDeclaredNode(r, p.Arguments)
	case "delete_declared_node":
		result, toolErr = h.toolDeleteDeclaredNode(r, p.Arguments)
	case "create_bootstrap_ticket":
		result, toolErr = h.toolCreateBootstrapTicket(r, p.Arguments)
	case "accept_node":
		result, toolErr = h.toolAcceptNode(r, p.Arguments)
	case "reject_node":
		result, toolErr = h.toolRejectNode(r, p.Arguments)
	default:
		return errResp(req.ID, -32601, "outil inconnu: "+p.Name)
	}

	if toolErr != nil {
		return okResp(req.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": "Erreur: " + toolErr.Error()}},
			"isError": true,
		})
	}
	text, _ := json.MarshalIndent(result, "", "  ")
	return okResp(req.ID, map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(text)}},
	})
}

// --- Tool implementations ------------------------------------------------

func (h *Handler) toolListProxies(r *http.Request) (any, error) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, name, enabled, json_extract(config,'$.host') as host,
		        json_extract(config,'$.type') as type,
		        json_extract(config,'$.tls_enabled') as tls
		 FROM proxies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, name, host, rtype string
		var enabled bool
		var tls *bool
		if err := rows.Scan(&id, &name, &enabled, &host, &rtype, &tls); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id": id, "name": name, "enabled": enabled, "host": host, "type": rtype, "tls": tls,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolGetProxy(r *http.Request, id string) (any, error) {
	var cfg string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT config FROM proxies WHERE id=? OR name=? OR json_extract(config,'$.host')=?`,
		id, id, id).Scan(&cfg)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("proxy introuvable: %s", id)
	}
	if err != nil {
		return nil, err
	}
	var out any
	json.Unmarshal([]byte(cfg), &out) //nolint:errcheck
	return out, nil
}

func (h *Handler) toolCreateProxy(r *http.Request, args map[string]any) (any, error) {
	host, _ := args["host"].(string)
	backend, _ := args["backend"].(string)
	tlsEnabled, _ := args["tls_enabled"].(bool)
	rtype, _ := args["type"].(string)
	lb, _ := args["lb"].(string)
	if host == "" || backend == "" {
		return nil, fmt.Errorf("host et backend requis")
	}
	if rtype == "" {
		rtype = "http"
	}
	switch rtype {
	case "http", "tcp", "udp":
	default:
		return nil, fmt.Errorf("type invalide: %s (http|tcp|udp)", rtype)
	}
	if lb == "" {
		lb = "round_robin"
	}
	id := uuid.New().String()
	now := time.Now().UTC()
	cfg := map[string]any{
		"id":          id,
		"host":        host,
		"type":        rtype,
		"backends":    []map[string]any{{"url": backend, "weight": 1}},
		"lb":          lb,
		"tls_enabled": tlsEnabled,
		"updated_at":  now,
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	_, err = h.DB.ExecContext(r.Context(),
		`INSERT INTO proxies (id, name, enabled, config) VALUES (?, ?, 1, ?)`,
		id, host, string(cfgJSON))
	if err != nil {
		return nil, err
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "create", "proxy:"+id, host)
	if h.Pusher != nil {
		go h.Pusher.PushRoutes(context.Background())
	}
	return map[string]any{"id": id, "host": host, "backend": backend, "type": rtype, "lb": lb}, nil
}

func (h *Handler) resolveProxyID(ctx context.Context, ref string) (id, name, cfgJSON string, enabled int, err error) {
	err = h.DB.QueryRowContext(ctx,
		`SELECT id, name, config, enabled FROM proxies
		 WHERE id=? OR name=? OR json_extract(config,'$.host')=?`,
		ref, ref, ref).Scan(&id, &name, &cfgJSON, &enabled)
	if err == sql.ErrNoRows {
		return "", "", "", 0, fmt.Errorf("proxy introuvable: %s", ref)
	}
	return id, name, cfgJSON, enabled, err
}

func (h *Handler) toolUpdateProxy(r *http.Request, args map[string]any) (any, error) {
	ref, _ := args["id"].(string)
	if ref == "" {
		return nil, fmt.Errorf("id requis")
	}
	id, name, cfgJSON, enabled, err := h.resolveProxyID(r.Context(), ref)
	if err != nil {
		return nil, err
	}
	var cfg map[string]any
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		return nil, err
	}
	changed := false
	if host, ok := args["host"].(string); ok && host != "" {
		cfg["host"] = host
		name = host
		changed = true
	}
	if backend, ok := args["backend"].(string); ok && backend != "" {
		cfg["backends"] = []map[string]any{{"url": backend, "weight": 1}}
		changed = true
	}
	if tls, ok := args["tls_enabled"].(bool); ok {
		cfg["tls_enabled"] = tls
		changed = true
	}
	if lb, ok := args["lb"].(string); ok && lb != "" {
		cfg["lb"] = lb
		changed = true
	}
	if en, ok := args["enabled"].(bool); ok {
		if en {
			enabled = 1
		} else {
			enabled = 0
		}
		changed = true
	}
	if !changed {
		return nil, fmt.Errorf("aucun champ à mettre à jour")
	}
	cfg["id"] = id
	cfg["updated_at"] = time.Now().UTC()
	outJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	_, err = h.DB.ExecContext(r.Context(),
		`UPDATE proxies SET name=?, config=?, enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		name, string(outJSON), enabled, id)
	if err != nil {
		return nil, err
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "update", "proxy:"+id, name)
	if h.Pusher != nil {
		go h.Pusher.PushRoutes(context.Background())
	}
	return map[string]any{"id": id, "name": name, "enabled": enabled == 1, "config": cfg}, nil
}

func (h *Handler) toolSetProxyEnabled(r *http.Request, args map[string]any) (any, error) {
	ref, _ := args["id"].(string)
	en, ok := args["enabled"].(bool)
	if ref == "" || !ok {
		return nil, fmt.Errorf("id et enabled requis")
	}
	id, name, _, _, err := h.resolveProxyID(r.Context(), ref)
	if err != nil {
		return nil, err
	}
	val := 0
	if en {
		val = 1
	}
	_, err = h.DB.ExecContext(r.Context(),
		`UPDATE proxies SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, val, id)
	if err != nil {
		return nil, err
	}
	action := "disable"
	if en {
		action = "enable"
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), action, "proxy:"+id, name)
	if h.Pusher != nil {
		go h.Pusher.PushRoutes(context.Background())
	}
	return map[string]any{"id": id, "enabled": en}, nil
}

func (h *Handler) toolDeleteProxy(r *http.Request, id string) (any, error) {
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM proxies WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, fmt.Errorf("proxy introuvable: %s", id)
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "delete", "proxy:"+id, "")
	if h.Pusher != nil {
		go h.Pusher.DeleteRoute(context.Background(), id)
	}
	return map[string]any{"deleted": id}, nil
}

func (h *Handler) toolListNodes(r *http.Request) (any, error) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, node_name, role, version, status,
		        COALESCE(cpu_pct,0), COALESCE(mem_pct,0), last_seen_at
		 FROM nodes ORDER BY node_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, name, role, ver, status string
		var cpu, mem float64
		var lastSeen time.Time
		if err := rows.Scan(&id, &name, &role, &ver, &status, &cpu, &mem, &lastSeen); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id": id, "node_name": name, "role": role, "version": ver,
			"status": status, "cpu_pct": cpu, "mem_pct": mem, "last_seen_at": lastSeen,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolListAgents() (any, error) {
	if h.ListAgents == nil {
		return []AgentInfo{}, nil
	}
	out := h.ListAgents()
	if out == nil {
		out = []AgentInfo{}
	}
	return out, nil
}

func (h *Handler) toolApproveAgent(id string) (any, error) {
	if id == "" {
		return nil, fmt.Errorf("id requis")
	}
	if h.ApproveAgent == nil {
		return nil, fmt.Errorf("approbation Agent non disponible")
	}
	h.ApproveAgent(id)
	return map[string]any{"status": "approved", "agent_id": id}, nil
}

func (h *Handler) toolRevokeAgent(id string) (any, error) {
	if id == "" {
		return nil, fmt.Errorf("id requis")
	}
	if h.RevokeAgent == nil {
		return nil, fmt.Errorf("révocation Agent non disponible")
	}
	h.RevokeAgent(id)
	return map[string]any{"status": "revoked", "agent_id": id}, nil
}

func (h *Handler) toolListAlerts(r *http.Request) (any, error) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, name, enabled, scope, triggers, channels, cooldown_sec, priority
		 FROM alert_rules ORDER BY priority`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, name, scope, triggers, channels string
		var enabled bool
		var cooldown, priority int
		if err := rows.Scan(&id, &name, &enabled, &scope, &triggers, &channels, &cooldown, &priority); err != nil {
			continue
		}
		var scopeObj, triggersObj, channelsObj any
		json.Unmarshal([]byte(scope), &scopeObj)       //nolint:errcheck
		json.Unmarshal([]byte(triggers), &triggersObj) //nolint:errcheck
		json.Unmarshal([]byte(channels), &channelsObj) //nolint:errcheck
		out = append(out, map[string]any{
			"id": id, "name": name, "enabled": enabled,
			"scope": scopeObj, "triggers": triggersObj, "channels": channelsObj,
			"cooldown_sec": cooldown, "priority": priority,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolGetMetrics(r *http.Request, proxy string) (any, error) {
	q := `SELECT
	  COUNT(*) AS requests,
	  SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) AS errors,
	  ROUND(100.0 * SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) / MAX(COUNT(*),1), 2) AS error_rate,
	  ROUND(AVG(latency_ms), 0) AS avg_latency_ms,
	  COUNT(DISTINCT ip) AS unique_ips
	FROM logs WHERE ts > datetime('now','-1 day')`
	args := []any{}
	if proxy != "" {
		q += ` AND domain = ?`
		args = append(args, proxy)
	}
	row := h.DB.QueryRowContext(r.Context(), q, args...)
	var reqs, errs int64
	var errRate, avgLat float64
	var ips int64
	if err := row.Scan(&reqs, &errs, &errRate, &avgLat, &ips); err != nil {
		return nil, err
	}
	return map[string]any{
		"requests": reqs, "errors": errs, "error_rate": errRate,
		"avg_latency_ms": avgLat, "unique_ips": ips,
		"window": "24h",
	}, nil
}

func (h *Handler) toolListBackups(r *http.Request) (any, error) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, name, size, created_at FROM backup_snapshots ORDER BY created_at DESC LIMIT 20`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, name string
		var size int64
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &size, &createdAt); err != nil {
			continue
		}
		out = append(out, map[string]any{"id": id, "name": name, "size_bytes": size, "created_at": createdAt})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolListUsers(r *http.Request) (any, error) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, email, role, created_at FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, email, role string
		var createdAt time.Time
		if err := rows.Scan(&id, &email, &role, &createdAt); err != nil {
			continue
		}
		out = append(out, map[string]any{"id": id, "email": email, "role": role, "created_at": createdAt})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolListSnippets(r *http.Request) (any, error) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, name, type, config, created_at FROM snippets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, name, typ, cfg string
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &typ, &cfg, &createdAt); err != nil {
			continue
		}
		var cfgObj any
		json.Unmarshal([]byte(cfg), &cfgObj) //nolint:errcheck
		out = append(out, map[string]any{"id": id, "name": name, "type": typ, "config": cfgObj, "created_at": createdAt})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolListDomains(r *http.Request) (any, error) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, domain, core_id, dns_provider, cert_method, delegation_mode,
		        cert_expires_at, created_at
		 FROM domains ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, domain, coreID, dnsProv, certMethod, delegMode string
		var certExpires *time.Time
		var createdAt time.Time
		if err := rows.Scan(&id, &domain, &coreID, &dnsProv, &certMethod, &delegMode, &certExpires, &createdAt); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id": id, "domain": domain, "core_id": coreID,
			"dns_provider": dnsProv, "cert_method": certMethod,
			"delegation_mode": delegMode, "cert_expires_at": certExpires,
			"created_at": createdAt,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolListCerts(r *http.Request) (any, error) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, domain, issuer, expires_at, updated_at FROM certs ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, domain, issuer string
		var expiresAt, updatedAt time.Time
		if err := rows.Scan(&id, &domain, &issuer, &expiresAt, &updatedAt); err != nil {
			continue
		}
		daysLeft := int(time.Until(expiresAt).Hours() / 24)
		out = append(out, map[string]any{
			"id": id, "domain": domain, "issuer": issuer,
			"expires_at": expiresAt, "days_until_expiry": daysLeft,
			"updated_at": updatedAt,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolListLogs(r *http.Request, domain, level string) (any, error) {
	q := `SELECT ts, level, component, domain, method, path, status, ip, latency_ms, message
	      FROM logs WHERE 1=1`
	args := []any{}
	if domain != "" {
		q += ` AND domain = ?`
		args = append(args, domain)
	}
	if level != "" {
		q += ` AND level = ?`
		args = append(args, level)
	}
	q += ` ORDER BY ts DESC LIMIT 100`
	rows, err := h.DB.QueryContext(r.Context(), q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var ts time.Time
		var lvl, component, dom, method, path, ip, message string
		var status, latency int
		if err := rows.Scan(&ts, &lvl, &component, &dom, &method, &path, &status, &ip, &latency, &message); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"ts": ts, "level": lvl, "component": component, "domain": dom,
			"method": method, "path": path, "status": status,
			"ip": ip, "latency_ms": latency, "message": message,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolListTeams(r *http.Request) (any, error) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT t.id, t.name,
		        (SELECT COUNT(*) FROM team_members WHERE team_id = t.id) AS member_count,
		        t.created_at
		 FROM teams t ORDER BY t.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, name string
		var members int
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &members, &createdAt); err != nil {
			continue
		}
		out = append(out, map[string]any{"id": id, "name": name, "member_count": members, "created_at": createdAt})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolGetAuditLog(r *http.Request, limit int) (any, error) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT actor, action, resource, detail, severity, created_at
		 FROM audit_log ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var actor, action, resource, detail, severity string
		var createdAt time.Time
		if err := rows.Scan(&actor, &action, &resource, &detail, &severity, &createdAt); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"actor": actor, "action": action, "resource": resource,
			"detail": detail, "severity": severity, "created_at": createdAt,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolGetSecurityOverview(r *http.Request) (any, error) {
	var activeBans, threats, openCVEs, expiringCerts int
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM security_bans WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP`).Scan(&activeBans)
	_ = h.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM security_threats`).Scan(&threats)
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM security_cves WHERE status='open'`).Scan(&openCVEs)
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM certs WHERE expires_at <= datetime('now', '+30 days')`).Scan(&expiringCerts)
	return map[string]any{
		"active_bans":     activeBans,
		"threats":         threats,
		"open_cves":       openCVEs,
		"expiring_certs":  expiringCerts,
	}, nil
}

func (h *Handler) toolListSecurityBans(r *http.Request, args map[string]any) (any, error) {
	var clauses []string
	var qargs []any
	if ip, _ := args["ip"].(string); ip != "" {
		clauses = append(clauses, "ip LIKE ?")
		qargs = append(qargs, "%"+ip+"%")
	}
	if source, _ := args["source"].(string); source != "" {
		clauses = append(clauses, "source=?")
		qargs = append(qargs, source)
	}
	if active, _ := args["active_only"].(bool); active {
		clauses = append(clauses, "(expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)")
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, ip, domain, reason, source, expires_at, created_at FROM security_bans`+where+
			` ORDER BY created_at DESC LIMIT 200`, qargs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, ip, domain, reason, source string
		var exp sql.NullString
		var createdAt string
		if err := rows.Scan(&id, &ip, &domain, &reason, &source, &exp, &createdAt); err != nil {
			continue
		}
		item := map[string]any{
			"id": id, "ip": ip, "domain": domain, "reason": reason,
			"source": source, "created_at": createdAt,
		}
		if exp.Valid {
			item["expires_at"] = exp.String
		} else {
			item["expires_at"] = nil
		}
		out = append(out, item)
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolCreateSecurityBan(r *http.Request, args map[string]any) (any, error) {
	ip, _ := args["ip"].(string)
	if ip == "" {
		return nil, fmt.Errorf("ip requis")
	}
	reason, _ := args["reason"].(string)
	domain, _ := args["domain"].(string)
	expiresAt, _ := args["expires_at"].(string)
	id := uuid.New().String()
	var exp any
	if expiresAt != "" {
		exp = expiresAt
	}
	_, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO security_bans (id, ip, domain, reason, source, expires_at) VALUES (?, ?, ?, ?, 'native', ?)`,
		id, ip, domain, reason, exp)
	if err != nil {
		return nil, err
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "create", "ban:"+id, ip)
	if h.OnBansChange != nil {
		h.OnBansChange()
	}
	return map[string]any{"id": id, "ip": ip, "permanent": expiresAt == ""}, nil
}

func (h *Handler) toolDeleteSecurityBan(r *http.Request, id string) (any, error) {
	if id == "" {
		return nil, fmt.Errorf("id requis")
	}
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM security_bans WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, fmt.Errorf("ban introuvable: %s", id)
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "delete", "ban:"+id, "")
	if h.OnBansChange != nil {
		h.OnBansChange()
	}
	return map[string]any{"deleted": id}, nil
}

func (h *Handler) toolListSecurityThreats(r *http.Request, args map[string]any) (any, error) {
	limit := 100
	if v, ok := args["limit"].(float64); ok && v > 0 {
		limit = int(v)
		if limit > 500 {
			limit = 500
		}
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, ip, scenario, origin, type, duration, created_at
		 FROM security_threats ORDER BY created_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id int
		var ip, scenario, origin, typ, duration, createdAt string
		if err := rows.Scan(&id, &ip, &scenario, &origin, &typ, &duration, &createdAt); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id": id, "ip": ip, "scenario": scenario, "origin": origin,
			"type": typ, "duration": duration, "created_at": createdAt,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolListSecurityCVEs(r *http.Request, args map[string]any) (any, error) {
	var clauses []string
	var qargs []any
	if status, _ := args["status"].(string); status != "" {
		clauses = append(clauses, "status=?")
		qargs = append(qargs, status)
	}
	if crit, _ := args["critical_only"].(bool); crit {
		clauses = append(clauses, "cvss_score>=7")
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, backend_url, cve_id, cvss_score, description, status, detected_at
		 FROM security_cves`+where+` ORDER BY cvss_score DESC, detected_at DESC LIMIT 200`, qargs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id int
		var backend, cveID, desc, status, detectedAt string
		var cvss float64
		if err := rows.Scan(&id, &backend, &cveID, &cvss, &desc, &status, &detectedAt); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id": id, "backend_url": backend, "cve_id": cveID, "cvss_score": cvss,
			"description": desc, "status": status, "detected_at": detectedAt,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

// --- resources/list + resources/read -------------------------------------

func (h *Handler) handleResourcesList(req rpcRequest) rpcResponse {
	return okResp(req.ID, map[string]any{
		"resources": []map[string]any{
			{"uri": "goproxify://proxies", "name": "Proxies", "description": "Liste de toutes les routes proxy", "mimeType": "application/json"},
			{"uri": "goproxify://nodes", "name": "Nœuds", "description": "Liste des nœuds Core et Agent", "mimeType": "application/json"},
			{"uri": "goproxify://agents", "name": "Agents", "description": "Agents WS (pending / approved)", "mimeType": "application/json"},
			{"uri": "goproxify://alerts", "name": "Alertes", "description": "Règles d'alerting", "mimeType": "application/json"},
			{"uri": "goproxify://users", "name": "Utilisateurs", "description": "Comptes utilisateurs et rôles", "mimeType": "application/json"},
			{"uri": "goproxify://snippets", "name": "Snippets", "description": "Middlewares réutilisables", "mimeType": "application/json"},
			{"uri": "goproxify://domains", "name": "Domaines", "description": "Domaines gérés et état TLS", "mimeType": "application/json"},
			{"uri": "goproxify://certs", "name": "Certificats", "description": "Certificats TLS et expiration", "mimeType": "application/json"},
			{"uri": "goproxify://logs", "name": "Logs", "description": "Derniers logs d'accès", "mimeType": "application/json"},
			{"uri": "goproxify://security/bans", "name": "Bans", "description": "Bans IP actifs et historiques", "mimeType": "application/json"},
			{"uri": "goproxify://security/threats", "name": "Menaces", "description": "Décisions CrowdSec", "mimeType": "application/json"},
			{"uri": "goproxify://security/cves", "name": "CVE", "description": "Vulnérabilités backends", "mimeType": "application/json"},
			{"uri": "goproxify://portal/destinations", "name": "Access destinations", "description": "Catalogue destinations Access", "mimeType": "application/json"},
			{"uri": "goproxify://portal/users", "name": "Access users", "description": "Utilisateurs Access", "mimeType": "application/json"},
			{"uri": "goproxify://portal/templates", "name": "Access templates", "description": "Templates HTML Access", "mimeType": "application/json"},
			{"uri": "goproxify://portal/audit", "name": "Access audit", "description": "Journal d'audit Access", "mimeType": "application/json"},
			{"uri": "goproxify://declared-nodes", "name": "Nœuds déclarés", "description": "Nœuds déclarés via le wizard architecture", "mimeType": "application/json"},
		},
	})
}

func (h *Handler) handleResourcesRead(req rpcRequest, r *http.Request) rpcResponse {
	var p struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return errResp(req.ID, -32602, "invalid params")
	}
	var data any
	var err error
	switch p.URI {
	case "goproxify://proxies":
		data, err = h.toolListProxies(r)
	case "goproxify://nodes":
		data, err = h.toolListNodes(r)
	case "goproxify://agents":
		data, err = h.toolListAgents()
	case "goproxify://alerts":
		data, err = h.toolListAlerts(r)
	case "goproxify://users":
		data, err = h.toolListUsers(r)
	case "goproxify://snippets":
		data, err = h.toolListSnippets(r)
	case "goproxify://domains":
		data, err = h.toolListDomains(r)
	case "goproxify://certs":
		data, err = h.toolListCerts(r)
	case "goproxify://logs":
		data, err = h.toolListLogs(r, "", "")
	case "goproxify://security/bans":
		data, err = h.toolListSecurityBans(r, map[string]any{"active_only": true})
	case "goproxify://security/threats":
		data, err = h.toolListSecurityThreats(r, map[string]any{})
	case "goproxify://security/cves":
		data, err = h.toolListSecurityCVEs(r, map[string]any{"status": "open"})
	case "goproxify://portal/destinations":
		data, err = h.toolListPortalDestinations(r, map[string]any{})
	case "goproxify://portal/users":
		data, err = h.toolListPortalUsers(r, map[string]any{})
	case "goproxify://portal/templates":
		data, err = h.toolListPortalTemplates(r)
	case "goproxify://portal/audit":
		data, err = h.toolListPortalAudit(r, map[string]any{})
	case "goproxify://declared-nodes":
		data, err = h.toolListDeclaredNodes(r)
	default:
		return errResp(req.ID, -32002, "resource not found: "+p.URI)
	}
	if err != nil {
		return errResp(req.ID, -32603, err.Error())
	}
	text, _ := json.MarshalIndent(data, "", "  ")
	return okResp(req.ID, map[string]any{
		"contents": []map[string]any{
			{"uri": p.URI, "mimeType": "application/json", "text": string(text)},
		},
	})
}

// --- SSE (server-sent events) --------------------------------------------

func (h *Handler) serveSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	if origin := r.Header.Get("Origin"); origin != "" {
		if u, err := url.Parse(origin); err == nil && strings.EqualFold(u.Host, r.Host) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming non supporté", http.StatusInternalServerError)
		return
	}

	// Envoie l'URL endpoint pour que le client sache où poster
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	endpointURL := scheme + "://" + r.Host + "/mcp"
	fmt.Fprintf(w, "event: endpoint\ndata: %s\n\n", endpointURL)
	flusher.Flush()

	// Keepalive toutes les 15s
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			fmt.Fprintf(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}
