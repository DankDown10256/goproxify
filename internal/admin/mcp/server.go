// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package mcp implémente un serveur MCP (Model Context Protocol) pour Goproxify.
// Il expose les ressources et outils de l'Administration via JSON-RPC 2.0 over HTTP.
// Spec: https://spec.modelcontextprotocol.io
package mcp

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/coreproxy"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/core/proxystore"
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
	// RulesEngine (optionnel) — moteur de règles automatiques pour l'outil run_rule.
	RulesEngine  RulesEvaluator
	CertDeployer CertDeployerIface // optionnel — déclenche les déploiements de certs
}

// RulesEvaluator est implémenté par rulesengine.Engine (évite l'import direct).
type RulesEvaluator interface {
	EvalNow(ctx context.Context, ruleID string, dryRun bool) (bool, map[string]any, error)
}

// CertDeployerIface est implémenté par certdeploy.Deployer (évite l'import direct).
type CertDeployerIface interface {
	TriggerTarget(ctx context.Context, targetID string) error
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
		"description": "Retourne les derniers logs d'accès (100 entrées max), filtrables par domaine, niveau ou request_id.",
		"inputSchema": schema(
			opt("domain", "string", "Filtrer par domaine proxy"),
			opt("level", "string", "Filtrer par niveau (info, warn, error)"),
			opt("request_id", "string", "Corrélation exacte par request_id (retourne tous les logs de la requête)"),
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
		"name":        "ban_ip",
		"description": "Banne immédiatement une IP via le moteur Sentinel (ban natif). Pousse aux Cores.",
		"inputSchema": schema(
			req("ip", "string", "Adresse IP à bannir"),
			opt("reason", "string", "Motif du ban (défaut: mcp_ban)"),
			opt("expires_at", "string", "Expiration RFC3339 ; omit = permanent"),
		),
	},
	{
		"name":        "unban_ip",
		"description": "Débanne une IP bannie par son adresse exacte (supprime tous les bans natifs sur cette IP).",
		"inputSchema": schema(req("ip", "string", "Adresse IP à débannir")),
	},
	{
		"name":        "rotate_cert",
		"description": "Force le renouvellement ACME d'un certificat par son domaine et le pousse aux Cores.",
		"inputSchema": schema(req("domain", "string", "Domaine dont le certificat doit être renouvelé")),
	},
	// Certificate Hub
	{
		"name":        "get_cert_status",
		"description": "Retourne le statut d'expiration détaillé de tous les certificats (days_left, status ok/warning/critical/expired) avec KPIs globaux.",
		"inputSchema": schema(opt("domain", "string", "Filtrer sur un domaine spécifique")),
	},
	{
		"name":        "list_cert_deploy_targets",
		"description": "Liste les cibles de déploiement configurées pour un certificat (webhook, ssh_exec) avec leur dernier statut.",
		"inputSchema": schema(req("cert_id", "string", "ID du certificat")),
	},
	{
		"name":        "trigger_cert_deploy",
		"description": "Déclenche immédiatement le déploiement d'un certificat vers une cible spécifique.",
		"inputSchema": schema(req("target_id", "string", "ID de la cible de déploiement")),
	},
	{
		"name":        "import_cert",
		"description": "Importe un certificat externe (non-ACME) en fournissant le PEM et la clé privée. Le domaine est extrait automatiquement.",
		"inputSchema": schema(
			req("cert_pem", "string", "Certificat PEM (-----BEGIN CERTIFICATE-----)"),
			req("key_pem", "string", "Clé privée PEM (-----BEGIN PRIVATE KEY----- ou EC PRIVATE KEY)"),
			opt("issuer", "string", "Émetteur (défaut: custom)"),
		),
	},
	{
		"name":        "list_rules",
		"description": "Liste les règles du moteur de règles automatiques (conditions, actions, état, statistiques).",
		"inputSchema": schema(opt("enabled_only", "boolean", "Si true, uniquement les règles activées")),
	},
	{
		"name":        "run_rule",
		"description": "Déclenche l'évaluation immédiate d'une règle. Par défaut en dry_run (aucune action exécutée).",
		"inputSchema": schema(
			req("id", "string", "ID de la règle"),
			opt("dry_run", "boolean", "Si false, exécute réellement l'action (défaut: true)"),
		),
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
		requestID, _ := p.Arguments["request_id"].(string)
		result, toolErr = h.toolListLogs(r, domain, level, requestID)
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
	case "ban_ip":
		result, toolErr = h.toolBanIP(r, p.Arguments)
	case "unban_ip":
		ip, _ := p.Arguments["ip"].(string)
		result, toolErr = h.toolUnbanIP(r, ip)
	case "rotate_cert":
		domain, _ := p.Arguments["domain"].(string)
		result, toolErr = h.toolRotateCert(r, domain)
	case "list_rules":
		result, toolErr = h.toolListRules(r, p.Arguments)
	case "run_rule":
		result, toolErr = h.toolRunRule(r, p.Arguments)
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
	case "list_alert_channels":
		result, toolErr = h.toolListAlertChannels(r)
	case "create_alert_channel":
		result, toolErr = h.toolCreateAlertChannel(r, p.Arguments)
	case "delete_alert_channel":
		id, _ := p.Arguments["id"].(string)
		result, toolErr = h.toolDeleteAlertChannel(r.Context(), id)
	case "list_alert_rules":
		result, toolErr = h.toolListAlertRules(r)
	case "create_alert_rule":
		result, toolErr = h.toolCreateAlertRule(r, p.Arguments)
	case "delete_alert_rule":
		id, _ := p.Arguments["id"].(string)
		result, toolErr = h.toolDeleteAlertRule(r.Context(), id)
	case "list_auth_providers":
		result, toolErr = h.toolListAuthProviders(r)
	case "create_auth_provider":
		result, toolErr = h.toolCreateAuthProvider(r, p.Arguments)
	case "delete_auth_provider":
		id, _ := p.Arguments["id"].(string)
		result, toolErr = h.toolDeleteAuthProvider(r.Context(), id)
	case "list_ip_profiles":
		result, toolErr = h.toolListIPProfiles(r)
	case "create_ip_profile":
		result, toolErr = h.toolCreateIPProfile(r, p.Arguments)
	case "delete_ip_profile":
		id, _ := p.Arguments["id"].(string)
		result, toolErr = h.toolDeleteIPProfile(r.Context(), id)
	case "create_snippet":
		result, toolErr = h.toolCreateSnippet(r, p.Arguments)
	case "delete_snippet":
		id, _ := p.Arguments["id"].(string)
		result, toolErr = h.toolDeleteSnippet(r.Context(), id)
	case "create_domain":
		result, toolErr = h.toolCreateDomain(r, p.Arguments)
	case "renew_domain":
		id, _ := p.Arguments["id"].(string)
		result, toolErr = h.toolRenewDomain(r, id)
	case "obtain_cert":
		domain, _ := p.Arguments["domain"].(string)
		result, toolErr = h.toolObtainCert(r, domain)
	case "get_cert_status":
		domain, _ := p.Arguments["domain"].(string)
		result, toolErr = h.toolGetCertStatus(r, domain)
	case "list_cert_deploy_targets":
		certID, _ := p.Arguments["cert_id"].(string)
		result, toolErr = h.toolListCertDeployTargets(r, certID)
	case "trigger_cert_deploy":
		targetID, _ := p.Arguments["target_id"].(string)
		result, toolErr = h.toolTriggerCertDeploy(r, targetID)
	case "import_cert":
		result, toolErr = h.toolImportCert(r, p.Arguments)
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
	envs, err := coreproxy.LoadProductionEnvelopes(r.Context(), h.DB)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]any, 0, len(envs))
	for _, e := range envs {
		var host, rtype string
		var tls *bool
		var m map[string]any
		if json.Unmarshal(e.Config, &m) == nil {
			if v, ok := m["host"].(string); ok {
				host = v
			}
			if v, ok := m["type"].(string); ok {
				rtype = v
			}
			if v, ok := m["tls_enabled"].(bool); ok {
				tls = &v
			}
		}
		if host == "" {
			host = e.Host
		}
		out = append(out, map[string]any{
			"id": e.ID, "name": e.Host, "enabled": e.Enabled, "host": host, "type": rtype, "tls": tls,
		})
	}
	return out, nil
}

func (h *Handler) toolGetProxy(r *http.Request, id string) (any, error) {
	env, err := h.resolveProxyEnvelope(r.Context(), id)
	if err != nil {
		return nil, err
	}
	var out any
	_ = json.Unmarshal(env.Config, &out)
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
	if rtype == "https" {
		rtype = "http"
		tlsEnabled = true
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
	actor := adminauth.ActorFromContext(r.Context())
	if err := h.publishToCores(r.Context(), id, host, true, cfgJSON, actor); err != nil {
		return nil, err
	}
	_ = admindb.WriteAudit(h.DB, actor, "create", "proxy:"+id, host)
	return map[string]any{"id": id, "host": host, "backend": backend, "type": rtype, "lb": lb}, nil
}

func (h *Handler) resolveProxyEnvelope(ctx context.Context, ref string) (*proxystore.Envelope, error) {
	envs, err := coreproxy.LoadProductionEnvelopes(ctx, h.DB)
	if err != nil {
		return nil, err
	}
	for _, e := range envs {
		if e.ID == ref || e.Host == ref {
			return e, nil
		}
		var m map[string]any
		if json.Unmarshal(e.Config, &m) == nil {
			if host, _ := m["host"].(string); host == ref {
				return e, nil
			}
		}
	}
	return nil, fmt.Errorf("proxy introuvable: %s", ref)
}

func (h *Handler) resolveProxyID(ctx context.Context, ref string) (id, name, cfgJSON string, enabled int, err error) {
	env, err := h.resolveProxyEnvelope(ctx, ref)
	if err != nil {
		return "", "", "", 0, err
	}
	en := 0
	if env.Enabled {
		en = 1
	}
	return env.ID, env.Host, string(env.Config), en, nil
}

func (h *Handler) publishToCores(ctx context.Context, id, host string, enabled bool, cfg json.RawMessage, actor string) error {
	targets, err := coreproxy.ListTargets(ctx, h.DB)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("aucun Core joignable")
	}
	client := coreproxy.NewClient()
	ok := 0
	var last error
	for _, t := range targets {
		if _, err := client.Publish(ctx, t, id, host, enabled, cfg, actor); err != nil {
			last = err
			continue
		}
		ok++
	}
	if ok == 0 {
		if last == nil {
			last = fmt.Errorf("publish échoué")
		}
		return last
	}
	return nil
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
	actor := adminauth.ActorFromContext(r.Context())
	if err := h.publishToCores(r.Context(), id, name, enabled == 1, outJSON, actor); err != nil {
		return nil, err
	}
	_ = admindb.WriteAudit(h.DB, actor, "update", "proxy:"+id, name)
	return map[string]any{"id": id, "name": name, "enabled": enabled == 1, "config": cfg}, nil
}

func (h *Handler) toolSetProxyEnabled(r *http.Request, args map[string]any) (any, error) {
	ref, _ := args["id"].(string)
	en, ok := args["enabled"].(bool)
	if ref == "" || !ok {
		return nil, fmt.Errorf("id et enabled requis")
	}
	id, name, cfgJSON, _, err := h.resolveProxyID(r.Context(), ref)
	if err != nil {
		return nil, err
	}
	actor := adminauth.ActorFromContext(r.Context())
	if err := h.publishToCores(r.Context(), id, name, en, json.RawMessage(cfgJSON), actor); err != nil {
		return nil, err
	}
	action := "disable"
	if en {
		action = "enable"
	}
	_ = admindb.WriteAudit(h.DB, actor, action, "proxy:"+id, name)
	return map[string]any{"id": id, "enabled": en}, nil
}

func (h *Handler) toolDeleteProxy(r *http.Request, id string) (any, error) {
	env, err := h.resolveProxyEnvelope(r.Context(), id)
	if err != nil {
		return nil, err
	}
	id = env.ID
	actor := adminauth.ActorFromContext(r.Context())
	targets, err := coreproxy.ListTargets(r.Context(), h.DB)
	if err != nil || len(targets) == 0 {
		return nil, fmt.Errorf("aucun Core joignable")
	}
	client := coreproxy.NewClient()
	var deleteErr error
	for _, t := range targets {
		if err := client.Delete(r.Context(), t, id); err != nil {
			deleteErr = err
		}
	}
	if deleteErr != nil {
		return nil, fmt.Errorf("suppression partielle ou échouée : %w", deleteErr)
	}
	_ = admindb.WriteAudit(h.DB, actor, "delete", "proxy:"+id, "")
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

func (h *Handler) toolListLogs(r *http.Request, domain, level, requestID string) (any, error) {
	q := `SELECT ts, level, component, domain, method, path, status, ip, latency_ms, COALESCE(request_id,''), message
	      FROM logs WHERE 1=1`
	args := []any{}
	if requestID != "" {
		q += ` AND request_id = ?`
		args = append(args, requestID)
	}
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
		var lvl, component, dom, method, path, ip, reqID, message string
		var status, latency int
		if err := rows.Scan(&ts, &lvl, &component, &dom, &method, &path, &status, &ip, &latency, &reqID, &message); err != nil {
			continue
		}
		entry := map[string]any{
			"ts": ts, "level": lvl, "component": component, "domain": dom,
			"method": method, "path": path, "status": status,
			"ip": ip, "latency_ms": latency, "message": message,
		}
		if reqID != "" {
			entry["request_id"] = reqID
		}
		out = append(out, entry)
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

func (h *Handler) toolBanIP(r *http.Request, args map[string]any) (any, error) {
	ip, _ := args["ip"].(string)
	if ip == "" {
		return nil, fmt.Errorf("ip requis")
	}
	reason, _ := args["reason"].(string)
	if reason == "" {
		reason = "mcp_ban"
	}
	expiresAt, _ := args["expires_at"].(string)
	id := "mcp-" + ip
	var exp any
	if expiresAt != "" {
		exp = expiresAt
	}
	_, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO security_bans (id, ip, domain, reason, source, expires_at) VALUES (?, ?, '', ?, 'native', ?)
		 ON CONFLICT(id) DO UPDATE SET reason=excluded.reason, expires_at=excluded.expires_at`,
		id, ip, reason, exp)
	if err != nil {
		return nil, err
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "ban_ip", "ban:"+id, ip)
	if h.OnBansChange != nil {
		h.OnBansChange()
	}
	return map[string]any{"id": id, "ip": ip, "reason": reason, "permanent": expiresAt == ""}, nil
}

func (h *Handler) toolUnbanIP(r *http.Request, ip string) (any, error) {
	if ip == "" {
		return nil, fmt.Errorf("ip requis")
	}
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM security_bans WHERE ip=?`, ip)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "unban_ip", "ip:"+ip, "")
	if h.OnBansChange != nil {
		h.OnBansChange()
	}
	return map[string]any{"ip": ip, "deleted": n}, nil
}

func (h *Handler) toolRotateCert(r *http.Request, domain string) (any, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain requis")
	}
	// Forcer le renouvellement en effaçant l'expiration stockée.
	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE domains SET cert_expires_at=NULL, updated_at=CURRENT_TIMESTAMP WHERE domain=?`, domain)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Domaine pas encore en DB — l'enregistrer pour déclenchement ACME.
		_, err = h.DB.ExecContext(r.Context(),
			`INSERT OR IGNORE INTO domains (id, domain, cert_method, delegation_mode)
			 VALUES (lower(hex(randomblob(16))), ?, 'acme', 'auto')`, domain)
		if err != nil {
			return nil, err
		}
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "rotate_cert", "domain:"+domain, "")
	if h.Pusher != nil {
		h.Pusher.PushRoutes(r.Context())
	}
	return map[string]any{"domain": domain, "status": "renew_requested"}, nil
}

func (h *Handler) toolGetCertStatus(r *http.Request, domain string) (any, error) {
	q := `SELECT id, domain, issuer, cert_pem, expires_at, updated_at FROM certs`
	var args []any
	if domain != "" {
		q += ` WHERE domain=?`
		args = append(args, domain)
	}
	q += ` ORDER BY expires_at ASC`
	rows, err := h.DB.QueryContext(r.Context(), q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now()
	var certs []map[string]any
	totals := map[string]int{"ok": 0, "warning": 0, "critical": 0, "expired": 0}
	for rows.Next() {
		var id, dom, issuer, certPEM, expiresStr, updatedStr string
		if err := rows.Scan(&id, &dom, &issuer, &certPEM, &expiresStr, &updatedStr); err != nil {
			continue
		}
		exp, _ := time.Parse("2006-01-02T15:04:05Z", expiresStr)
		if exp.IsZero() {
			exp, _ = time.Parse("2006-01-02 15:04:05", expiresStr)
		}
		daysLeft := int(exp.Sub(now).Hours() / 24)
		var status string
		switch {
		case daysLeft < 0:
			status = "expired"
		case daysLeft <= 7:
			status = "critical"
		case daysLeft <= 30:
			status = "warning"
		default:
			status = "ok"
		}
		totals[status]++
		certs = append(certs, map[string]any{
			"id": id, "domain": dom, "issuer": issuer,
			"expires_at": expiresStr, "updated_at": updatedStr,
			"days_left": daysLeft, "status": status,
		})
	}
	if certs == nil {
		certs = []map[string]any{}
	}
	return map[string]any{
		"certs": certs, "total": len(certs),
		"ok": totals["ok"], "warning": totals["warning"],
		"critical": totals["critical"], "expired": totals["expired"],
	}, nil
}

func (h *Handler) toolListCertDeployTargets(r *http.Request, certID string) (any, error) {
	if certID == "" {
		return nil, fmt.Errorf("cert_id requis")
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, type, trigger_on, last_deploy, last_status FROM cert_deploy_targets WHERE cert_id=? ORDER BY rowid`, certID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, typ, triggerOn string
		var lastDeploy, lastStatus sql.NullString
		if err := rows.Scan(&id, &typ, &triggerOn, &lastDeploy, &lastStatus); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id": id, "type": typ, "trigger_on": triggerOn,
			"last_deploy": lastDeploy.String, "last_status": lastStatus.String,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolTriggerCertDeploy(r *http.Request, targetID string) (any, error) {
	if targetID == "" {
		return nil, fmt.Errorf("target_id requis")
	}
	var certID, typ string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT cert_id, type FROM cert_deploy_targets WHERE id=?`, targetID).Scan(&certID, &typ)
	if err != nil {
		return nil, fmt.Errorf("target introuvable: %w", err)
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "trigger_cert_deploy", "target:"+targetID, "")
	if h.CertDeployer != nil {
		if err := h.CertDeployer.TriggerTarget(r.Context(), targetID); err != nil {
			return nil, fmt.Errorf("déploiement échoué: %w", err)
		}
	}
	return map[string]any{"target_id": targetID, "cert_id": certID, "type": typ, "status": "triggered"}, nil
}

func (h *Handler) toolImportCert(r *http.Request, args map[string]any) (any, error) {
	certPEM, _ := args["cert_pem"].(string)
	keyPEM, _ := args["key_pem"].(string)
	issuer, _ := args["issuer"].(string)
	if certPEM == "" || keyPEM == "" {
		return nil, fmt.Errorf("cert_pem et key_pem requis")
	}
	if issuer == "" {
		issuer = "custom"
	}
	// Parse domain from cert
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("cert_pem invalide: aucun bloc PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("certificat invalide: %w", err)
	}
	domain := ""
	if len(leaf.DNSNames) > 0 {
		domain = leaf.DNSNames[0]
	} else if leaf.Subject.CommonName != "" {
		domain = leaf.Subject.CommonName
	}
	if domain == "" {
		return nil, fmt.Errorf("impossible d'extraire le domaine du certificat")
	}
	_, err = h.DB.ExecContext(r.Context(),
		`INSERT INTO certs (id, domain, issuer, cert_pem, key_pem, expires_at, updated_at)
		 VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		 ON CONFLICT(domain) DO UPDATE SET
		   issuer=excluded.issuer, cert_pem=excluded.cert_pem, key_pem=excluded.key_pem,
		   expires_at=excluded.expires_at, updated_at=CURRENT_TIMESTAMP`,
		domain, issuer, certPEM, keyPEM, leaf.NotAfter.UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "import_cert", "domain:"+domain, "")
	return map[string]any{"domain": domain, "issuer": issuer, "expires_at": leaf.NotAfter.UTC().Format(time.RFC3339), "status": "imported"}, nil
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
		`SELECT id, ip, scenario, origin, type, duration, core_name, occurrences, last_seen_at, created_at
		 FROM security_threats ORDER BY last_seen_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, occurrences int
		var ip, scenario, origin, typ, duration, coreName, lastSeenAt, createdAt string
		if err := rows.Scan(&id, &ip, &scenario, &origin, &typ, &duration, &coreName, &occurrences, &lastSeenAt, &createdAt); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id": id, "ip": ip, "scenario": scenario, "origin": origin,
			"type": typ, "duration": duration, "core_name": coreName,
			"occurrences": occurrences, "last_seen_at": lastSeenAt, "created_at": createdAt,
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
		`SELECT id, backend_url, cve_id, cvss_score, description, status, core_name, detected_at
		 FROM security_cves`+where+` ORDER BY cvss_score DESC, detected_at DESC LIMIT 200`, qargs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id int
		var backend, cveID, desc, status, coreName, detectedAt string
		var cvss float64
		if err := rows.Scan(&id, &backend, &cveID, &cvss, &desc, &status, &coreName, &detectedAt); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id": id, "backend_url": backend, "cve_id": cveID, "cvss_score": cvss,
			"description": desc, "status": status, "core_name": coreName, "detected_at": detectedAt,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolListRules(r *http.Request, args map[string]any) (any, error) {
	where := ""
	if en, _ := args["enabled_only"].(bool); en {
		where = " WHERE enabled=1"
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, name, description, enabled, condition_json, action_json,
		        cooldown_sec, fire_count, last_fired_at, created_at, updated_at
		 FROM rules_engine_rules`+where+` ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, name, desc, condJSON, actionJSON, createdAt, updatedAt string
		var enabled, cooldown, fireCount int
		var lastFired sql.NullString
		if err := rows.Scan(&id, &name, &desc, &enabled, &condJSON, &actionJSON,
			&cooldown, &fireCount, &lastFired, &createdAt, &updatedAt); err != nil {
			continue
		}
		item := map[string]any{
			"id": id, "name": name, "description": desc, "enabled": enabled == 1,
			"condition": json.RawMessage(condJSON), "action": json.RawMessage(actionJSON),
			"cooldown_sec": cooldown, "fire_count": fireCount,
			"created_at": createdAt, "updated_at": updatedAt,
		}
		if lastFired.Valid {
			item["last_fired_at"] = lastFired.String
		}
		out = append(out, item)
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolRunRule(r *http.Request, args map[string]any) (any, error) {
	id, _ := args["id"].(string)
	if id == "" {
		return nil, fmt.Errorf("id requis")
	}
	dryRun := true
	if dr, ok := args["dry_run"].(bool); ok {
		dryRun = dr
	}
	if h.RulesEngine == nil {
		return nil, fmt.Errorf("moteur de règles non disponible")
	}
	matched, detail, err := h.RulesEngine.EvalNow(r.Context(), id, dryRun)
	if err != nil {
		return nil, err
	}
	return map[string]any{"matched": matched, "dry_run": dryRun, "detail": detail}, nil
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
			{"uri": "goproxify://certs/monitor", "name": "Monitoring ACME", "description": "Statut d'expiration de tous les certificats avec KPIs", "mimeType": "application/json"},
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
	case "goproxify://certs/monitor":
		data, err = h.toolGetCertStatus(r, "")
	case "goproxify://logs":
		data, err = h.toolListLogs(r, "", "", "")
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
