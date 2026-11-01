// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package mcp implémente un serveur MCP (Model Context Protocol) pour Goproxify.
// Il expose les ressources et outils de l'Administration via JSON-RPC 2.0 over HTTP.
// Spec: https://spec.modelcontextprotocol.io
package mcp

import (
	"github.com/vincamok/goproxify/internal/admin/routesecrets"
	agentsources "github.com/vincamok/goproxify/internal/agent/sources"
	"github.com/vincamok/goproxify/internal/admin/automation"
	"github.com/vincamok/goproxify/internal/edge/engines"
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
	"github.com/vincamok/goproxify/internal/admin/acme"
	"github.com/vincamok/goproxify/internal/admin/alerting"
	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/analytics"
	"github.com/vincamok/goproxify/internal/admin/logs"
	"github.com/vincamok/goproxify/internal/admin/siemcfg"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/admin/archstore"
	"github.com/vincamok/goproxify/internal/admin/asn"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/alerting/channels"
	"github.com/vincamok/goproxify/internal/admin/certdeploy"
	"github.com/vincamok/goproxify/internal/admin/ech"
	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/admin/internalca"
	"github.com/vincamok/goproxify/internal/admin/mcpaccess"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/admin/security"
	"github.com/vincamok/goproxify/internal/edge/middleware"
	"github.com/vincamok/goproxify/internal/edge/proxystore"
	"github.com/vincamok/goproxify/internal/labels"
	"github.com/vincamok/goproxify/internal/sqltime"
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
	Pusher RoutePusher // optionnel — push vers les passerelles après create/delete/update
	// Access (optionnel) — push config / templates portail vers les passerelles.
	Access          AccessPusher
	AccessTemplates AccessTemplatesPusher
	// Agents (optionnel) — registre en mémoire Admin ; callbacks WS.
	ListAgents   func() []AgentInfo
	ApproveAgent func(agentID string)
	RevokeAgent  func(agentID string)
	// Groups (optionnel) — groupes HA, pour valider la portée « group:<nom> » d'un ban.
	Groups api.GroupResolver
	// OnBansChange (optionnel) — push_bans vers les passerelles après create/delete ban.
	OnBansChange func()
	// OnUnban (optionnel) — lève les bans d'une IP sur les passerelles, y compris ceux qu'elles ont posés
	// elles-mêmes, puis renvoie la liste des bans (remplace OnBansChange pour un déban).
	OnUnban func(ip string)
	// OnUnbanMany (optionnel) — lève les bans de plusieurs adresses d'un coup (déban d'un ASN).
	OnUnbanMany func(ips []string)
	// ASN (optionnel) — base des systèmes autonomes pour les outils ASN.
	ASN *asn.Store
	// OnWhitelistChange (optionnel) — pousse les profils IP aux passerelles après un changement de la
	// liste blanche des bans (qui en est un).
	OnWhitelistChange func()
	// ResolvePublicURL (optionnel) — base publique Admin pour les tickets bootstrap (QR / curl|bash).
	ResolvePublicURL func(r *http.Request) string
	// Hosts (optionnel) — hôtes déclarés et tickets d'installation (outils list_hosts, create_host_join_ticket).
	Hosts *api.HostsHandler
	// Automation (optionnel) — flux d'automatisation (règles, planifications, playbooks).
	Automation   *automation.Service
	DNSProviders *acme.ProviderStore // optionnel — fournisseurs DNS nommés (ACME DNS-01)
	CertDeployer CertDeployerIface   // optionnel — déclenche les déploiements de certs
	InternalCA   *internalca.Manager // optionnel — CA interne (émission de certs hors ACME)
	ArchStore    *archstore.Store    // optionnel — architecture.json (outil get_architecture)
	// ProxyMetrics (optionnel) — série de débit/erreurs/p95 par host relevée par l'Admin (outil get_proxy_metrics).
	ProxyMetrics func(points int) (entries any, sampledAt any)
	// SIEMStatus (optionnel) — état de l'exporteur SIEM rapporté par chaque passerelle (outil get_siem_status).
	SIEMStatus func() []siemcfg.NodeStatus
}

// CertDeployerIface est implémenté par certdeploy.Deployer (évite l'import direct).
type CertDeployerIface interface {
	TriggerTarget(ctx context.Context, targetID string) error
}

// RoutePusher est implémenté par edgews.Manager (évite un import cyclique).
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

	if !mcpaccess.Allowed(h.DB, r) {
		http.Error(w, "IP non autorisée pour le MCP", http.StatusForbidden)
		return
	}

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
		resp = h.handleToolsList(req, r)
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
		"description": "Liste toutes les routes proxy (HTTP, TCP, UDP) : celles gérées depuis l'Admin (source \"managed\"), les proxies implicites générés par GoProxify — portail Access, délégations — dont seule la surcouche est modifiable (source \"implicit\") et celles découvertes par les labels des conteneurs (source \"docker\", \"k8s\"…, lecture seule).",
		"inputSchema": schema(),
	},
	{
		"name":        "get_proxy",
		"description": "Retourne la configuration complète d'un proxy par son ID ou son domaine.",
		"inputSchema": schema(req("id", "string", "ID ou domaine du proxy")),
	},
	{
		"name":        "get_proxy_labels",
		"description": "Donne les labels (Docker, Portainer, Kubernetes) qui reproduisent un proxy, avec ce qui n'a pas de label. Les secrets sortent sous forme de variables.",
		"inputSchema": schema(
			req("id", "string", "ID ou domaine du proxy"),
			opt("format", "string", "compose | portainer | portainer_inline | docker_run | kubernetes (défaut : tous)"),
		),
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
		"name":        "get_discovered_container",
		"description": "Détail d'une route découverte par les labels d'un conteneur : config servie par la passerelle (secrets masqués), labels qui la reproduisent, bilan de sécurité (score, contrôles, manques parmi TLS / WAF / rate limit) et labels corrigés avec le modèle de sécurité appliqué (un snippet de l'Admin du bon type, sinon WAF en blocage et 100 req/s).",
		"inputSchema": schema(
			req("id", "string", "ID de la route découverte (champ id de list_proxies) ou son domaine"),
			opt("edge", "string", "Nom de la passerelle, si plusieurs annoncent la même route"),
			opt("format", "string", "compose | portainer | portainer_inline | docker_run | kubernetes : ne garde que ce format (défaut : tous)"),
		),
	},
	{
		"name":        "list_orphan_proxies",
		"description": "Liste les proxies créés par convert_discovered_container dont le conteneur d'origine n'est plus annoncé par sa passerelle (routes mortes probables). Une passerelle injoignable n'en fait déclarer aucun.",
		"inputSchema": schema(),
	},
	{
		"name":        "convert_discovered_container",
		"description": "Convertit une route découverte par les labels d'un conteneur (list_proxies, source \"docker\", \"k8s\"…) en proxy configuré modifiable, avec sa configuration actuelle. Le proxy prend la place de la route des labels sur son hôte ; désactivé ou supprimé, il la lui rend. Les backends sont repris tels quels (adresses de conteneur). Retourne l'ID du proxy créé.",
		"inputSchema": schema(
			req("id", "string", "ID de la route découverte (champ id de list_proxies) ou son domaine"),
			opt("edge", "string", "Nom de la passerelle, si plusieurs annoncent la même route"),
		),
	},
	{
		"name":        "set_container_route_enabled",
		"description": "Active ou désactive la route issue des labels d'un conteneur (Docker, Portainer, Podman, Kubernetes, annuaires) sans toucher au conteneur. Désactivée, la route ne sert plus de trafic sur aucune passerelle, mais reste listée (list_proxies : enabled=false) pour être réactivée. S'applique à l'hôte, tous conteneurs du pool compris. Un proxy configuré se gère avec set_proxy_enabled.",
		"inputSchema": schema(
			req("host", "string", "Domaine de la route découverte (champ host de list_proxies)"),
			req("enabled", "boolean", "true = activer, false = désactiver"),
		),
	},
	{
		"name":        "update_proxy",
		"description": "Met à jour un proxy existant (host, backend, tls, lb, enabled, options avancées).",
		"inputSchema": schema(
			req("id", "string", "ID, nom ou domaine du proxy"),
			opt("host", "string", "Nouveau domaine"),
			opt("backend", "string", "Nouvelle URL backend (remplace la liste backends)"),
			opt("tls_enabled", "boolean", "Active ou désactive HTTPS"),
			opt("lb", "string", "Load balancing: round_robin, weighted, adaptive"),
			opt("enabled", "boolean", "Active ou désactive la route"),
			opt("options", "object", "Options avancées à poser (valeur null = retirer) : split, maintenance, signed_url, graphql, bandwidth, redact_json, html_inject, hedge, static, request_schema, openapi, grpc_transcode, surface (apprentissage de la surface : {\"mode\":\"learn\"}), grpc_web, rate_limit, conditions"),
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
	{
		"name":        "purge_proxy_cache",
		"description": "Vide le cache HTTP d'un proxy sur toutes les passerelles : tout le cache, ou seulement les entrées portant un tag (Cache-Tag / Surrogate-Key) ou correspondant à un chemin.",
		"inputSchema": schema(
			req("id", "string", "ID, nom ou domaine du proxy"),
			opt("tags", "string", "Tags à purger, séparés par des virgules"),
			opt("paths", "string", "Chemins à purger (avec ou sans query, suffixe * = préfixe), séparés par des virgules"),
		),
	},
	// Nœuds / Agents
	{
		"name":        "list_nodes",
		"description": "Liste les nœuds passerelle et Agent avec leurs métriques (CPU, mémoire, statut).",
		"inputSchema": schema(),
	},
	{
		"name":        "list_agents",
		"description": "Liste les Agents vus via WebSocket (pending, approved, revoked).",
		"inputSchema": schema(),
	},
	{
		"name":        "approve_agent",
		"description": "Approuve un Agent en attente (envoie approve_agent aux passerelles via WS).",
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
	{
		"name":        "list_alert_events",
		"description": "Liste les alertes déclenchées (30 jours conservés), la plus récente d'abord : règle, déclencheur, détail, message.",
		"inputSchema": schema(
			opt("days", "number", "Fenêtre en jours (défaut 30, max 30)"),
			opt("trigger", "string", "Filtrer par déclencheur, ex. slo_burn, high_error_rate, node_offline"),
			opt("node", "string", "Filtrer par nom de passerelle"),
			opt("limit", "number", "Nombre max d'événements (défaut 100, max 500)"),
		),
	},
	// Métriques
	{
		"name":        "get_metrics",
		"description": "Retourne les KPIs de trafic des dernières 24h (requêtes, erreurs, latence).",
		"inputSchema": schema(opt("proxy", "string", "Filtrer par domaine proxy (laisser vide pour tout le trafic)")),
	},
	{
		"name":        "get_proxy_metrics",
		"description": "Retourne, par host, le débit (req/s), le taux d'erreurs 5xx (0..1) et le p95 (ms) du dernier relevé, avec la série de débit récente (un point toutes les 10 s). Vide juste après un démarrage de l'Admin.",
		"inputSchema": schema(opt("host", "string", "Filtrer sur un host (laisser vide pour tous)"), opt("points", "number", "Nombre de points de la série (défaut 60, max 360)")),
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
	{
		"name":        "list_detector_types",
		"description": "Types de détecteur par route (ip_filter, geo_ip, bot, waf) avec leurs champs de configuration. À consulter avant create_snippet pour ces types.",
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
		"description": "Retourne les derniers logs d'accès (100 entrées max), filtrables par domaine, niveau, request_id ou empreinte TLS (tls_ja4, tls_ja3 — renvoyées dans chaque entrée quand la passerelle termine le TLS). Une entrée ip_truncated porte une IP tronquée par l'anonymisation RGPD (x.x.x.0, préfixe /48) qui regroupe plusieurs clients : ne pas la bannir.",
		"inputSchema": schema(
			opt("domain", "string", "Filtrer par domaine proxy"),
			opt("level", "string", "Filtrer par niveau (info, warn, error)"),
			opt("request_id", "string", "Corrélation exacte par request_id (retourne tous les logs de la requête)"),
			opt("tls_ja4", "string", "Filtrer par empreinte TLS JA4 du client (repérer un même outil ou botnet, quelle que soit son IP)"),
			opt("tls_ja3", "string", "Filtrer par empreinte TLS JA3 (hash MD5) du client"),
			opt("source", "string", "admin (défaut) : copie des logs gardée par l'Admin, 100 entrées max ; edge : base de logs de chaque passerelle, fusionnée par l'Admin avec ses propres logs (500 entrées par page, du plus récent au plus ancien). Une réponse edge porte entries, has_more, cursor, partial (délai d'une passerelle atteint, affiner le filtre) et unreachable (passerelles qui n'ont pas répondu : leurs lignes manquent)"),
			opt("node", "string", "Avec source=edge : nom d'une seule passerelle"),
			opt("cursor", "string", "Avec source=edge : jeton « cursor » de la page précédente, pour la page suivante"),
		),
	},
	{
		"name":        "get_siem_status",
		"description": "Exporteur SIEM des passerelles : configuration (destinations syslog RFC 5424 TCP/TLS, HTTP NDJSON ou OTLP/HTTP JSON, jetons des en-têtes masqués) et état rapporté par chaque passerelle (livraisons, retard en secondes sur la plus ancienne ligne non livrée, erreur, at_risk = des lignes vont être purgées avant d'être livrées). Chaque passerelle exporte seule avec son propre curseur, même Admin éteint ; une passerelle muette depuis plus de 90 s est marquée stale. Un retard au-delà du seuil de la destination déclenche l'alerte siem_export_lag. Réservé aux administrateurs.",
		"inputSchema": schema(),
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
		"name":        "list_plugins",
		"description": "Plugins WebAssembly installés sur les passerelles (nom, version, hooks, politique d'erreur, limites, champs de configuration, empreinte). Lecture seule : l'installation d'un plugin passe par l'API ou la CLI.",
		"inputSchema": schema(),
	},
	{
		"name":        "list_security_engine_types",
		"description": "Moteurs de sécurité globaux (Ephor, Seuils multi-passerelles, CrowdSec, WAF — interrupteur maître du WAF par passerelle) avec leurs champs de configuration (chemins imbriqués comme ip_score.ban_threshold, secrets).",
		"inputSchema": schema(),
	},
	{
		"name":        "list_security_bans",
		"description": "Liste les bans IP (Seuils multi-passerelles, CrowdSec, Ephor, plugins de détection comme Coraza, natif).",
		"inputSchema": schema(
			opt("ip", "string", "Filtrer par IP (sous-chaîne)"),
			opt("source", "string", "Filtrer par source: native, fleet, crowdsec, threat, plugin:<nom> (ex. plugin:coraza)"),
			opt("active_only", "boolean", "Si true, uniquement les bans non expirés"),
			opt("edge", "string", "Passerelle (nom du nœud ou id du token) : ses bans et les bans globaux"),
		),
	},
	{
		"name": "create_security_ban",
		"description": "Crée un ban IP natif (permanent par défaut) sur une adresse ou une plage CIDR. Pousse les bans aux passerelles. " +
			"Une plage est normalisée (203.0.113.7/24 devient 203.0.113.0/24), refusée si plus large que /16 (IPv4) ou /32 (IPv6), " +
			"ou si elle contient l'adresse de l'appelant. Mesurer l'impact avant avec preview_security_ban.",
		"inputSchema": schema(
			req("ip", "string", "Adresse IP ou plage CIDR à bannir"),
			opt("reason", "string", "Motif du ban"),
			opt("domain", "string", "Domaine ciblé (vide = global)"),
			opt("expires_at", "string", "Expiration RFC3339 ; omit = permanent"),
			opt("scope", "string", "Passerelles qui appliquent le ban : nom d'une passerelle ou group:<nom> d'un groupe HA ; omis = toutes"),
		),
	},
	{
		"name":        "delete_security_ban",
		"description": "Supprime un ban par son ID et resynchronise les passerelles.",
		"inputSchema": schema(req("id", "string", "ID du ban")),
	},
	{
		"name":        "ban_ip",
		"description": "Banne immédiatement une IP ou une plage CIDR (ban natif). Pousse aux passerelles. Mêmes règles que create_security_ban.",
		"inputSchema": schema(
			req("ip", "string", "Adresse IP ou plage CIDR à bannir"),
			opt("reason", "string", "Motif du ban (défaut: mcp_ban)"),
			opt("expires_at", "string", "Expiration RFC3339 ; omit = permanent"),
		),
	},
	{
		"name": "unban_ip",
		"description": "Débanne une IP ou une plage CIDR par sa valeur exacte (supprime tous les bans natifs portant cette valeur). " +
			"Débannir une adresse située dans une plage bannie ne lève pas le ban de la plage : supprimer la plage elle-même, ou créer un profil IP allow.",
		"inputSchema": schema(req("ip", "string", "Adresse IP ou plage CIDR à débannir, telle qu'enregistrée")),
	},
	{
		"name":        "rotate_cert",
		"description": "Force le renouvellement ACME d'un certificat par son domaine et le pousse aux passerelles.",
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
		"name":        "list_cert_deploy_types",
		"description": "Types de cible de déploiement de certificats (webhook, ssh_exec…) avec leurs champs de configuration (clé, libellé, secret, requis).",
		"inputSchema": schema(),
	},
	{
		"name":        "list_dns_providers",
		"description": "Fournisseurs DNS nommés utilisés par le challenge ACME DNS-01 (nom, type, paramètres ; secrets masqués). Un domaine les désigne par leur nom.",
		"inputSchema": schema(),
	},
	{
		"name":        "list_dns_provider_types",
		"description": "Types de fournisseur DNS ACME (OVH, Cloudflare, Route 53, Gandi, Hetzner et les modules libdns : attrs.engine = libdns) avec leurs paramètres (clé, secret, requis, variable d'environnement).",
		"inputSchema": schema(opt("q", "string", "Filtrer sur le type ou le libellé (sous-chaîne, insensible à la casse)")),
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
		"name":        "create_internal_ca",
		"description": "Crée une nouvelle autorité de certification interne (CA racine auto-signée) pour émettre des certificats serveur/client hors ACME.",
		"inputSchema": schema(
			req("name", "string", "Nom de la CA (identifiant lisible)"),
			req("common_name", "string", "Common Name du certificat racine"),
			opt("validity_years", "number", "Durée de validité en années (défaut: 10)"),
		),
	},
	{
		"name":        "list_internal_cas",
		"description": "Liste les autorités de certification internes avec leur subject et date d'expiration.",
		"inputSchema": schema(),
	},
	{
		"name":        "get_ech_status",
		"description": "État d'Encrypted Client Hello (ECH) : activation, nom public, clés (jamais les clés privées) et valeur ech= à publier dans l'enregistrement DNS HTTPS.",
		"inputSchema": schema(),
	},
	{
		"name":        "issue_internal_cert",
		"description": "Émet un certificat serveur ou client signé par une CA interne.",
		"inputSchema": schema(
			req("ca_id", "string", "ID de la CA interne émettrice"),
			req("common_name", "string", "Common Name du certificat"),
			opt("sans", "array", "Noms alternatifs (DNS ou IP)"),
			opt("usage", "string", "server ou client (défaut: server)"),
			opt("validity_days", "number", "Durée de validité en jours (défaut: 397)"),
		),
	},
	{
		"name":        "list_internal_certs",
		"description": "Liste les certificats émis par une CA interne donnée.",
		"inputSchema": schema(req("ca_id", "string", "ID de la CA interne")),
	},
	{
		"name":        "revoke_internal_cert",
		"description": "Révoque un certificat émis par une CA interne.",
		"inputSchema": schema(req("cert_id", "string", "ID du certificat émis")),
	},
	{
		"name":        "list_security_threats",
		"description": "Liste les décisions CrowdSec synchronisées (security_threats).",
		"inputSchema": schema(opt("limit", "number", "Nombre d'entrées (défaut: 100, max: 500)")),
	},
	{
		"name":        "list_security_cves",
		"description": "Liste les CVE détectées sur les backends, avec exploitation active (kev) et probabilité d'exploitation (epss_score, 0-1, FIRST.org).",
		"inputSchema": schema(
			opt("status", "string", "Filtrer: open, ignored, resolved"),
			opt("critical_only", "boolean", "Si true, CVSS >= 7 uniquement"),
			opt("kev_only", "boolean", "Si true, uniquement les CVE du catalogue CISA KEV (exploitation active)"),
		),
	},
}

func init() {
	tools = append(tools, portalTools()...)
	tools = append(tools, infraTools()...)
}

// --- tools/call ----------------------------------------------------------

func listedTool(name string) bool {
	for _, t := range tools {
		if t["name"] == name {
			return true
		}
	}
	return false
}

// denyTool retourne le motif de refus d'un outil, "" s'il est autorisé. /mcp n'est
// monté qu'avec RequirePAT : ce contrôle tient lieu d'EnforcePATScope et de
// RequireAdmin de la route REST équivalente. Un outil sans scope déclaré est refusé.
func (h *Handler) denyTool(r *http.Request, tool string) string {
	scope := rbac.ToolRequiredScope(tool)
	if scope == "" {
		return "outil sans scope déclaré: " + tool
	}
	if !rbac.EffectiveHasScope(r.Context(), h.DB, scope) {
		return "scope insuffisant: " + scope
	}
	if rbac.ToolRequiresAdmin(tool) && !rbac.IsAdmin(r.Context(), h.DB, adminauth.UserIDFromContext(r.Context())) {
		return "accès réservé aux administrateurs"
	}
	return ""
}

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

	if !listedTool(p.Name) {
		return errResp(req.ID, -32601, "outil inconnu: "+p.Name)
	}
	if denied := h.denyTool(r, p.Name); denied != "" {
		return okResp(req.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": "Erreur: " + denied}},
			"isError": true,
		})
	}

	var result any
	var toolErr error

	switch p.Name {
	case "list_proxies":
		result, toolErr = h.toolListProxies(r)
	case "get_proxy":
		id, _ := p.Arguments["id"].(string)
		result, toolErr = h.toolGetProxy(r, id)
	case "get_proxy_labels":
		id, _ := p.Arguments["id"].(string)
		format, _ := p.Arguments["format"].(string)
		result, toolErr = h.toolGetProxyLabels(r, id, format)
	case "create_proxy":
		result, toolErr = h.toolCreateProxy(r, p.Arguments)
	case "get_discovered_container":
		result, toolErr = h.toolGetDiscoveredContainer(r, p.Arguments)
	case "list_orphan_proxies":
		result, toolErr = (&api.DiscoveredContainersHandler{DB: h.DB, Log: h.Log, Groups: h.Groups}).Orphans(r.Context())
	case "convert_discovered_container":
		result, toolErr = h.toolConvertDiscoveredContainer(r, p.Arguments)
	case "set_container_route_enabled":
		result, toolErr = h.toolSetContainerRouteEnabled(r, p.Arguments)
	case "update_proxy":
		result, toolErr = h.toolUpdateProxy(r, p.Arguments)
	case "set_proxy_enabled":
		result, toolErr = h.toolSetProxyEnabled(r, p.Arguments)
	case "delete_proxy":
		id, _ := p.Arguments["id"].(string)
		result, toolErr = h.toolDeleteProxy(r, id)
	case "purge_proxy_cache":
		result, toolErr = h.toolPurgeProxyCache(r, p.Arguments)
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
	case "list_alert_events":
		result, toolErr = h.toolListAlertEvents(r, p.Arguments)
	case "get_metrics":
		proxy, _ := p.Arguments["proxy"].(string)
		result, toolErr = h.toolGetMetrics(r, proxy)
	case "get_proxy_metrics":
		host, _ := p.Arguments["host"].(string)
		points, _ := p.Arguments["points"].(float64)
		result, toolErr = h.toolGetProxyMetrics(host, int(points))
	case "list_backups":
		result, toolErr = h.toolListBackups(r)
	case "list_users":
		result, toolErr = h.toolListUsers(r)
	case "list_snippets":
		result, toolErr = h.toolListSnippets(r)
	case "list_detector_types":
		result = middleware.Detectors()
	case "list_domains":
		result, toolErr = h.toolListDomains(r)
	case "list_certs":
		result, toolErr = h.toolListCerts(r)
	case "list_logs":
		domain, _ := p.Arguments["domain"].(string)
		level, _ := p.Arguments["level"].(string)
		requestID, _ := p.Arguments["request_id"].(string)
		ja3, _ := p.Arguments["tls_ja3"].(string)
		ja4, _ := p.Arguments["tls_ja4"].(string)
		result, toolErr = h.toolListLogsFiltered(r, domain, level, requestID, ja3, ja4)
	case "get_siem_status":
		result = h.toolSIEMStatus()
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
	case "list_plugins":
		result, toolErr = h.toolListPlugins(r)
	case "list_security_engine_types":
		result = engines.Manifests()
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
	case "list_security_threats":
		result, toolErr = h.toolListSecurityThreats(r, p.Arguments)
	case "list_security_cves":
		result, toolErr = h.toolListSecurityCVEs(r, p.Arguments)
	case "get_prism_anomalies":
		result, toolErr = h.toolGetPrismAnomalies(r, p.Arguments)
	case "get_prism_slo":
		result, toolErr = h.toolGetPrismSLO(r, p.Arguments)
	case "get_prism_tls_fingerprints":
		result, toolErr = h.toolGetPrismTLSFingerprints(r, p.Arguments)
	case "get_prism_geo":
		result, toolErr = h.toolGetPrismGeo(r, p.Arguments)
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
	case "list_portal_groups":
		result, toolErr = h.toolListPortalGroups(r, p.Arguments)
	case "create_portal_group":
		result, toolErr = h.toolCreatePortalGroup(r, p.Arguments)
	case "update_portal_group":
		result, toolErr = h.toolUpdatePortalGroup(r, p.Arguments)
	case "delete_portal_group":
		result, toolErr = h.toolDeletePortalGroup(r, p.Arguments)
	case "list_portal_destination_groups":
		result, toolErr = h.toolListPortalDestGroups(r, p.Arguments)
	case "create_portal_destination_group":
		result, toolErr = h.toolCreatePortalDestGroup(r, p.Arguments)
	case "update_portal_destination_group":
		result, toolErr = h.toolUpdatePortalDestGroup(r, p.Arguments)
	case "delete_portal_destination_group":
		result, toolErr = h.toolDeletePortalDestGroup(r, p.Arguments)
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
	case "list_portal_sessions":
		result, toolErr = h.toolListPortalSessions(r, p.Arguments)
	case "terminate_portal_session":
		result, toolErr = h.toolTerminatePortalSession(r, p.Arguments)
	case "list_portal_access_requests":
		result, toolErr = h.toolListPortalAccessRequests(r, p.Arguments)
	case "decide_portal_access_request":
		result, toolErr = h.toolDecidePortalAccessRequest(r, p.Arguments)
	case "get_portal_policy":
		result, toolErr = h.toolGetPortalPolicy(r, p.Arguments)
	case "set_portal_policy":
		result, toolErr = h.toolSetPortalPolicy(r, p.Arguments)
	case "list_portal_recordings":
		result, toolErr = h.toolListPortalRecordings(r, p.Arguments)
	case "delete_portal_recording":
		result, toolErr = h.toolDeletePortalRecording(r, p.Arguments)
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
	case "trace_ip":
		result, toolErr = h.toolTraceIP(r, p.Arguments)
	case "preview_security_ban":
		result, toolErr = h.toolPreviewSecurityBan(r, p.Arguments)
	case "lookup_asn":
		result, toolErr = h.toolLookupASN(r, p.Arguments)
	case "preview_asn_ban":
		result, toolErr = h.toolPreviewASNBan(r, p.Arguments)
	case "ban_asn":
		result, toolErr = h.toolBanASN(r, p.Arguments)
	case "unban_asn":
		result, toolErr = h.toolUnbanASN(r, p.Arguments)
	case "import_security_bans":
		result, toolErr = h.toolImportSecurityBans(r, p.Arguments)
	case "list_ban_whitelist":
		result, toolErr = h.toolListBanWhitelist()
	case "add_ban_whitelist":
		result, toolErr = h.toolAddBanWhitelist(r, p.Arguments)
	case "remove_ban_whitelist":
		result, toolErr = h.toolRemoveBanWhitelist(r, p.Arguments)
	case "simulate_ephor_config":
		result, toolErr = h.toolSimulateEphor(r, p.Arguments)
	case "get_ephor_references":
		result, toolErr = h.toolGetEphorReferences(r, p.Arguments)
	case "get_proxy_surface":
		result, toolErr = h.toolGetProxySurface(r, p.Arguments)
	case "get_app_inventory":
		result, toolErr = h.toolGetAppInventory(r, p.Arguments)
	case "get_entry_rejections":
		result, toolErr = h.toolGetEntryRejections(r, p.Arguments)
	case "get_domain_watch":
		result, toolErr = h.toolGetDomainWatch(r, p.Arguments)
	case "get_tls_reputation":
		result, toolErr = h.toolGetTLSReputation(r, p.Arguments)
	case "get_traffic_reference":
		result, toolErr = h.toolGetTrafficReference(r, p.Arguments)
	case "get_proxy_surface_suggestions":
		result, toolErr = h.toolGetProxySurfaceSuggestions(r, p.Arguments)
	case "accept_proxy_surface_suggestions":
		result, toolErr = h.toolAcceptProxySurfaceSuggestions(r, p.Arguments)
	case "enforce_proxy_surface":
		result, toolErr = h.toolEnforceProxySurface(r, p.Arguments)
	case "relax_proxy_surface":
		result, toolErr = h.toolRelaxProxySurface(r, p.Arguments)
	case "get_proxy_surface_openapi":
		result, toolErr = h.toolGetProxySurfaceOpenAPI(r, p.Arguments)
	case "get_proxy_surface_proposals":
		result, toolErr = h.toolGetProxySurfaceProposals(r, p.Arguments)
	case "reset_proxy_surface":
		result, toolErr = h.toolResetProxySurface(r, p.Arguments)
	case "suggest_ephor_thresholds":
		result, toolErr = h.toolSuggestEphorThresholds(r, p.Arguments)
	case "get_waf_activity":
		result, toolErr = h.toolGetWAFActivity(r, p.Arguments)
	case "get_topology_live":
		result, toolErr = h.toolGetTopologyLive(r)
	case "list_declared_nodes":
		result, toolErr = h.toolListDeclaredNodes(r)
	case "get_architecture":
		result, toolErr = h.toolGetArchitecture(p.Arguments)
	case "list_discovery_sources":
		result = agentsources.Manifests()
	case "create_declared_node":
		result, toolErr = h.toolCreateDeclaredNode(r, p.Arguments)
	case "delete_declared_node":
		result, toolErr = h.toolDeleteDeclaredNode(r, p.Arguments)
	case "list_hosts":
		result, toolErr = h.toolListHosts(r)
	case "create_host_join_ticket":
		result, toolErr = h.toolCreateHostJoinTicket(r, p.Arguments)
	case "create_bootstrap_ticket":
		result, toolErr = h.toolCreateBootstrapTicket(r, p.Arguments)
	case "accept_node":
		result, toolErr = h.toolAcceptNode(r, p.Arguments)
	case "reject_node":
		result, toolErr = h.toolRejectNode(r, p.Arguments)
	case "list_alert_channel_types":
		result = channels.Manifests()
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
	case "ack_alert_event":
		id, _ := p.Arguments["id"].(string)
		result, toolErr = h.toolAckAlertEvent(r.Context(), id, adminauth.ActorFromContext(r.Context()))
	case "list_auth_provider_types":
		result = middleware.SSOProviders()
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
	case "list_cert_deploy_types":
		result = certdeploy.Manifests()
	case "list_dns_providers":
		result, toolErr = h.toolListDNSProviders()
	case "list_dns_provider_types":
		q, _ := p.Arguments["q"].(string)
		result = dnsProviderTypes(q)
	case "list_cert_deploy_targets":
		certID, _ := p.Arguments["cert_id"].(string)
		result, toolErr = h.toolListCertDeployTargets(r, certID)
	case "trigger_cert_deploy":
		targetID, _ := p.Arguments["target_id"].(string)
		result, toolErr = h.toolTriggerCertDeploy(r, targetID)
	case "import_cert":
		result, toolErr = h.toolImportCert(r, p.Arguments)
	case "create_internal_ca":
		result, toolErr = h.toolCreateInternalCA(r, p.Arguments)
	case "list_internal_cas":
		result, toolErr = h.toolListInternalCAs(r)
	case "get_ech_status":
		result, toolErr = ech.NewStore(h.DB).Status()
	case "issue_internal_cert":
		result, toolErr = h.toolIssueInternalCert(r, p.Arguments)
	case "list_internal_certs":
		caID, _ := p.Arguments["ca_id"].(string)
		result, toolErr = h.toolListInternalCerts(r, caID)
	case "revoke_internal_cert":
		certID, _ := p.Arguments["cert_id"].(string)
		result, toolErr = h.toolRevokeInternalCert(r, certID)
	default:
		var ok bool
		if result, toolErr, ok = h.callAutomationTool(r, p.Name, p.Arguments); !ok {
			return errResp(req.ID, -32601, "outil inconnu: "+p.Name)
		}
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
	envs, err := edgeproxy.LoadProductionEnvelopes(r.Context(), h.DB)
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
		source := "managed"
		if e.Implicit {
			source = "implicit"
		}
		out = append(out, map[string]any{
			"id": e.ID, "name": e.Host, "enabled": e.Enabled, "host": host, "type": rtype, "tls": tls,
			"source": source,
		})
	}
	dc := &api.DiscoveredContainersHandler{DB: h.DB, Log: h.Log, Groups: h.Groups}
	for _, d := range dc.FetchFromEdges(r.Context()) {
		out = append(out, map[string]any{
			"id": d.ID, "name": d.Host, "enabled": !d.Disabled, "host": d.Host, "type": "http", "tls": d.TLS,
			"source": d.Source, "read_only": true, "aliases": d.Aliases, "backends": d.Backends,
			"edge": d.EdgeName, "edge_label": d.EdgeLabel, "group": d.Group, "agent": d.AgentName, "shadowed_by": d.ShadowedBy,
			"inactive": d.Inactive, "state": d.State,
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
	_ = json.Unmarshal(routesecrets.Mask(env.Config, routesecrets.FromDB(h.DB)), &out)
	return out, nil
}

func (h *Handler) toolGetProxyLabels(r *http.Request, id, format string) (any, error) {
	env, err := h.resolveProxyEnvelope(r.Context(), id)
	if err != nil {
		return nil, err
	}
	if env.Implicit {
		return nil, fmt.Errorf("un proxy implicite est généré par GoProxify : il n'y a pas de labels à exporter")
	}
	out, err := api.BuildProxyLabels(env.Config)
	if err != nil {
		return nil, err
	}
	if format == "" {
		return out, nil
	}
	f, ok := out.Formats[format]
	if !ok {
		return nil, fmt.Errorf("format inconnu %q (compose, portainer, portainer_inline, docker_run, kubernetes)", format)
	}
	return map[string]any{"format": format, "text": f.Text, "env": f.Env, "unsupported": out.Unsupported}, nil
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
	if err := mcpaccess.CheckBackend(h.DB, backend); err != nil {
		return nil, err
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
	if err := h.publishToEdges(r.Context(), id, host, true, cfgJSON, actor); err != nil {
		return nil, err
	}
	_ = admindb.WriteAudit(h.DB, actor, "create", "proxy:"+id, host)
	return map[string]any{"id": id, "host": host, "backend": backend, "type": rtype, "lb": lb}, nil
}

func (h *Handler) toolGetDiscoveredContainer(r *http.Request, args map[string]any) (any, error) {
	id, _ := args["id"].(string)
	edge, _ := args["edge"].(string)
	format, _ := args["format"].(string)
	if id == "" {
		return nil, fmt.Errorf("id requis")
	}
	dc := &api.DiscoveredContainersHandler{DB: h.DB, Log: h.Log, Groups: h.Groups}
	c, err := dc.Find(r.Context(), id, edge)
	if err != nil {
		return nil, err
	}
	d, err := dc.Detail(r.Context(), c)
	if err != nil {
		return nil, err
	}
	for _, l := range []*api.ProxyLabels{d.Labels, d.FixedLabels} {
		if l == nil {
			continue
		}
		if format == "" {
			continue
		}
		if f, ok := l.Formats[format]; ok {
			l.Formats = map[string]labels.Output{format: f}
		} else {
			return nil, fmt.Errorf("format inconnu %q (compose, portainer, portainer_inline, docker_run, kubernetes)", format)
		}
	}
	return d, nil
}

func (h *Handler) toolConvertDiscoveredContainer(r *http.Request, args map[string]any) (any, error) {
	id, _ := args["id"].(string)
	edge, _ := args["edge"].(string)
	if id == "" {
		return nil, fmt.Errorf("id requis")
	}
	c, err := (&api.DiscoveredContainersHandler{DB: h.DB, Log: h.Log, Groups: h.Groups}).ForConversion(r.Context(), id, edge)
	if err != nil {
		return nil, err
	}
	for _, b := range c.Backends {
		if err := mcpaccess.CheckBackend(h.DB, b); err != nil {
			return nil, err
		}
	}
	proxyID := uuid.New().String()
	cfgJSON, err := c.ConversionConfig(proxyID, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	actor := adminauth.ActorFromContext(r.Context())
	if err := h.publishToEdges(r.Context(), proxyID, c.Host, true, cfgJSON, actor); err != nil {
		return nil, err
	}
	_ = admindb.WriteAudit(h.DB, actor, "create", "proxy:"+proxyID, c.Host)
	return map[string]any{"id": proxyID, "host": c.Host, "backends": c.Backends, "converted_from": c.ID}, nil
}

func (h *Handler) toolSetContainerRouteEnabled(r *http.Request, args map[string]any) (any, error) {
	host, _ := args["host"].(string)
	en, ok := args["enabled"].(bool)
	if host == "" || !ok {
		return nil, fmt.Errorf("host et enabled requis")
	}
	var pusher api.DisabledRoutesPusher
	if p, ok := h.Pusher.(api.DisabledRoutesPusher); ok {
		pusher = p
	}
	dc := &api.DiscoveredContainersHandler{DB: h.DB, Log: h.Log, Groups: h.Groups, Pusher: pusher}
	if err := dc.SetEnabled(r.Context(), adminauth.UserIDFromContext(r.Context()), adminauth.ActorFromContext(r.Context()), host, en); err != nil {
		return nil, err
	}
	return map[string]any{"host": host, "enabled": en}, nil
}

func (h *Handler) resolveProxyEnvelope(ctx context.Context, ref string) (*proxystore.Envelope, error) {
	envs, err := edgeproxy.LoadProductionEnvelopes(ctx, h.DB)
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

func (h *Handler) publishToEdges(ctx context.Context, id, host string, enabled bool, cfg json.RawMessage, actor string) error {
	targets, err := edgeproxy.ListTargets(ctx, h.DB)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return fmt.Errorf("aucune passerelle joignable")
	}
	client := edgeproxy.NewClient()
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
		if err := mcpaccess.CheckBackend(h.DB, backend); err != nil {
			return nil, err
		}
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
	if opts, ok := args["options"].(map[string]any); ok && len(opts) > 0 {
		for k, v := range opts {
			if !advancedProxyOptions[k] {
				return nil, fmt.Errorf("option inconnue : %q", k)
			}
			if v == nil {
				delete(cfg, k)
			} else {
				cfg[k] = v
			}
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
	if err := h.publishToEdges(r.Context(), id, name, enabled == 1, outJSON, actor); err != nil {
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
	if err := h.publishToEdges(r.Context(), id, name, en, json.RawMessage(cfgJSON), actor); err != nil {
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
	targets, err := edgeproxy.ListTargets(r.Context(), h.DB)
	if err != nil || len(targets) == 0 {
		return nil, fmt.Errorf("aucune passerelle joignable")
	}
	client := edgeproxy.NewClient()
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

func (h *Handler) toolPurgeProxyCache(r *http.Request, args map[string]any) (any, error) {
	idArg, _ := args["id"].(string)
	env, err := h.resolveProxyEnvelope(r.Context(), idArg)
	if err != nil {
		return nil, err
	}
	splitList := func(key string) []string {
		raw, _ := args[key].(string)
		var out []string
		for _, s := range strings.Split(raw, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	tags, paths := splitList("tags"), splitList("paths")
	targets, err := edgeproxy.ListTargets(r.Context(), h.DB)
	if err != nil || len(targets) == 0 {
		return nil, fmt.Errorf("aucune passerelle joignable")
	}
	client := edgeproxy.NewClient()
	total, ok := 0, 0
	var lastErr error
	for _, t := range targets {
		n, err := client.PurgeCache(r.Context(), t, env.ID, tags, paths)
		if err != nil {
			lastErr = err
			continue
		}
		total += n
		ok++
	}
	if ok == 0 {
		return nil, fmt.Errorf("purge échouée : %w", lastErr)
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "purge_cache", "proxy:"+env.ID, env.Host)
	return map[string]any{"purged": total}, nil
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
		`SELECT id, name, type, description, config, created_at FROM snippets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, name, typ, desc, cfg string
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &typ, &desc, &cfg, &createdAt); err != nil {
			continue
		}
		var cfgObj any
		if man, ok := middleware.DetectorManifest(typ); ok {
			var m map[string]any
			if json.Unmarshal([]byte(cfg), &m) == nil && m != nil {
				cfgObj = man.Mask(m)
			}
		}
		if cfgObj == nil {
			json.Unmarshal([]byte(cfg), &cfgObj) //nolint:errcheck
		}
		out = append(out, map[string]any{"id": id, "name": name, "type": typ, "description": desc, "config": cfgObj, "created_at": createdAt})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolListDomains(r *http.Request) (any, error) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, domain, edge_id, dns_provider, cert_method, delegation_mode,
		        cert_expires_at, created_at
		 FROM domains ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, domain, edgeID, dnsProv, certMethod, delegMode string
		var certExpires *time.Time
		var createdAt time.Time
		if err := rows.Scan(&id, &domain, &edgeID, &dnsProv, &certMethod, &delegMode, &certExpires, &createdAt); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id": id, "domain": domain, "edge_id": edgeID,
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
	return h.toolListLogsFiltered(r, domain, level, requestID, "", "")
}

func (h *Handler) toolListLogsFiltered(r *http.Request, domain, level, requestID, ja3, ja4 string) (any, error) {
	q := `SELECT ts, level, component, domain, method, path, status, ip, latency_ms, COALESCE(request_id,''), message, ip_truncated, COALESCE(tls_ja3,''), COALESCE(tls_ja4,'')
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
	if ja3 != "" {
		q += ` AND tls_ja3 = ? AND tls_ja3 != ''`
		args = append(args, ja3)
	}
	if ja4 != "" {
		q += ` AND tls_ja4 = ? AND tls_ja4 != ''`
		args = append(args, ja4)
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
		var lvl, component, dom, method, path, ip, reqID, message, rowJA3, rowJA4 string
		var status, latency int
		var ipTruncated bool
		if err := rows.Scan(&ts, &lvl, &component, &dom, &method, &path, &status, &ip, &latency, &reqID, &message, &ipTruncated, &rowJA3, &rowJA4); err != nil {
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
		if rowJA4 != "" {
			entry["tls_ja4"] = rowJA4
		}
		if rowJA3 != "" {
			entry["tls_ja3"] = rowJA3
		}
		// IP tronquée par l'anonymisation : ban_ip sur cette valeur ne viserait aucun client.
		if ipTruncated {
			entry["ip_truncated"] = true
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
		`SELECT COUNT(*) FROM security_bans WHERE expires_at IS NULL OR datetime(expires_at) > CURRENT_TIMESTAMP`).Scan(&activeBans)
	_ = h.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM security_threats`).Scan(&threats)
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM security_cves WHERE status='open'`).Scan(&openCVEs)
	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM certs WHERE expires_at <= datetime('now', '+30 days')`).Scan(&expiringCerts)
	return map[string]any{
		"active_bans":    activeBans,
		"threats":        threats,
		"open_cves":      openCVEs,
		"expiring_certs": expiringCerts,
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
		clauses = append(clauses, "(expires_at IS NULL OR datetime(expires_at) > CURRENT_TIMESTAMP)")
	}
	if edge, _ := args["edge"].(string); edge != "" {
		var node string
		if h.DB.QueryRowContext(r.Context(), `SELECT node_name FROM tokens WHERE id=? OR node_name=? LIMIT 1`, edge, edge).Scan(&node) == nil && node != "" {
			edge = node
		}
		clauses = append(clauses, "(edge_name=? OR edge_name='')")
		qargs = append(qargs, edge)
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, ip, domain, reason, source, edge_name, target_scope, expires_at, created_at, signals, user_agent FROM security_bans`+where+
			` ORDER BY created_at DESC LIMIT 200`, qargs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, ip, domain, reason, source, edgeName, scope, signals, userAgent string
		var exp sql.NullString
		var createdAt string
		if err := rows.Scan(&id, &ip, &domain, &reason, &source, &edgeName, &scope, &exp, &createdAt, &signals, &userAgent); err != nil {
			continue
		}
		item := map[string]any{
			"id": id, "ip": ip, "domain": domain, "reason": reason,
			"source": source, "edge_name": edgeName, "target_scope": scope, "created_at": createdAt,
		}
		if why := security.DecodeBanSignals(signals); len(why) > 0 {
			item["signals"] = why
		}
		if userAgent != "" {
			item["user_agent"] = userAgent
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
	rawIP, _ := args["ip"].(string)
	ip, err := h.banTarget(r, rawIP)
	if err != nil {
		return nil, err
	}
	reason, _ := args["reason"].(string)
	domain, _ := args["domain"].(string)
	expiresAt, _ := args["expires_at"].(string)
	exp, err := security.NormalizeBanExpiry(expiresAt)
	if err != nil {
		return nil, err
	}
	rawScope, _ := args["scope"].(string)
	scope, err := api.NormalizeBanScope(h.DB, h.Groups, rawScope)
	if err != nil {
		return nil, err
	}
	id := uuid.New().String()
	_, err = h.DB.ExecContext(r.Context(),
		`INSERT INTO security_bans (id, ip, domain, reason, source, expires_at, target_scope) VALUES (?, ?, ?, ?, 'native', ?, ?)`,
		id, ip, domain, reason, exp, scope)
	if err != nil {
		return nil, err
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "create", "ban:"+id, ip)
	if h.OnBansChange != nil {
		h.OnBansChange()
	}
	return map[string]any{"id": id, "ip": ip, "permanent": expiresAt == "", "scope": scope}, nil
}

func (h *Handler) toolDeleteSecurityBan(r *http.Request, id string) (any, error) {
	if id == "" {
		return nil, fmt.Errorf("id requis")
	}
	var ip, reason, source string
	h.DB.QueryRowContext(r.Context(), //nolint:errcheck
		`SELECT ip, reason, source FROM security_bans WHERE id=?`, id).Scan(&ip, &reason, &source)
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM security_bans WHERE id=?`, id)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, fmt.Errorf("ban introuvable: %s", id)
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "delete", "ban:"+id, "")
	h.notifyUnban(r, ip, reason, source, id)
	return map[string]any{"deleted": id}, nil
}

// notifyUnban trace le déban dans l'historique (rejoué aux passerelles qui l'auraient manqué, et
// point de départ du comptage des Seuils multi-passerelles) puis le propage aux passerelles.
func (h *Handler) notifyUnban(r *http.Request, ip, reason, source, banID string) {
	if ip == "" {
		if h.OnBansChange != nil {
			h.OnBansChange()
		}
		return
	}
	h.DB.ExecContext(r.Context(), //nolint:errcheck
		`INSERT INTO security_ban_history (ip, domain, action, reason, source, ban_id) VALUES (?, '', 'unbanned', ?, ?, ?)`,
		ip, reason, source, banID)
	if h.OnUnban != nil {
		h.OnUnban(ip)
	} else if h.OnBansChange != nil {
		h.OnBansChange()
	}
}

func (h *Handler) toolBanIP(r *http.Request, args map[string]any) (any, error) {
	rawIP, _ := args["ip"].(string)
	ip, err := h.banTarget(r, rawIP)
	if err != nil {
		return nil, err
	}
	reason, _ := args["reason"].(string)
	if reason == "" {
		reason = "mcp_ban"
	}
	expiresAt, _ := args["expires_at"].(string)
	exp, err := security.NormalizeBanExpiry(expiresAt)
	if err != nil {
		return nil, err
	}
	id := "mcp-" + ip
	_, err = h.DB.ExecContext(r.Context(),
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
	h.notifyUnban(r, ip, "", "", "")
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
		domain, issuer, certPEM, keyPEM, sqltime.Format(leaf.NotAfter))
	if err != nil {
		return nil, err
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "import_cert", "domain:"+domain, "")
	return map[string]any{"domain": domain, "issuer": issuer, "expires_at": leaf.NotAfter.UTC().Format(time.RFC3339), "status": "imported"}, nil
}

func (h *Handler) toolCreateInternalCA(r *http.Request, args map[string]any) (any, error) {
	if h.InternalCA == nil {
		return nil, fmt.Errorf("CA interne non configurée")
	}
	name, _ := args["name"].(string)
	commonName, _ := args["common_name"].(string)
	if name == "" || commonName == "" {
		return nil, fmt.Errorf("name et common_name requis")
	}
	years := 10
	if v, ok := args["validity_years"].(float64); ok && v > 0 {
		years = int(v)
	}
	ca, err := h.InternalCA.CreateCA(r.Context(), name, commonName, time.Duration(years)*365*24*time.Hour)
	if err != nil {
		return nil, err
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "create_internal_ca", "ca:"+ca.ID, "")
	return ca, nil
}

func (h *Handler) toolListInternalCAs(r *http.Request) (any, error) {
	if h.InternalCA == nil {
		return nil, fmt.Errorf("CA interne non configurée")
	}
	return h.InternalCA.ListCAs(r.Context())
}

func (h *Handler) toolIssueInternalCert(r *http.Request, args map[string]any) (any, error) {
	if h.InternalCA == nil {
		return nil, fmt.Errorf("CA interne non configurée")
	}
	caID, _ := args["ca_id"].(string)
	commonName, _ := args["common_name"].(string)
	usage, _ := args["usage"].(string)
	if caID == "" || commonName == "" {
		return nil, fmt.Errorf("ca_id et common_name requis")
	}
	if usage == "" {
		usage = "server"
	}
	var sans []string
	if raw, ok := args["sans"].([]any); ok {
		for _, s := range raw {
			if str, ok := s.(string); ok {
				sans = append(sans, str)
			}
		}
	}
	days := 397
	if v, ok := args["validity_days"].(float64); ok && v > 0 {
		days = int(v)
	}
	cert, err := h.InternalCA.IssueCert(r.Context(), caID, commonName, sans, usage, time.Duration(days)*24*time.Hour)
	if err != nil {
		return nil, err
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "issue_internal_cert", "cert:"+cert.ID, "")
	return cert, nil
}

func (h *Handler) toolListInternalCerts(r *http.Request, caID string) (any, error) {
	if h.InternalCA == nil {
		return nil, fmt.Errorf("CA interne non configurée")
	}
	if caID == "" {
		return nil, fmt.Errorf("ca_id requis")
	}
	return h.InternalCA.ListCerts(r.Context(), caID)
}

func (h *Handler) toolRevokeInternalCert(r *http.Request, certID string) (any, error) {
	if h.InternalCA == nil {
		return nil, fmt.Errorf("CA interne non configurée")
	}
	if certID == "" {
		return nil, fmt.Errorf("cert_id requis")
	}
	if err := h.InternalCA.RevokeCert(r.Context(), certID); err != nil {
		return nil, err
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "revoke_internal_cert", "cert:"+certID, "")
	return map[string]any{"cert_id": certID, "status": "revoked"}, nil
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
		`SELECT id, ip, scenario, origin, type, duration, edge_name, occurrences, last_seen_at, created_at
		 FROM security_threats ORDER BY last_seen_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, occurrences int
		var ip, scenario, origin, typ, duration, edgeName, lastSeenAt, createdAt string
		if err := rows.Scan(&id, &ip, &scenario, &origin, &typ, &duration, &edgeName, &occurrences, &lastSeenAt, &createdAt); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id": id, "ip": ip, "scenario": scenario, "origin": origin,
			"type": typ, "duration": duration, "edge_name": edgeName,
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
	if kevOnly, _ := args["kev_only"].(bool); kevOnly {
		clauses = append(clauses, "kev=1")
	}
	where := ""
	if len(clauses) > 0 {
		where = " WHERE " + strings.Join(clauses, " AND ")
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, backend_url, cve_id, cvss_score, description, status, edge_name, detected_at, kev, epss_score, host, product, version, source
		 FROM security_cves`+where+` ORDER BY cvss_score DESC, detected_at DESC LIMIT 200`, qargs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, kevInt int
		var backend, cveID, desc, status, edgeName, detectedAt, host, product, version, source string
		var cvss, epssScore float64
		if err := rows.Scan(&id, &backend, &cveID, &cvss, &desc, &status, &edgeName, &detectedAt, &kevInt, &epssScore, &host, &product, &version, &source); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id": id, "backend_url": backend, "cve_id": cveID, "cvss_score": cvss,
			"description": desc, "status": status, "edge_name": edgeName, "detected_at": detectedAt,
			"kev": kevInt != 0, "epss_score": epssScore,
			"host": host, "product": product, "version": version, "source": source,
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
			{"uri": "goproxify://nodes", "name": "Nœuds", "description": "Liste des nœuds passerelle et Agent", "mimeType": "application/json"},
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

// resourceTools associe chaque ressource à l'outil qu'elle expose : sa lecture
// exige les mêmes droits que l'outil.
var resourceTools = map[string]string{
	"goproxify://proxies":             "list_proxies",
	"goproxify://nodes":               "list_nodes",
	"goproxify://agents":              "list_agents",
	"goproxify://alerts":              "list_alerts",
	"goproxify://users":               "list_users",
	"goproxify://snippets":            "list_snippets",
	"goproxify://domains":             "list_domains",
	"goproxify://certs":               "list_certs",
	"goproxify://certs/monitor":       "get_cert_status",
	"goproxify://logs":                "list_logs",
	"goproxify://security/bans":       "list_security_bans",
	"goproxify://security/threats":    "list_security_threats",
	"goproxify://security/cves":       "list_security_cves",
	"goproxify://portal/destinations": "list_portal_destinations",
	"goproxify://portal/users":        "list_portal_users",
	"goproxify://portal/templates":    "list_portal_templates",
	"goproxify://portal/audit":        "list_portal_audit",
	"goproxify://declared-nodes":      "list_declared_nodes",
}

func (h *Handler) handleResourcesRead(req rpcRequest, r *http.Request) rpcResponse {
	var p struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return errResp(req.ID, -32602, "invalid params")
	}
	tool, ok := resourceTools[p.URI]
	if !ok {
		return errResp(req.ID, -32002, "resource not found: "+p.URI)
	}
	if denied := h.denyTool(r, tool); denied != "" {
		return errResp(req.ID, -32603, denied)
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
	if r.URL.RawQuery != "" {
		endpointURL += "?" + r.URL.RawQuery // conserve ?toolsets= pour les POST du client
	}
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

func (h *Handler) toolGetProxyMetrics(host string, points int) (any, error) {
	if h.ProxyMetrics == nil {
		return nil, fmt.Errorf("relevé des métriques indisponible")
	}
	entries, sampledAt := h.ProxyMetrics(points)
	if host != "" {
		raw, err := json.Marshal(entries)
		if err != nil {
			return nil, err
		}
		var all []map[string]any
		if err := json.Unmarshal(raw, &all); err != nil {
			return nil, err
		}
		filtered := make([]map[string]any, 0, 1)
		for _, e := range all {
			if e["host"] == host {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}
	return map[string]any{"interval_s": 10, "sampled_at": sampledAt, "proxies": entries}, nil
}

func (h *Handler) toolListAlertEvents(r *http.Request, args map[string]any) (any, error) {
	days, _ := args["days"].(float64)
	limit, _ := args["limit"].(float64)
	trigger, _ := args["trigger"].(string)
	node, _ := args["node"].(string)
	return alerting.RecentEvents(r.Context(), h.DB, int(days), int(limit), trigger, node)
}

// advancedProxyOptions : clés de la configuration d'un proxy modifiables par update_proxy (`options`).
var advancedProxyOptions = map[string]bool{
	"split": true, "maintenance": true, "signed_url": true, "graphql": true, "bandwidth": true,
	"redact_json": true, "html_inject": true, "hedge": true, "static": true, "request_schema": true, "openapi": true, "grpc_transcode": true, "grpc_web": true, "rate_limit": true, "conditions": true, "surface": true,
	"max_body_size": true, "ip_filter": true, "geo_ip": true, "cors": true, "waf": true,
}

// toolListLogsEdges : list_logs avec source=edge. Même logique que GET /api/v1/logs?source=edge (fusion des bases de
// logs des passerelles et des lignes propres de l'Admin).
func (h *Handler) toolListLogsEdges(r *http.Request, args map[string]any) (any, error) {
	q := url.Values{"source": {"edge"}}
	for arg, param := range map[string]string{
		"domain": "domain", "level": "level", "request_id": "request_id", "tls_ja3": "tls_ja3", "tls_ja4": "tls_ja4",
		"node": "node_name", "cursor": "cursor",
	} {
		if v, _ := args[arg].(string); v != "" {
			q.Set(param, v)
		}
	}
	lh := &api.LogsHandler{DB: h.DB, Store: logs.New(h.DB), Log: h.Log}
	return lh.ListEdges(r.Context(), q)
}

// toolSIEMStatus : get_siem_status. Même contenu que GET /api/v1/logs/siem et /api/v1/logs/siem/status.
func (h *Handler) toolSIEMStatus() any {
	nodes := []siemcfg.NodeStatus{}
	if h.SIEMStatus != nil {
		nodes = h.SIEMStatus()
	}
	return map[string]any{"config": siemcfg.Mask(siemcfg.Load(h.DB)), "nodes": nodes}
}

// metricsFromAggregates : requêtes, erreurs et latence des 24 dernières heures lues dans les cumuls par minute que
// calculent les passerelles (elles ne comptent que les requêtes HTTP, pas les lignes système). Les IP uniques
// portent sur des lignes : elles viendront du regroupement par dimension des passerelles.
func (h *Handler) metricsFromAggregates(r *http.Request, proxy string) (any, error) {
	since := time.Now().Add(-24 * time.Hour)
	q := `SELECT COALESCE(SUM(requests), 0),
	             COALESCE(SUM(CASE WHEN status >= 400 THEN requests ELSE 0 END), 0),
	             COALESCE(SUM(latency_ms_sum), 0)
	      FROM logs_minute WHERE minute >= ?`
	args := []any{logs.MinuteKey(since)}
	if proxy != "" {
		q += ` AND domain = ?`
		args = append(args, proxy)
	}
	var reqs, errs, latSum int64
	if err := h.DB.QueryRowContext(r.Context(), q, args...).Scan(&reqs, &errs, &latSum); err != nil {
		return nil, err
	}
	errRate, avgLat := 0.0, 0.0
	if reqs > 0 {
		errRate = float64(int64(10000*float64(errs)/float64(reqs)+0.5)) / 100
		avgLat = float64(int64(float64(latSum)/float64(reqs) + 0.5))
	}
	ips, estimated := h.uniqueIPs(r.Context(), proxy, since)
	out := map[string]any{
		"requests": reqs, "errors": errs, "error_rate": errRate,
		"avg_latency_ms": avgLat, "unique_ips": ips,
		"window": "24h",
	}
	if estimated {
		out["unique_ips_estimated"] = true
	}
	return out, nil
}


func (h *Handler) toolGetMetrics(r *http.Request, proxy string) (any, error) {
	return h.metricsFromAggregates(r, proxy)
}

// uniqueIPs compte les IP distinctes depuis since : l'union de celles des passerelles (estimée au-delà de quelques
// milliers) ; sans passerelle, zéro.
func (h *Handler) uniqueIPs(ctx context.Context, proxy string, since time.Time) (n int64, estimated bool) {
	src := &prismedge.Source{DB: h.DB}
	p := analytics.Params{Proxy: proxy, From: since, To: time.Now()}
	if !src.Available(ctx, p) {
		return 0, false
	}
	n, meta, err := src.UniqueIPs(ctx, p)
	if err != nil {
		return 0, false
	}
	return n, meta.Estimated
}
