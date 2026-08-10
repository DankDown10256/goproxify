// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/auth"
)

// Catalogue v1 des scopes ressource (API + MCP).
const (
	ScopeProxiesRead   = "proxies:read"
	ScopeProxiesWrite  = "proxies:write"
	ScopeProxiesDelete = "proxies:delete"
	ScopeNodesRead     = "nodes:read"
	ScopeNodesWrite    = "nodes:write"
	ScopeAlertsRead    = "alerts:read"
	ScopeMetricsRead   = "metrics:read"
	ScopeBackupsRead   = "backups:read"
	ScopeUsersRead     = "users:read"
	ScopeSnippetsRead  = "snippets:read"
	ScopeSnippetsWrite = "snippets:write"
	ScopeDomainsRead   = "domains:read"
	ScopeCertsRead     = "certs:read"
	ScopeLogsRead      = "logs:read"
	ScopeTeamsRead     = "teams:read"
	ScopeAuditRead     = "audit:read"
	ScopeSecurityWrite = "security:write"
	ScopeImportWrite   = "import:write"
	ScopePairingRead   = "pairing:read"
	ScopePortalRead    = "portal:read"
	ScopePortalWrite   = "portal:write"
)

// AllPATScopes liste tous les scopes connus (ordre stable pour l'UI).
var AllPATScopes = []string{
	ScopeProxiesRead, ScopeProxiesWrite, ScopeProxiesDelete,
	ScopeNodesRead, ScopeNodesWrite, ScopeAlertsRead, ScopeMetricsRead, ScopeBackupsRead,
	ScopeUsersRead, ScopeSnippetsRead, ScopeSnippetsWrite,
	ScopeDomainsRead, ScopeCertsRead, ScopeLogsRead, ScopeTeamsRead, ScopeAuditRead,
	ScopeSecurityWrite, ScopeImportWrite, ScopePairingRead,
	ScopePortalRead, ScopePortalWrite,
}

// ScopeMeta décrit un scope pour l'UI / API.
type ScopeMeta struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

// ScopeCatalog retourne les métadonnées de tous les scopes.
func ScopeCatalog() []ScopeMeta {
	desc := map[string]string{
		ScopeProxiesRead:   "Lister et lire les proxies",
		ScopeProxiesWrite:  "Créer et modifier les proxies",
		ScopeProxiesDelete: "Supprimer des proxies",
		ScopeNodesRead:     "Lister les nœuds / Cores",
		ScopeNodesWrite:    "Approuver / révoquer Agents et muter les nœuds",
		ScopeAlertsRead:    "Lister les alertes et règles",
		ScopeMetricsRead:   "Lire les métriques",
		ScopeBackupsRead:   "Lister les sauvegardes",
		ScopeUsersRead:     "Lister les utilisateurs",
		ScopeSnippetsRead:  "Lister les snippets",
		ScopeSnippetsWrite: "Créer et modifier les snippets",
		ScopeDomainsRead:   "Lister les domaines",
		ScopeCertsRead:     "Lister les certificats",
		ScopeLogsRead:      "Lire les logs",
		ScopeTeamsRead:     "Lister les équipes",
		ScopeAuditRead:     "Lire le journal d'audit et le dashboard sécurité (bans, menaces, CVE)",
		ScopeSecurityWrite: "Créer / supprimer bans et muter la sécurité",
		ScopeImportWrite:   "Importer des configurations",
		ScopePairingRead:   "Lire le secret d'appairage",
		ScopePortalRead:    "Lire GoProxify Access (config, catalogue, users, templates, audit)",
		ScopePortalWrite:   "Gérer GoProxify Access (config, catalogue, invitations, templates, push)",
	}
	out := make([]ScopeMeta, 0, len(AllPATScopes))
	for _, id := range AllPATScopes {
		out = append(out, ScopeMeta{ID: id, Description: desc[id]})
	}
	return out
}

// IsKnownScope indique si le scope fait partie du catalogue v1.
func IsKnownScope(scope string) bool {
	for _, s := range AllPATScopes {
		if s == scope {
			return true
		}
	}
	return false
}

// AvailableScopesForUser retourne les scopes que le compte peut actuellement déléguer / exercer.
func AvailableScopesForUser(ctx context.Context, db *sql.DB, userID string) []string {
	role := UserRole(ctx, db, userID)
	if role == "" {
		return nil
	}
	var out []string
	add := func(scopes ...string) {
		for _, s := range scopes {
			out = append(out, s)
		}
	}
	// Lecture de base pour tout compte authentifié
	add(ScopeProxiesRead, ScopeNodesRead, ScopeAlertsRead, ScopeMetricsRead,
		ScopeBackupsRead, ScopeSnippetsRead, ScopeDomainsRead, ScopeCertsRead,
		ScopeLogsRead, ScopeAuditRead)

	switch {
	case IsSuperAdminRole(role), IsAdminRole(role):
		add(ScopeProxiesWrite, ScopeProxiesDelete, ScopeSnippetsWrite, ScopeUsersRead, ScopeTeamsRead,
			ScopeNodesWrite, ScopeSecurityWrite, ScopeImportWrite, ScopePairingRead,
			ScopePortalRead, ScopePortalWrite)
	default:
		// user (et legacy operator/viewer normalisés) : write PAT si grant write effectif
		if UserHasWriteGrant(ctx, db, userID) {
			add(ScopeProxiesWrite, ScopeSnippetsWrite)
		}
	}
	return out
}

// UserCanHoldScope indique si le compte possède actuellement ce droit.
func UserCanHoldScope(ctx context.Context, db *sql.DB, userID, scope string) bool {
	for _, s := range AvailableScopesForUser(ctx, db, userID) {
		if s == scope {
			return true
		}
	}
	return false
}

// EffectiveHasScope applique scopes PAT ∩ droits courants (ou droits seuls pour JWT).
func EffectiveHasScope(ctx context.Context, db *sql.DB, scope string) bool {
	userID := auth.UserIDFromContext(ctx)
	if userID == "" || !UserCanHoldScope(ctx, db, userID, scope) {
		return false
	}
	if !auth.IsPATAuth(ctx) {
		return true
	}
	for _, s := range auth.PATScopesFromContext(ctx) {
		if s == scope {
			return true
		}
	}
	return false
}

// ToolRequiredScope mappe un outil MCP vers le scope requis.
func ToolRequiredScope(tool string) string {
	switch tool {
	case "list_proxies", "get_proxy":
		return ScopeProxiesRead
	case "create_proxy", "update_proxy", "set_proxy_enabled":
		return ScopeProxiesWrite
	case "delete_proxy":
		return ScopeProxiesDelete
	case "list_nodes", "list_agents", "list_declared_nodes":
		return ScopeNodesRead
	case "approve_agent", "revoke_agent",
		"create_declared_node", "delete_declared_node",
		"create_bootstrap_ticket", "accept_node", "reject_node":
		return ScopeNodesWrite
	case "list_alerts":
		return ScopeAlertsRead
	case "get_metrics":
		return ScopeMetricsRead
	case "list_backups":
		return ScopeBackupsRead
	case "list_users":
		return ScopeUsersRead
	case "list_snippets":
		return ScopeSnippetsRead
	case "list_domains":
		return ScopeDomainsRead
	case "list_certs":
		return ScopeCertsRead
	case "list_logs":
		return ScopeLogsRead
	case "list_teams":
		return ScopeTeamsRead
	case "get_audit_log",
		"get_security_overview", "list_security_bans",
		"list_security_threats", "list_security_cves":
		return ScopeAuditRead
	case "create_security_ban", "delete_security_ban":
		return ScopeSecurityWrite
	case "get_portal_config", "list_portal_destinations", "preview_portal_destinations",
		"list_portal_users", "list_portal_audit", "list_portal_templates", "get_portal_template":
		return ScopePortalRead
	case "update_portal_config", "push_portal",
		"create_portal_destination", "update_portal_destination", "delete_portal_destination",
		"invite_portal_user", "update_portal_user", "delete_portal_user", "resend_portal_invite",
		"upsert_portal_template", "delete_portal_template", "push_portal_templates":
		return ScopePortalWrite
	default:
		return ""
	}
}

// RequiredScopeForRequest déduit le scope API pour une requête REST (PAT uniquement).
// Retourne "" si aucune contrainte de scope PAT (ex. /me, MFA).
func RequiredScopeForRequest(r *http.Request) string {
	path := r.URL.Path
	method := r.Method

	// Gestion des PAT self-service : JWT seulement (vérifié ailleurs) — pas de scope.
	if strings.HasPrefix(path, "/api/v1/me") {
		return ""
	}
	if strings.HasPrefix(path, "/api/v1/auth/") {
		return ""
	}
	if strings.HasPrefix(path, "/api/v1/settings/mfa") {
		return ""
	}
	if path == "/api/v1/pairing-secret" {
		return ScopePairingRead
	}

	switch {
	case strings.HasPrefix(path, "/api/v1/proxies"):
		switch method {
		case http.MethodGet:
			return ScopeProxiesRead
		case http.MethodDelete:
			return ScopeProxiesDelete
		default:
			return ScopeProxiesWrite
		}
	case strings.HasPrefix(path, "/api/v1/nodes"),
		strings.HasPrefix(path, "/api/v1/declared-nodes"),
		strings.HasPrefix(path, "/api/v1/bootstrap-tickets"),
		strings.HasPrefix(path, "/api/v1/node-events"),
		strings.HasPrefix(path, "/api/v1/discovered-containers"),
		strings.HasPrefix(path, "/api/v1/backends/health"),
		strings.HasPrefix(path, "/api/v1/agents"):
		if method == http.MethodGet {
			return ScopeNodesRead
		}
		return ScopeNodesWrite
	case strings.HasPrefix(path, "/api/v1/alert"):
		return ScopeAlertsRead
	case strings.HasPrefix(path, "/api/v1/prism"):
		return ScopeMetricsRead
	case strings.HasPrefix(path, "/api/v1/backups"):
		return ScopeBackupsRead
	case strings.HasPrefix(path, "/api/v1/users"):
		return ScopeUsersRead
	case strings.HasPrefix(path, "/api/v1/snippets"):
		if method == http.MethodGet {
			return ScopeSnippetsRead
		}
		return ScopeSnippetsWrite
	case strings.HasPrefix(path, "/api/v1/domains"):
		return ScopeDomainsRead
	case strings.HasPrefix(path, "/api/v1/certs"):
		return ScopeCertsRead
	case strings.HasPrefix(path, "/api/v1/logs"):
		return ScopeLogsRead
	case strings.HasPrefix(path, "/api/v1/teams"):
		return ScopeTeamsRead
	case strings.HasPrefix(path, "/api/v1/audit"):
		return ScopeAuditRead
	case strings.HasPrefix(path, "/api/v1/tokens"):
		// Tokens d'appairage : réservé admin ; un PAT ne doit pas les gérer sans users-like droit.
		return ScopeUsersRead
	case strings.HasPrefix(path, "/api/v1/security"),
		strings.HasPrefix(path, "/api/v1/ip-profiles"),
		strings.HasPrefix(path, "/api/v1/auth-providers"):
		if method == http.MethodGet {
			return ScopeAuditRead
		}
		return ScopeSecurityWrite
	case strings.HasPrefix(path, "/api/v1/import"):
		if method == http.MethodGet {
			return ScopeAuditRead
		}
		return ScopeImportWrite
	case strings.HasPrefix(path, "/api/v1/portal"),
		strings.HasPrefix(path, "/api/v1/portal-page-templates"):
		if method == http.MethodGet {
			return ScopePortalRead
		}
		return ScopePortalWrite
	default:
		return ""
	}
}

// EnforcePATScope refuse les requêtes PAT sans le scope effectif requis.
func EnforcePATScope(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !auth.IsPATAuth(r.Context()) {
				next.ServeHTTP(w, r)
				return
			}
			required := RequiredScopeForRequest(r)
			if required == "" {
				next.ServeHTTP(w, r)
				return
			}
			if !EffectiveHasScope(r.Context(), db, required) {
				http.Error(w, "scope insuffisant: "+required, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
