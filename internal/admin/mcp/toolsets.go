// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"net/http"
	"strings"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// toolsetNames liste les groupes d'outils sélectionnables via /mcp?toolsets=a,b. Un modèle
// local à petit contexte ne tient pas la liste complète (~17k tokens) : il n'en charge qu'une partie.
var toolsetNames = []string{
	"proxies", "nodes", "alerts", "observability", "domains", "certs",
	"security", "automation", "snippets", "portal", "admin",
}

// toolsetOf rattache un outil à son groupe ; "" si l'outil n'a pas de scope.
func toolsetOf(tool string) string {
	switch tool {
	case "get_proxy_surface", "get_app_inventory", "get_proxy_surface_suggestions", "accept_proxy_surface_suggestions", "enforce_proxy_surface", "relax_proxy_surface", "get_proxy_surface_proposals", "get_proxy_surface_openapi", "reset_proxy_surface", "simulate_ephor_config", "get_ephor_references", "suggest_ephor_thresholds", "trace_ip", "preview_security_ban", "preview_asn_ban":
		return "security"
	case "get_audit_log":
		return "admin"
	}
	if strings.Contains(tool, "flow") || strings.Contains(tool, "silence") || strings.Contains(tool, "automation") {
		return "automation"
	}
	switch rbac.ToolRequiredScope(tool) {
	case rbac.ScopeProxiesRead, rbac.ScopeProxiesWrite, rbac.ScopeProxiesDelete:
		return "proxies"
	case rbac.ScopeNodesRead, rbac.ScopeNodesWrite:
		return "nodes"
	case rbac.ScopeAlertsRead, rbac.ScopeAlertsWrite:
		return "alerts"
	case rbac.ScopeMetricsRead, rbac.ScopeLogsRead:
		return "observability"
	case rbac.ScopeDomainsRead, rbac.ScopeDomainsWrite:
		return "domains"
	case rbac.ScopeCertsRead, rbac.ScopeCertsWrite:
		return "certs"
	case rbac.ScopeAuditRead, rbac.ScopeSecurityWrite:
		return "security"
	case rbac.ScopeSnippetsRead, rbac.ScopeSnippetsWrite:
		return "snippets"
	case rbac.ScopePortalRead, rbac.ScopePortalWrite:
		return "portal"
	case rbac.ScopeBackupsRead, rbac.ScopeUsersRead, rbac.ScopeTeamsRead:
		return "admin"
	}
	return ""
}

// parseToolsets lit ?toolsets= ; nil = tous les groupes.
func parseToolsets(raw string) (map[string]bool, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	known := map[string]bool{}
	for _, n := range toolsetNames {
		known[n] = true
	}
	sets := map[string]bool{}
	for _, s := range strings.Split(raw, ",") {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if !known[s] {
			return nil, fmt.Errorf("toolset inconnu: %s (disponibles: %s)", s, strings.Join(toolsetNames, ", "))
		}
		sets[s] = true
	}
	return sets, nil
}

// handleToolsList n'annonce que les outils que l'appelant peut appeler (mêmes contrôles que
// denyTool, mémorisés par scope), restreints aux groupes demandés par ?toolsets=.
func (h *Handler) handleToolsList(req rpcRequest, r *http.Request) rpcResponse {
	sets, err := parseToolsets(r.URL.Query().Get("toolsets"))
	if err != nil {
		return errResp(req.ID, -32602, err.Error())
	}
	ctx := r.Context()
	scopeOK := map[string]bool{}
	var isAdmin *bool
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		name, _ := t["name"].(string)
		if sets != nil && !sets[toolsetOf(name)] {
			continue
		}
		scope := rbac.ToolRequiredScope(name)
		if scope == "" {
			continue
		}
		ok, seen := scopeOK[scope]
		if !seen {
			ok = rbac.EffectiveHasScope(ctx, h.DB, scope)
			scopeOK[scope] = ok
		}
		if !ok {
			continue
		}
		if rbac.ToolRequiresAdmin(name) {
			if isAdmin == nil {
				v := rbac.IsAdmin(ctx, h.DB, adminauth.UserIDFromContext(ctx))
				isAdmin = &v
			}
			if !*isAdmin {
				continue
			}
		}
		out = append(out, t)
	}
	return okResp(req.ID, map[string]any{"tools": out})
}
