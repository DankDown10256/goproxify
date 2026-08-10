// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/api"
)

// AccessPusher pousse la config portail vers un Core (évite import corews).
type AccessPusher = api.PortalPusher

// AccessTemplatesPusher pousse les templates HTML Access.
type AccessTemplatesPusher = api.PortalPageTemplatePusher

func (h *Handler) portalHandler() *api.PortalHandler {
	return &api.PortalHandler{DB: h.DB, Log: h.Log, Pusher: h.Access}
}

func (h *Handler) portalTemplatesHandler() *api.PortalPageTemplatesHandler {
	return &api.PortalPageTemplatesHandler{DB: h.DB, Log: h.Log, Pusher: h.AccessTemplates}
}

func (h *Handler) callHandler(r *http.Request, handler http.Handler, method, path string, body any) (any, error) {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rdr)
	req = req.WithContext(r.Context())
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code >= 400 {
		msg := strings.TrimSpace(rr.Body.String())
		if msg == "" {
			msg = http.StatusText(rr.Code)
		}
		return nil, fmt.Errorf("HTTP %d: %s", rr.Code, msg)
	}
	if rr.Body.Len() == 0 {
		return map[string]any{"ok": true}, nil
	}
	var out any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (h *Handler) callPortal(r *http.Request, method, path string, body any) (any, error) {
	return h.callHandler(r, h.portalHandler(), method, path, body)
}

func (h *Handler) callPortalTemplates(r *http.Request, method, path string, body any) (any, error) {
	return h.callHandler(r, h.portalTemplatesHandler(), method, path, body)
}

func argStr(args map[string]any, key string) string {
	v, _ := args[key].(string)
	return strings.TrimSpace(v)
}

func argBoolPtr(args map[string]any, key string) *bool {
	v, ok := args[key].(bool)
	if !ok {
		return nil
	}
	return &v
}

func argInt(args map[string]any, key string, def int) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err == nil {
			return n
		}
	}
	return def
}

func argStringSlice(args map[string]any, key string) []string {
	v, ok := args[key]
	if !ok || v == nil {
		return nil
	}
	switch x := v.(type) {
	case []string:
		return x
	case string:
		if strings.TrimSpace(x) == "" {
			return []string{}
		}
		parts := strings.Split(x, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				out = append(out, p)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	}
	return nil
}

func portalTools() []map[string]any {
	return []map[string]any{
		{
			"name":        "get_portal_config",
			"description": "Retourne la config GoProxify Access (portail SSH/shell) pour un Core.",
			"inputSchema": schema(req("core", "string", "Nom du nœud Core")),
		},
		{
			"name":        "update_portal_config",
			"description": "Met à jour les options Access d'un Core (ports, hôte public, 2FA, TTL session…) et pousse vers le Core.",
			"inputSchema": schema(
				req("core", "string", "Nom du nœud Core"),
				opt("enabled", "boolean", "Active le portail Access"),
				opt("ssh_port", "number", "Port SSH Access"),
				opt("http_port", "number", "Port HTTPS Access"),
				opt("public_host", "string", "Hôte public (invitations / liens)"),
				opt("allow_personal_targets", "boolean", "Autoriser les cibles personnelles"),
				opt("require_2fa", "boolean", "Exiger la 2FA Access"),
				opt("session_ttl_sec", "number", "TTL session en secondes"),
				opt("session_mode", "string", "Mode session: one_shot ou renew"),
			),
		},
		{
			"name":        "push_portal",
			"description": "Repousse la config Access (catalogue + users) vers un Core.",
			"inputSchema": schema(req("core", "string", "Nom du nœud Core")),
		},
		{
			"name":        "list_portal_destinations",
			"description": "Liste le catalogue de destinations Access (filtre optionnel par Core).",
			"inputSchema": schema(opt("core", "string", "Filtrer par nom de Core")),
		},
		{
			"name":        "create_portal_destination",
			"description": "Ajoute une destination au catalogue Access.",
			"inputSchema": schema(
				req("core_name", "string", "Core propriétaire"),
				req("name", "string", "Libellé affiché"),
				req("kind", "string", "ssh ou docker"),
				opt("host", "string", "Hôte SSH (kind=ssh)"),
				opt("port", "number", "Port SSH (défaut 22)"),
				opt("agent_name", "string", "Nom Agent (kind=docker)"),
				opt("container", "string", "Conteneur (kind=docker)"),
				opt("tags", "array", "Tags (intersection avec users)"),
			),
		},
		{
			"name":        "update_portal_destination",
			"description": "Modifie une destination Access existante.",
			"inputSchema": schema(
				req("id", "string", "ID de la destination"),
				req("core_name", "string", "Core propriétaire"),
				req("name", "string", "Libellé"),
				req("kind", "string", "ssh ou docker"),
				opt("host", "string", "Hôte SSH"),
				opt("port", "number", "Port SSH"),
				opt("agent_name", "string", "Nom Agent"),
				opt("container", "string", "Conteneur"),
				opt("tags", "array", "Tags"),
				opt("enabled", "boolean", "Active / désactive"),
			),
		},
		{
			"name":        "delete_portal_destination",
			"description": "Supprime une destination du catalogue Access.",
			"inputSchema": schema(req("id", "string", "ID de la destination")),
		},
		{
			"name":        "preview_portal_destinations",
			"description": "Prévisualise les destinations Access visibles pour un jeu de tags (intersection).",
			"inputSchema": schema(
				req("core", "string", "Nom du Core"),
				opt("tags", "string", "Tags séparés par des virgules"),
			),
		},
		{
			"name":        "list_portal_users",
			"description": "Liste les utilisateurs Access (invités / actifs).",
			"inputSchema": schema(opt("core", "string", "Filtrer par home_core")),
		},
		{
			"name":        "invite_portal_user",
			"description": "Invite un utilisateur Access par email (SMTP Admin requis).",
			"inputSchema": schema(
				req("email", "string", "Email de l'invité"),
				req("home_core", "string", "Core d'accueil"),
				opt("tags", "array", "Tags utilisateur"),
			),
		},
		{
			"name":        "update_portal_user",
			"description": "Met à jour tags, statut ou home_core d'un utilisateur Access.",
			"inputSchema": schema(
				req("id", "string", "ID utilisateur Access"),
				opt("tags", "array", "Nouveaux tags"),
				opt("status", "string", "active, invited ou disabled"),
				opt("home_core", "string", "Nouveau Core d'accueil"),
			),
		},
		{
			"name":        "delete_portal_user",
			"description": "Supprime un utilisateur Access.",
			"inputSchema": schema(req("id", "string", "ID utilisateur Access")),
		},
		{
			"name":        "resend_portal_invite",
			"description": "Renvoie l'email d'invitation Access.",
			"inputSchema": schema(req("id", "string", "ID utilisateur Access")),
		},
		{
			"name":        "list_portal_audit",
			"description": "Journal d'audit Access (métadonnées sessions / connexions).",
			"inputSchema": schema(
				opt("core", "string", "Filtrer par Core"),
				opt("limit", "number", "Nombre d'entrées (défaut 100, max 500)"),
			),
		},
		{
			"name":        "list_portal_templates",
			"description": "Liste les templates HTML Access (login, vault, shell…).",
			"inputSchema": schema(),
		},
		{
			"name":        "get_portal_template",
			"description": "Retourne un template HTML Access par clé.",
			"inputSchema": schema(req("key", "string", "Clé template (ex: login, vault)")),
		},
		{
			"name":        "upsert_portal_template",
			"description": "Crée ou met à jour un template HTML Access.",
			"inputSchema": schema(
				req("key", "string", "Clé template"),
				req("body", "string", "Contenu HTML"),
				opt("name", "string", "Libellé (défaut = clé)"),
			),
		},
		{
			"name":        "delete_portal_template",
			"description": "Supprime un template HTML Access (retour au fallback).",
			"inputSchema": schema(req("key", "string", "Clé template")),
		},
		{
			"name":        "push_portal_templates",
			"description": "Pousse tous les templates HTML Access vers les Cores.",
			"inputSchema": schema(),
		},
	}
}

func (h *Handler) toolGetPortalConfig(r *http.Request, args map[string]any) (any, error) {
	core := argStr(args, "core")
	if core == "" {
		return nil, fmt.Errorf("core requis")
	}
	return h.callPortal(r, http.MethodGet, "/api/v1/portal?core="+url.QueryEscape(core), nil)
}

func (h *Handler) toolUpdatePortalConfig(r *http.Request, args map[string]any) (any, error) {
	core := argStr(args, "core")
	if core == "" {
		return nil, fmt.Errorf("core requis")
	}
	raw, err := h.callPortal(r, http.MethodGet, "/api/v1/portal?core="+url.QueryEscape(core), nil)
	if err != nil {
		return nil, err
	}
	cfgMap, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("réponse config invalide")
	}
	if b := argBoolPtr(args, "enabled"); b != nil {
		cfgMap["enabled"] = *b
	}
	if _, ok := args["ssh_port"]; ok {
		cfgMap["ssh_port"] = argInt(args, "ssh_port", 2222)
	}
	if _, ok := args["http_port"]; ok {
		cfgMap["http_port"] = argInt(args, "http_port", 8444)
	}
	if _, ok := args["public_host"]; ok {
		cfgMap["public_host"] = argStr(args, "public_host")
	}
	if b := argBoolPtr(args, "allow_personal_targets"); b != nil {
		cfgMap["allow_personal_targets"] = *b
	}
	if b := argBoolPtr(args, "require_2fa"); b != nil {
		cfgMap["require_2fa"] = *b
	}
	if _, ok := args["session_ttl_sec"]; ok {
		cfgMap["session_ttl_sec"] = argInt(args, "session_ttl_sec", 60)
	}
	if _, ok := args["session_mode"]; ok {
		cfgMap["session_mode"] = argStr(args, "session_mode")
	}
	return h.callPortal(r, http.MethodPut, "/api/v1/portal?core="+url.QueryEscape(core), cfgMap)
}

func (h *Handler) toolPushPortal(r *http.Request, args map[string]any) (any, error) {
	core := argStr(args, "core")
	if core == "" {
		return nil, fmt.Errorf("core requis")
	}
	return h.callPortal(r, http.MethodPost, "/api/v1/portal/push?core="+url.QueryEscape(core), map[string]any{})
}

func (h *Handler) toolListPortalDestinations(r *http.Request, args map[string]any) (any, error) {
	path := "/api/v1/portal/destinations"
	if core := argStr(args, "core"); core != "" {
		path += "?core=" + url.QueryEscape(core)
	}
	return h.callPortal(r, http.MethodGet, path, nil)
}

func (h *Handler) toolCreatePortalDestination(r *http.Request, args map[string]any) (any, error) {
	body := map[string]any{
		"core_name":  argStr(args, "core_name"),
		"name":       argStr(args, "name"),
		"kind":       argStr(args, "kind"),
		"host":       argStr(args, "host"),
		"port":       argInt(args, "port", 22),
		"agent_name": argStr(args, "agent_name"),
		"container":  argStr(args, "container"),
		"tags":       argStringSlice(args, "tags"),
	}
	if body["core_name"] == "" || body["name"] == "" || body["kind"] == "" {
		return nil, fmt.Errorf("core_name, name et kind requis")
	}
	return h.callPortal(r, http.MethodPost, "/api/v1/portal/destinations", body)
}

func (h *Handler) toolUpdatePortalDestination(r *http.Request, args map[string]any) (any, error) {
	id := argStr(args, "id")
	if id == "" {
		return nil, fmt.Errorf("id requis")
	}
	enabled := true
	if b := argBoolPtr(args, "enabled"); b != nil {
		enabled = *b
	}
	body := map[string]any{
		"core_name":  argStr(args, "core_name"),
		"name":       argStr(args, "name"),
		"kind":       argStr(args, "kind"),
		"host":       argStr(args, "host"),
		"port":       argInt(args, "port", 22),
		"agent_name": argStr(args, "agent_name"),
		"container":  argStr(args, "container"),
		"tags":       argStringSlice(args, "tags"),
		"enabled":    enabled,
	}
	return h.callPortal(r, http.MethodPut, "/api/v1/portal/destinations/"+url.PathEscape(id), body)
}

func (h *Handler) toolDeletePortalDestination(r *http.Request, args map[string]any) (any, error) {
	id := argStr(args, "id")
	if id == "" {
		return nil, fmt.Errorf("id requis")
	}
	return h.callPortal(r, http.MethodDelete, "/api/v1/portal/destinations/"+url.PathEscape(id), nil)
}

func (h *Handler) toolPreviewPortalDestinations(r *http.Request, args map[string]any) (any, error) {
	core := argStr(args, "core")
	if core == "" {
		return nil, fmt.Errorf("core requis")
	}
	q := url.Values{}
	q.Set("core", core)
	if tags := argStr(args, "tags"); tags != "" {
		q.Set("tags", tags)
	} else if sl := argStringSlice(args, "tags"); len(sl) > 0 {
		q.Set("tags", strings.Join(sl, ","))
	}
	return h.callPortal(r, http.MethodGet, "/api/v1/portal/destinations/preview?"+q.Encode(), nil)
}

func (h *Handler) toolListPortalUsers(r *http.Request, args map[string]any) (any, error) {
	path := "/api/v1/portal/users"
	if core := argStr(args, "core"); core != "" {
		path += "?core=" + url.QueryEscape(core)
	}
	return h.callPortal(r, http.MethodGet, path, nil)
}

func (h *Handler) toolInvitePortalUser(r *http.Request, args map[string]any) (any, error) {
	email := argStr(args, "email")
	home := argStr(args, "home_core")
	if email == "" || home == "" {
		return nil, fmt.Errorf("email et home_core requis")
	}
	body := map[string]any{
		"email":     email,
		"home_core": home,
		"tags":      argStringSlice(args, "tags"),
	}
	return h.callPortal(r, http.MethodPost, "/api/v1/portal/users/invite", body)
}

func (h *Handler) toolUpdatePortalUser(r *http.Request, args map[string]any) (any, error) {
	id := argStr(args, "id")
	if id == "" {
		return nil, fmt.Errorf("id requis")
	}
	body := map[string]any{}
	if _, ok := args["tags"]; ok {
		tags := argStringSlice(args, "tags")
		body["tags"] = tags
	}
	if s := argStr(args, "status"); s != "" {
		body["status"] = s
	}
	if s := argStr(args, "home_core"); s != "" {
		body["home_core"] = s
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("aucun champ à mettre à jour")
	}
	return h.callPortal(r, http.MethodPut, "/api/v1/portal/users/"+url.PathEscape(id), body)
}

func (h *Handler) toolDeletePortalUser(r *http.Request, args map[string]any) (any, error) {
	id := argStr(args, "id")
	if id == "" {
		return nil, fmt.Errorf("id requis")
	}
	return h.callPortal(r, http.MethodDelete, "/api/v1/portal/users/"+url.PathEscape(id), nil)
}

func (h *Handler) toolResendPortalInvite(r *http.Request, args map[string]any) (any, error) {
	id := argStr(args, "id")
	if id == "" {
		return nil, fmt.Errorf("id requis")
	}
	return h.callPortal(r, http.MethodPost, "/api/v1/portal/users/"+url.PathEscape(id)+"/resend", map[string]any{})
}

func (h *Handler) toolListPortalAudit(r *http.Request, args map[string]any) (any, error) {
	q := url.Values{}
	if core := argStr(args, "core"); core != "" {
		q.Set("core", core)
	}
	if _, ok := args["limit"]; ok {
		q.Set("limit", strconv.Itoa(argInt(args, "limit", 100)))
	}
	path := "/api/v1/portal/audit"
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	return h.callPortal(r, http.MethodGet, path, nil)
}

func (h *Handler) toolListPortalTemplates(r *http.Request) (any, error) {
	return h.callPortalTemplates(r, http.MethodGet, "/api/v1/portal-page-templates", nil)
}

func (h *Handler) toolGetPortalTemplate(r *http.Request, args map[string]any) (any, error) {
	key := argStr(args, "key")
	if key == "" {
		return nil, fmt.Errorf("key requis")
	}
	return h.callPortalTemplates(r, http.MethodGet, "/api/v1/portal-page-templates/"+url.PathEscape(key), nil)
}

func (h *Handler) toolUpsertPortalTemplate(r *http.Request, args map[string]any) (any, error) {
	key := argStr(args, "key")
	bodyHTML, _ := args["body"].(string)
	if key == "" {
		return nil, fmt.Errorf("key requis")
	}
	name := argStr(args, "name")
	if name == "" {
		name = key
	}
	return h.callPortalTemplates(r, http.MethodPut, "/api/v1/portal-page-templates/"+url.PathEscape(key), map[string]any{
		"name": name,
		"body": bodyHTML,
	})
}

func (h *Handler) toolDeletePortalTemplate(r *http.Request, args map[string]any) (any, error) {
	key := argStr(args, "key")
	if key == "" {
		return nil, fmt.Errorf("key requis")
	}
	return h.callPortalTemplates(r, http.MethodDelete, "/api/v1/portal-page-templates/"+url.PathEscape(key), nil)
}

func (h *Handler) toolPushPortalTemplates(r *http.Request) (any, error) {
	return h.callPortalTemplates(r, http.MethodPost, "/api/v1/portal-page-templates/push", map[string]any{})
}
