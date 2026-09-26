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

// AccessPusher pousse la config portail vers une passerelle (évite import edgews).
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
			"description": "Retourne la config GoProxify Access (portail SSH/shell) pour une passerelle.",
			"inputSchema": schema(req("edge", "string", "Nom du nœud passerelle")),
		},
		{
			"name":        "update_portal_config",
			"description": "Met à jour les options Access d'une passerelle (ports, hôte public, 2FA, TTL session…) et pousse vers la passerelle.",
			"inputSchema": schema(
				req("edge", "string", "Nom du nœud passerelle"),
				opt("enabled", "boolean", "Active le portail Access"),
				opt("ssh_port", "number", "Port SSH Access"),
				opt("http_port", "number", "Port HTTPS Access"),
				opt("public_host", "string", "Hôte public (invitations / liens)"),
				opt("allow_personal_targets", "boolean", "Autoriser les cibles personnelles"),
				opt("require_2fa", "boolean", "Exiger la 2FA Access"),
				opt("session_ttl_sec", "number", "TTL session en secondes"),
				opt("session_mode", "string", "Mode session: one_shot ou renew"),
				opt("ha_session_mode", "string", "Groupe HA : sessions web sticky (défaut, restent sur la passerelle) ou shared (répliquées entre les membres)"),
			),
		},
		{
			"name":        "push_portal",
			"description": "Repousse la config Access (catalogue + users) vers une passerelle.",
			"inputSchema": schema(req("edge", "string", "Nom du nœud passerelle")),
		},
		{
			"name":        "list_portal_destinations",
			"description": "Liste le catalogue de destinations Access (filtre optionnel par passerelle).",
			"inputSchema": schema(opt("edge", "string", "Filtrer par nom de passerelle")),
		},
		{
			"name":        "create_portal_destination",
			"description": "Ajoute une destination au catalogue Access.",
			"inputSchema": schema(
				req("edge_name", "string", "Passerelle propriétaire"),
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
				req("edge_name", "string", "Passerelle propriétaire"),
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
				req("edge", "string", "Nom de la passerelle"),
				opt("tags", "string", "Tags séparés par des virgules"),
			),
		},
		{
			"name":        "list_portal_users",
			"description": "Liste les utilisateurs Access (invités / actifs).",
			"inputSchema": schema(opt("edge", "string", "Filtrer par home_edge")),
		},
		{
			"name":        "invite_portal_user",
			"description": "Invite un utilisateur Access par email (SMTP Admin requis).",
			"inputSchema": schema(
				req("email", "string", "Email de l'invité"),
				req("home_edge", "string", "Passerelle d'accueil"),
				opt("tags", "array", "Tags utilisateur"),
			),
		},
		{
			"name":        "update_portal_user",
			"description": "Met à jour tags, statut ou home_edge d'un utilisateur Access.",
			"inputSchema": schema(
				req("id", "string", "ID utilisateur Access"),
				opt("tags", "array", "Nouveaux tags"),
				opt("status", "string", "active, invited ou disabled"),
				opt("home_edge", "string", "Nouveau passerelle d'accueil"),
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
				opt("edge", "string", "Filtrer par passerelle"),
				opt("limit", "number", "Nombre d'entrées (défaut 100, max 500)"),
			),
		},
		{
			"name":        "list_portal_sessions",
			"description": "Liste les connexions Access en cours sur une passerelle (SSH et web), remontées en direct.",
			"inputSchema": schema(req("edge", "string", "Nom de la passerelle")),
		},
		{
			"name":        "terminate_portal_session",
			"description": "Termine une connexion Access en cours (l'id vient de list_portal_sessions).",
			"inputSchema": schema(
				req("edge", "string", "Nom de la passerelle"),
				req("id", "string", "ID de la connexion"),
			),
		},
		{
			"name":        "list_portal_access_requests",
			"description": "Liste les demandes d'accès temporaire Access d'une passerelle (en attente, accordées, refusées…).",
			"inputSchema": schema(
				req("edge", "string", "Nom de la passerelle"),
				opt("status", "string", "pending, approved, denied ou revoked"),
			),
		},
		{
			"name":        "decide_portal_access_request",
			"description": "Approuve, refuse ou révoque une demande d'accès temporaire Access.",
			"inputSchema": schema(
				req("id", "string", "ID de la demande"),
				req("decision", "string", "approve, deny ou revoke"),
				opt("duration_min", "number", "Durée accordée en minutes (approve ; défaut = durée demandée, max 1440)"),
			),
		},
		{
			"name":        "get_portal_policy",
			"description": "Retourne la politique d'accès Access d'une passerelle (plages horaires, IP autorisées, inactivité).",
			"inputSchema": schema(req("edge", "string", "Nom de la passerelle")),
		},
		{
			"name":        "set_portal_policy",
			"description": "Remplace la politique d'accès Access d'une passerelle. Les champs absents reviennent à leur valeur par défaut (pas de restriction).",
			"inputSchema": schema(
				req("edge", "string", "Nom de la passerelle"),
				opt("hours_enabled", "boolean", "Limiter les accès à des horaires"),
				opt("days", "array", "Jours autorisés, 0 = dimanche à 6 = samedi"),
				opt("start_time", "string", "Début HH:MM"),
				opt("end_time", "string", "Fin HH:MM (après le début)"),
				opt("timezone", "string", "Fuseau IANA, ex. Europe/Paris"),
				opt("ip_allow", "array", "IP ou CIDR autorisés ; vide = tous"),
				opt("idle_timeout_min", "number", "Fermeture après N minutes sans saisie ; 0 = jamais"),
				opt("record_sessions", "boolean", "Enregistrer la sortie des terminaux (rejeu dans l'admin)"),
				opt("record_retention_days", "number", "Jours de conservation des enregistrements ; 0 = illimitée"),
			),
		},
		{
			"name":        "list_portal_recordings",
			"description": "Liste les enregistrements de sessions Access d'une passerelle (métadonnées ; le rejeu se fait dans l'interface ou avec la CLI).",
			"inputSchema": schema(req("edge", "string", "Nom de la passerelle")),
		},
		{
			"name":        "delete_portal_recording",
			"description": "Supprime définitivement un enregistrement de session Access.",
			"inputSchema": schema(
				req("edge", "string", "Nom de la passerelle"),
				req("id", "string", "ID de l'enregistrement"),
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
			"description": "Pousse tous les templates HTML Access vers les passerelles.",
			"inputSchema": schema(),
		},
	}
}

func (h *Handler) toolGetPortalConfig(r *http.Request, args map[string]any) (any, error) {
	edge := argStr(args, "edge")
	if edge == "" {
		return nil, fmt.Errorf("edge requis")
	}
	return h.callPortal(r, http.MethodGet, "/api/v1/portal?edge="+url.QueryEscape(edge), nil)
}

func (h *Handler) toolUpdatePortalConfig(r *http.Request, args map[string]any) (any, error) {
	edge := argStr(args, "edge")
	if edge == "" {
		return nil, fmt.Errorf("edge requis")
	}
	raw, err := h.callPortal(r, http.MethodGet, "/api/v1/portal?edge="+url.QueryEscape(edge), nil)
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
	if _, ok := args["ha_session_mode"]; ok {
		cfgMap["ha_session_mode"] = argStr(args, "ha_session_mode")
	}
	return h.callPortal(r, http.MethodPut, "/api/v1/portal?edge="+url.QueryEscape(edge), cfgMap)
}

func (h *Handler) toolPushPortal(r *http.Request, args map[string]any) (any, error) {
	edge := argStr(args, "edge")
	if edge == "" {
		return nil, fmt.Errorf("edge requis")
	}
	return h.callPortal(r, http.MethodPost, "/api/v1/portal/push?edge="+url.QueryEscape(edge), map[string]any{})
}

func (h *Handler) toolListPortalDestinations(r *http.Request, args map[string]any) (any, error) {
	path := "/api/v1/portal/destinations"
	if edge := argStr(args, "edge"); edge != "" {
		path += "?edge=" + url.QueryEscape(edge)
	}
	return h.callPortal(r, http.MethodGet, path, nil)
}

func (h *Handler) toolCreatePortalDestination(r *http.Request, args map[string]any) (any, error) {
	body := map[string]any{
		"edge_name":  argStr(args, "edge_name"),
		"name":       argStr(args, "name"),
		"kind":       argStr(args, "kind"),
		"host":       argStr(args, "host"),
		"port":       argInt(args, "port", 22),
		"agent_name": argStr(args, "agent_name"),
		"container":  argStr(args, "container"),
		"tags":       argStringSlice(args, "tags"),
	}
	if body["edge_name"] == "" || body["name"] == "" || body["kind"] == "" {
		return nil, fmt.Errorf("edge_name, name et kind requis")
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
		"edge_name":  argStr(args, "edge_name"),
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
	edge := argStr(args, "edge")
	if edge == "" {
		return nil, fmt.Errorf("edge requis")
	}
	q := url.Values{}
	q.Set("edge", edge)
	if tags := argStr(args, "tags"); tags != "" {
		q.Set("tags", tags)
	} else if sl := argStringSlice(args, "tags"); len(sl) > 0 {
		q.Set("tags", strings.Join(sl, ","))
	}
	return h.callPortal(r, http.MethodGet, "/api/v1/portal/destinations/preview?"+q.Encode(), nil)
}

func (h *Handler) toolListPortalUsers(r *http.Request, args map[string]any) (any, error) {
	path := "/api/v1/portal/users"
	if edge := argStr(args, "edge"); edge != "" {
		path += "?edge=" + url.QueryEscape(edge)
	}
	return h.callPortal(r, http.MethodGet, path, nil)
}

func (h *Handler) toolInvitePortalUser(r *http.Request, args map[string]any) (any, error) {
	email := argStr(args, "email")
	home := argStr(args, "home_edge")
	if email == "" || home == "" {
		return nil, fmt.Errorf("email et home_edge requis")
	}
	body := map[string]any{
		"email":     email,
		"home_edge": home,
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
	if s := argStr(args, "home_edge"); s != "" {
		body["home_edge"] = s
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
	if edge := argStr(args, "edge"); edge != "" {
		q.Set("edge", edge)
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

func (h *Handler) toolListPortalSessions(r *http.Request, args map[string]any) (any, error) {
	edge := argStr(args, "edge")
	if edge == "" {
		return nil, fmt.Errorf("edge requis")
	}
	return h.callPortal(r, http.MethodGet, "/api/v1/portal/sessions?edge="+url.QueryEscape(edge), nil)
}

func (h *Handler) toolTerminatePortalSession(r *http.Request, args map[string]any) (any, error) {
	edge, id := argStr(args, "edge"), argStr(args, "id")
	if edge == "" || id == "" {
		return nil, fmt.Errorf("edge et id requis")
	}
	return h.callPortal(r, http.MethodDelete, "/api/v1/portal/sessions/"+url.PathEscape(id)+"?edge="+url.QueryEscape(edge), nil)
}

func (h *Handler) toolListPortalAccessRequests(r *http.Request, args map[string]any) (any, error) {
	edge := argStr(args, "edge")
	if edge == "" {
		return nil, fmt.Errorf("edge requis")
	}
	q := url.Values{"edge": {edge}}
	if st := argStr(args, "status"); st != "" {
		q.Set("status", st)
	}
	return h.callPortal(r, http.MethodGet, "/api/v1/portal/access-requests?"+q.Encode(), nil)
}

func (h *Handler) toolDecidePortalAccessRequest(r *http.Request, args map[string]any) (any, error) {
	id, decision := argStr(args, "id"), argStr(args, "decision")
	if id == "" {
		return nil, fmt.Errorf("id requis")
	}
	if decision != "approve" && decision != "deny" && decision != "revoke" {
		return nil, fmt.Errorf("decision doit être approve, deny ou revoke")
	}
	body := map[string]any{}
	if _, ok := args["duration_min"]; ok {
		body["duration_min"] = argInt(args, "duration_min", 0)
	}
	return h.callPortal(r, http.MethodPost, "/api/v1/portal/access-requests/"+url.PathEscape(id)+"/"+decision, body)
}

func (h *Handler) toolGetPortalPolicy(r *http.Request, args map[string]any) (any, error) {
	edge := argStr(args, "edge")
	if edge == "" {
		return nil, fmt.Errorf("edge requis")
	}
	return h.callPortal(r, http.MethodGet, "/api/v1/portal/policy?edge="+url.QueryEscape(edge), nil)
}

func (h *Handler) toolSetPortalPolicy(r *http.Request, args map[string]any) (any, error) {
	edge := argStr(args, "edge")
	if edge == "" {
		return nil, fmt.Errorf("edge requis")
	}
	body := map[string]any{}
	for _, k := range []string{"hours_enabled", "days", "start_time", "end_time", "timezone", "ip_allow", "idle_timeout_min", "record_sessions", "record_retention_days"} {
		if v, ok := args[k]; ok {
			body[k] = v
		}
	}
	return h.callPortal(r, http.MethodPut, "/api/v1/portal/policy?edge="+url.QueryEscape(edge), body)
}

func (h *Handler) toolListPortalRecordings(r *http.Request, args map[string]any) (any, error) {
	edge := argStr(args, "edge")
	if edge == "" {
		return nil, fmt.Errorf("edge requis")
	}
	return h.callPortal(r, http.MethodGet, "/api/v1/portal/recordings?edge="+url.QueryEscape(edge), nil)
}

func (h *Handler) toolDeletePortalRecording(r *http.Request, args map[string]any) (any, error) {
	edge, id := argStr(args, "edge"), argStr(args, "id")
	if edge == "" || id == "" {
		return nil, fmt.Errorf("edge et id requis")
	}
	return h.callPortal(r, http.MethodDelete, "/api/v1/portal/recordings/"+url.PathEscape(id)+"?edge="+url.QueryEscape(edge), nil)
}
