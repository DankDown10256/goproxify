// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
)

// extraTools retourne les définitions des outils supplémentaires.
func extraTools() []map[string]any {
	return []map[string]any{
		// Alert channels
		{
			"name":        "list_alert_channels",
			"description": "Liste les canaux de notification configurés (email, webhook, Slack, ntfy, Gotify…).",
			"inputSchema": schema(),
		},
		{
			"name":        "create_alert_channel",
			"description": "Crée un canal de notification. Retourne l'ID créé.",
			"inputSchema": schema(
				req("name", "string", "Nom unique du canal"),
				req("type", "string", "Type : email, webhook, slack, ntfy, gotify, jira, linear, github, gitlab, zammad, glpi"),
				req("config", "object", "Configuration spécifique au type (url, token, destinataires…)"),
				opt("enabled", "boolean", "Activer immédiatement (défaut: true)"),
			),
		},
		{
			"name":        "delete_alert_channel",
			"description": "Supprime un canal de notification par son ID.",
			"inputSchema": schema(req("id", "string", "ID du canal à supprimer")),
		},
		// Alert rules
		{
			"name":        "list_alert_rules",
			"description": "Liste les règles d'alerte avec leurs déclencheurs, canaux et priorité.",
			"inputSchema": schema(),
		},
		{
			"name":        "create_alert_rule",
			"description": "Crée une règle d'alerte. Retourne l'ID créé.",
			"inputSchema": schema(
				req("name", "string", "Nom de la règle"),
				req("triggers", "array", "Déclencheurs JSON (ex: [{\"type\":\"error_rate\",\"threshold\":0.05}])"),
				req("channels", "array", "IDs des canaux destinataires"),
				opt("scope", "object", "Filtre de périmètre (proxy, domain…)"),
				opt("cooldown_sec", "number", "Délai minimal entre deux alertes en secondes (défaut: 300)"),
				opt("priority", "number", "Priorité (0 = normale, plus élevé = plus urgent)"),
				opt("enabled", "boolean", "Activer immédiatement (défaut: true)"),
			),
		},
		{
			"name":        "delete_alert_rule",
			"description": "Supprime une règle d'alerte par son ID.",
			"inputSchema": schema(req("id", "string", "ID de la règle à supprimer")),
		},
		// Auth providers
		{
			"name":        "list_auth_providers",
			"description": "Liste les fournisseurs d'authentification SSO (OIDC, SAML, LDAP…).",
			"inputSchema": schema(),
		},
		{
			"name":        "create_auth_provider",
			"description": "Crée un fournisseur SSO. Retourne l'ID créé.",
			"inputSchema": schema(
				req("name", "string", "Nom unique du fournisseur"),
				req("provider", "string", "Type : oidc, saml, ldap, github, google, azure"),
				req("config", "object", "Configuration (client_id, client_secret, issuer, etc.)"),
				opt("enabled", "boolean", "Activer immédiatement (défaut: true)"),
			),
		},
		{
			"name":        "delete_auth_provider",
			"description": "Supprime un fournisseur SSO par son ID.",
			"inputSchema": schema(req("id", "string", "ID du fournisseur à supprimer")),
		},
		// IP profiles
		{
			"name":        "list_ip_profiles",
			"description": "Liste les profils IP (listes blanches/noires, GeoIP, feeds de réputation).",
			"inputSchema": schema(),
		},
		{
			"name":        "create_ip_profile",
			"description": "Crée un profil IP de filtrage. Retourne l'ID créé.",
			"inputSchema": schema(
				req("name", "string", "Nom unique du profil"),
				req("mode", "string", "Action : deny (blocage) ou allow (liste blanche)"),
				opt("profile_type", "string", "Type : custom (défaut), crowdsec, abuseipdb, firehol"),
				opt("cidrs", "array", "Liste de CIDRs statiques (ex: [\"1.2.3.0/24\"])"),
				opt("feed_urls", "array", "URLs de feeds IP à synchroniser"),
				opt("feed_format", "string", "Format des feeds : plain (défaut), cidr, json"),
				opt("refresh_interval_h", "number", "Intervalle de rafraîchissement en heures (défaut: 24)"),
				opt("enabled", "boolean", "Activer immédiatement (défaut: true)"),
			),
		},
		{
			"name":        "delete_ip_profile",
			"description": "Supprime un profil IP par son ID.",
			"inputSchema": schema(req("id", "string", "ID du profil à supprimer")),
		},
		// Snippet mutations
		{
			"name":        "create_snippet",
			"description": "Crée un snippet middleware réutilisable. Retourne l'ID créé.",
			"inputSchema": schema(
				req("name", "string", "Nom unique du snippet"),
				req("type", "string", "Type : waf, rate_limit, headers, auth, redirect, rewrite…"),
				req("config", "object", "Configuration spécifique au type"),
			),
		},
		{
			"name":        "delete_snippet",
			"description": "Supprime un snippet par son ID.",
			"inputSchema": schema(req("id", "string", "ID du snippet à supprimer")),
		},
		// Domain mutations
		{
			"name":        "create_domain",
			"description": "Déclare un domaine géré (déclenche le challenge ACME). Retourne l'ID créé.",
			"inputSchema": schema(
				req("domain", "string", "Nom de domaine (ex: app.example.com)"),
				opt("core_id", "string", "ID du Core cible (cluster multi-Core)"),
			),
		},
		{
			"name":        "renew_domain",
			"description": "Force le renouvellement du certificat ACME d'un domaine.",
			"inputSchema": schema(req("id", "string", "ID du domaine")),
		},
		// Cert mutations
		{
			"name":        "obtain_cert",
			"description": "Demande l'émission d'un certificat TLS pour un domaine (challenge ACME).",
			"inputSchema": schema(req("domain", "string", "Nom de domaine")),
		},
	}
}

func init() {
	tools = append(tools, extraTools()...)
}

// --- Implémentations --------------------------------------------------------

func (h *Handler) toolListAlertChannels(r *http.Request) (any, error) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, name, type, enabled, created_at FROM alert_channels ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, name, typ string
		var enabled int
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &typ, &enabled, &createdAt); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id": id, "name": name, "type": typ,
			"enabled": enabled == 1, "created_at": createdAt,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolCreateAlertChannel(r *http.Request, args map[string]any) (any, error) {
	name, _ := args["name"].(string)
	typ, _ := args["type"].(string)
	cfg := args["config"]
	if name == "" || typ == "" || cfg == nil {
		return nil, fmt.Errorf("name, type et config sont requis")
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("config invalide : %w", err)
	}
	enabled := 1
	if e, ok := args["enabled"].(bool); ok && !e {
		enabled = 0
	}
	id := uuid.New().String()
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO alert_channels (id, name, type, config, enabled) VALUES (?,?,?,?,?)`,
		id, name, typ, string(cfgJSON), enabled); err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "name": name, "type": typ}, nil
}

func (h *Handler) toolDeleteAlertChannel(ctx context.Context, id string) (any, error) {
	res, err := h.DB.ExecContext(ctx,
		`DELETE FROM alert_channels WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, fmt.Errorf("canal introuvable : %s", id)
	}
	return map[string]any{"deleted": id}, nil
}

func (h *Handler) toolListAlertRules(r *http.Request) (any, error) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, name, enabled, scope, triggers, channels, cooldown_sec, priority, created_at
		 FROM alert_rules ORDER BY priority, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, name, scope, triggers, channels string
		var enabled, cooldown, priority int
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &enabled, &scope, &triggers, &channels, &cooldown, &priority, &createdAt); err != nil {
			continue
		}
		var scopeObj, triggersObj, channelsObj any
		json.Unmarshal([]byte(scope), &scopeObj)       //nolint:errcheck
		json.Unmarshal([]byte(triggers), &triggersObj) //nolint:errcheck
		json.Unmarshal([]byte(channels), &channelsObj) //nolint:errcheck
		out = append(out, map[string]any{
			"id": id, "name": name, "enabled": enabled == 1,
			"scope": scopeObj, "triggers": triggersObj, "channels": channelsObj,
			"cooldown_sec": cooldown, "priority": priority, "created_at": createdAt,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolCreateAlertRule(r *http.Request, args map[string]any) (any, error) {
	name, _ := args["name"].(string)
	if name == "" {
		return nil, fmt.Errorf("name est requis")
	}
	triggersJSON := "[]"
	if t := args["triggers"]; t != nil {
		b, _ := json.Marshal(t)
		triggersJSON = string(b)
	}
	channelsJSON := "[]"
	if c := args["channels"]; c != nil {
		b, _ := json.Marshal(c)
		channelsJSON = string(b)
	}
	scopeJSON := "{}"
	if s := args["scope"]; s != nil {
		b, _ := json.Marshal(s)
		scopeJSON = string(b)
	}
	cooldown := 300
	if v, ok := args["cooldown_sec"].(float64); ok && v > 0 {
		cooldown = int(v)
	}
	priority := 0
	if v, ok := args["priority"].(float64); ok {
		priority = int(v)
	}
	enabled := 1
	if e, ok := args["enabled"].(bool); ok && !e {
		enabled = 0
	}
	id := uuid.New().String()
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO alert_rules (id, name, scope, triggers, channels, cooldown_sec, priority, enabled)
		 VALUES (?,?,?,?,?,?,?,?)`,
		id, name, scopeJSON, triggersJSON, channelsJSON, cooldown, priority, enabled); err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "name": name}, nil
}

func (h *Handler) toolDeleteAlertRule(ctx context.Context, id string) (any, error) {
	res, err := h.DB.ExecContext(ctx, `DELETE FROM alert_rules WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, fmt.Errorf("règle introuvable : %s", id)
	}
	return map[string]any{"deleted": id}, nil
}

func (h *Handler) toolListAuthProviders(r *http.Request) (any, error) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, name, provider, enabled, created_at FROM auth_providers ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, name, provider string
		var enabled int
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &provider, &enabled, &createdAt); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"id": id, "name": name, "provider": provider,
			"enabled": enabled == 1, "created_at": createdAt,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolCreateAuthProvider(r *http.Request, args map[string]any) (any, error) {
	name, _ := args["name"].(string)
	provider, _ := args["provider"].(string)
	cfg := args["config"]
	if name == "" || provider == "" || cfg == nil {
		return nil, fmt.Errorf("name, provider et config sont requis")
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("config invalide : %w", err)
	}
	enabled := 1
	if e, ok := args["enabled"].(bool); ok && !e {
		enabled = 0
	}
	id := uuid.New().String()
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO auth_providers (id, name, provider, config, enabled) VALUES (?,?,?,?,?)`,
		id, name, provider, string(cfgJSON), enabled); err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "name": name, "provider": provider}, nil
}

func (h *Handler) toolDeleteAuthProvider(ctx context.Context, id string) (any, error) {
	res, err := h.DB.ExecContext(ctx, `DELETE FROM auth_providers WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, fmt.Errorf("fournisseur introuvable : %s", id)
	}
	return map[string]any{"deleted": id}, nil
}

func (h *Handler) toolListIPProfiles(r *http.Request) (any, error) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, name, profile_type, mode, cidrs, feed_urls, enabled, last_updated_at, created_at,
		        last_error, consecutive_failures, COALESCE(next_attempt_at, '')
		 FROM ip_profiles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, name, profileType, mode, cidrs, feedURLs, lastError, nextAttempt string
		var failures int
		var enabled int
		var lastUpdated *time.Time
		var createdAt time.Time
		if err := rows.Scan(&id, &name, &profileType, &mode, &cidrs, &feedURLs, &enabled, &lastUpdated, &createdAt, &lastError, &failures, &nextAttempt); err != nil {
			continue
		}
		var cidrsObj, feedsObj any
		json.Unmarshal([]byte(cidrs), &cidrsObj)    //nolint:errcheck
		json.Unmarshal([]byte(feedURLs), &feedsObj) //nolint:errcheck
		out = append(out, map[string]any{
			"id": id, "name": name, "profile_type": profileType, "mode": mode,
			"cidrs": cidrsObj, "feed_urls": feedsObj,
			"enabled": enabled == 1, "last_updated_at": lastUpdated, "created_at": createdAt,
			"last_error": lastError, "consecutive_failures": failures, "next_attempt_at": nextAttempt,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, nil
}

func (h *Handler) toolCreateIPProfile(r *http.Request, args map[string]any) (any, error) {
	name, _ := args["name"].(string)
	mode, _ := args["mode"].(string)
	if name == "" || mode == "" {
		return nil, fmt.Errorf("name et mode sont requis")
	}
	profileType := "custom"
	if v, _ := args["profile_type"].(string); v != "" {
		profileType = v
	}
	cidrsJSON := "[]"
	if c := args["cidrs"]; c != nil {
		b, _ := json.Marshal(c)
		cidrsJSON = string(b)
	}
	feedURLsJSON := "[]"
	if f := args["feed_urls"]; f != nil {
		b, _ := json.Marshal(f)
		feedURLsJSON = string(b)
	}
	feedFormat := "plain"
	if v, _ := args["feed_format"].(string); v != "" {
		feedFormat = v
	}
	refreshH := 24
	if v, ok := args["refresh_interval_h"].(float64); ok && v > 0 {
		refreshH = int(v)
	}
	enabled := 1
	if e, ok := args["enabled"].(bool); ok && !e {
		enabled = 0
	}
	id := uuid.New().String()
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO ip_profiles
		 (id, name, profile_type, mode, cidrs, feed_urls, feed_format, refresh_interval_h, enabled)
		 VALUES (?,?,?,?,?,?,?,?,?)`,
		id, name, profileType, mode, cidrsJSON, feedURLsJSON, feedFormat, refreshH, enabled); err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "name": name, "mode": mode, "profile_type": profileType}, nil
}

func (h *Handler) toolDeleteIPProfile(ctx context.Context, id string) (any, error) {
	res, err := h.DB.ExecContext(ctx, `DELETE FROM ip_profiles WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, fmt.Errorf("profil introuvable : %s", id)
	}
	return map[string]any{"deleted": id}, nil
}

func (h *Handler) toolCreateSnippet(r *http.Request, args map[string]any) (any, error) {
	name, _ := args["name"].(string)
	typ, _ := args["type"].(string)
	cfg := args["config"]
	if name == "" || typ == "" || cfg == nil {
		return nil, fmt.Errorf("name, type et config sont requis")
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("config invalide : %w", err)
	}
	id := uuid.New().String()
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO snippets (id, name, type, config) VALUES (?,?,?,?)`,
		id, name, typ, string(cfgJSON)); err != nil {
		return nil, err
	}
	return map[string]any{"id": id, "name": name, "type": typ}, nil
}

func (h *Handler) toolDeleteSnippet(ctx context.Context, id string) (any, error) {
	res, err := h.DB.ExecContext(ctx, `DELETE FROM snippets WHERE id = ?`, id)
	if err != nil {
		return nil, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return nil, fmt.Errorf("snippet introuvable : %s", id)
	}
	return map[string]any{"deleted": id}, nil
}

func (h *Handler) toolCreateDomain(r *http.Request, args map[string]any) (any, error) {
	domain, _ := args["domain"].(string)
	if domain == "" {
		return nil, fmt.Errorf("domain est requis")
	}
	coreID, _ := args["core_id"].(string)
	id := uuid.New().String()
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO domains (id, domain, core_id, dns_provider, cert_method, delegation_mode)
		 VALUES (?,?,?,?,?,?)`,
		id, domain, coreID, "", "acme", "auto"); err != nil {
		return nil, err
	}
	if h.Pusher != nil {
		h.Pusher.PushRoutes(r.Context())
	}
	return map[string]any{"id": id, "domain": domain}, nil
}

func (h *Handler) toolRenewDomain(r *http.Request, id string) (any, error) {
	var domain string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain FROM domains WHERE id = ?`, id).Scan(&domain); err != nil {
		return nil, fmt.Errorf("domaine introuvable : %s", id)
	}
	// Marquer pour renouvellement forcé en vidant la date d'expiration du cert.
	if _, err := h.DB.ExecContext(r.Context(),
		`UPDATE domains SET cert_expires_at = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, id); err != nil {
		return nil, err
	}
	if h.Pusher != nil {
		h.Pusher.PushRoutes(r.Context())
	}
	return map[string]any{"id": id, "domain": domain, "status": "renew_requested"}, nil
}

func (h *Handler) toolObtainCert(r *http.Request, domain string) (any, error) {
	if domain == "" {
		return nil, fmt.Errorf("domain est requis")
	}
	// Vérifie que le domaine existe, sinon le crée.
	var id string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id FROM domains WHERE domain = ?`, domain).Scan(&id)
	if err != nil {
		id = uuid.New().String()
		if _, err := h.DB.ExecContext(r.Context(),
			`INSERT INTO domains (id, domain, core_id, dns_provider, cert_method, delegation_mode)
			 VALUES (?,?,?,?,?,?)`,
			id, domain, "", "", "acme", "auto"); err != nil {
			return nil, err
		}
	}
	if h.Pusher != nil {
		h.Pusher.PushRoutes(r.Context())
	}
	return map[string]any{"domain": domain, "status": "cert_requested"}, nil
}
