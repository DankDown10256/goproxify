// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/core/router"
)

// RoutePusher est implémenté par corews.Manager / corepush.Pusher.
type RoutePusher interface {
	PushRoutes(ctx context.Context)
	DeleteRoute(ctx context.Context, id string)
}

// errorPagesPusher optionnel : push templates avant les routes pour éviter une course.
type errorPagesPusher interface {
	PushErrorPages(ctx context.Context)
}

// ProxyVersioner enregistre une version de config proxy dans l'historique.
type ProxyVersioner interface {
	SaveProxyVersion(db *sql.DB, proxyID, configJSON, note string)
}

// ProxiesHandler gère le CRUD HTTP des proxies (routes).
type ProxiesHandler struct {
	DB        *sql.DB
	Log       *slog.Logger
	Pusher    RoutePusher
	Versioner ProxyVersioner
}

func (h *ProxiesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Extrait l'éventuel {id} après /api/v1/proxies/
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/proxies")
	path = strings.TrimPrefix(path, "/")
	id := strings.Split(path, "/")[0]

	switch {
	case r.Method == http.MethodGet && id == "":
		h.list(w, r)
	case r.Method == http.MethodPost && id == "":
		h.create(w, r)
	case r.Method == http.MethodGet && id != "":
		h.get(w, r, id)
	case r.Method == http.MethodPut && id != "":
		h.update(w, r, id)
	case r.Method == http.MethodPatch && id != "":
		h.patch(w, r, id)
	case r.Method == http.MethodDelete && id != "":
		h.delete(w, r, id)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

type proxyRow struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Config    json.RawMessage `json:"config"`
	Enabled   bool            `json:"enabled"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

func (h *ProxiesHandler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, name, config, enabled, created_at, updated_at FROM proxies ORDER BY created_at DESC`)
	if err != nil {
		h.Log.Error("proxies: list", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()

	userID := auth.UserIDFromContext(r.Context())

	// Filtre optionnel par périmètre token Core (?core=uuid|node_name).
	coreRef := r.URL.Query().Get("core")
	var coreAccess rbac.CoreAccess
	filterByCore := coreRef != ""
	if filterByCore {
		coreAccess = rbac.ResolveCoreAccess(r.Context(), h.DB, coreRef)
		if coreAccess.TokenID == "" {
			// Core inconnu : aucune route (évite de tout exposer par erreur).
			coreAccess.Role = "viewer"
		}
	}

	result := make([]proxyRow, 0)
	for rows.Next() {
		var p proxyRow
		var cfgJSON string
		var enabled int
		if err := rows.Scan(&p.ID, &p.Name, &cfgJSON, &enabled, &p.CreatedAt, &p.UpdatedAt); err != nil {
			continue
		}
		p.Config = json.RawMessage(cfgJSON)
		p.Enabled = enabled == 1
		var route router.Route
		_ = json.Unmarshal([]byte(cfgJSON), &route)
		route.ID = p.ID
		if !rbac.CanReadProxy(r.Context(), h.DB, userID, &route) {
			continue
		}
		if filterByCore && !rbac.RouteAllowedByToken(coreAccess.Role, coreAccess.Scopes, &route) {
			continue
		}
		result = append(result, p)
	}
	jsonOK(w, result)
}

// proxyBody est la structure attendue pour les requêtes POST/PUT sur /proxies.
// Le champ Config préserve intégralement le JSON envoyé par le frontend
// (sans round-trip destructif via router.Route).
type proxyBody struct {
	Config  json.RawMessage `json:"config"`
	Enabled *bool           `json:"enabled,omitempty"`
}

func (h *ProxiesHandler) create(w http.ResponseWriter, r *http.Request) {
	var body proxyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Config) == 0 {
		writeErr(w, r, http.StatusBadRequest, "api.err.json_body")
		return
	}

	// Parse minimal fields pour RBAC et génération de l'ID.
	var route router.Route
	_ = json.Unmarshal(body.Config, &route)
	route.ID = uuid.New().String()
	route.UpdatedAt = time.Now()

	userID := auth.UserIDFromContext(r.Context())
	if !rbac.CanWriteProxy(r.Context(), h.DB, userID, &route) {
		writeErr(w, r, http.StatusForbidden, "api.err.out_of_scope_domain")
		return
	}

	// Inject les champs générés côté serveur dans le JSON brut pour préserver
	// tous les champs extra (http_version, aliases, tls_mode, health_check…).
	cfgJSON, _ := injectRouteFields(body.Config, route.ID, route.UpdatedAt)

	enabled := 1
	if body.Enabled != nil && !*body.Enabled {
		enabled = 0
	}

	_, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO proxies (id, name, config, enabled) VALUES (?, ?, ?, ?)`,
		route.ID, route.Host, cfgJSON, enabled,
	)
	if err != nil {
		h.Log.Error("proxies: create", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	actor := auth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "create", "proxy:"+route.ID, route.Host)

	if h.Versioner != nil {
		h.Versioner.SaveProxyVersion(h.DB, route.ID, cfgJSON, "création")
	}
	if h.Pusher != nil {
		go h.pushProxyConfig(context.Background())
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(proxyRow{
		ID:     route.ID,
		Name:   route.Host,
		Config: json.RawMessage(cfgJSON),
	})
}

func (h *ProxiesHandler) get(w http.ResponseWriter, r *http.Request, id string) {
	p, err := h.loadProxy(r, id)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.proxy_not_found")
		return
	}
	if err != nil {
		h.Log.Error("proxies: get", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	userID := auth.UserIDFromContext(r.Context())
	var routeForRBAC router.Route
	_ = json.Unmarshal(p.Config, &routeForRBAC)
	if !rbac.CanReadProxy(r.Context(), h.DB, userID, &routeForRBAC) {
		writeErr(w, r, http.StatusNotFound, "api.err.proxy_not_found")
		return
	}
	jsonOK(w, p)
}

func (h *ProxiesHandler) update(w http.ResponseWriter, r *http.Request, id string) {
	var body proxyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Config) == 0 {
		writeErr(w, r, http.StatusBadRequest, "api.err.json_body")
		return
	}

	var route router.Route
	_ = json.Unmarshal(body.Config, &route)
	route.ID = id
	route.UpdatedAt = time.Now()

	userID := auth.UserIDFromContext(r.Context())
	if !rbac.CanWriteProxy(r.Context(), h.DB, userID, &route) {
		writeErr(w, r, http.StatusForbidden, "api.err.out_of_scope")
		return
	}

	cfgJSON, _ := injectRouteFields(body.Config, id, route.UpdatedAt)

	var res sql.Result
	var err error
	if body.Enabled != nil {
		res, err = h.DB.ExecContext(r.Context(),
			`UPDATE proxies SET name=?, config=?, enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
			route.Host, cfgJSON, boolToInt(*body.Enabled), id,
		)
	} else {
		res, err = h.DB.ExecContext(r.Context(),
			`UPDATE proxies SET name=?, config=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
			route.Host, cfgJSON, id,
		)
	}
	if err != nil {
		h.Log.Error("proxies: update", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.proxy_not_found")
		return
	}

	actor := auth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "update", "proxy:"+id, route.Host)

	if h.Versioner != nil {
		h.Versioner.SaveProxyVersion(h.DB, id, cfgJSON, "modification")
	}
	if h.Pusher != nil {
		go h.pushProxyConfig(context.Background())
	}

	jsonOK(w, proxyRow{
		ID:     id,
		Name:   route.Host,
		Config: json.RawMessage(cfgJSON),
	})
}

func (h *ProxiesHandler) patch(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Enabled == nil {
		http.Error(w, "corps JSON invalide : champ enabled requis", http.StatusBadRequest)
		return
	}
	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE proxies SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		boolToInt(*body.Enabled), id,
	)
	if err != nil {
		h.Log.Error("proxies: patch", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.proxy_not_found")
		return
	}
	actor := auth.UserIDFromContext(r.Context())
	state := "désactivé"
	if *body.Enabled {
		state = "activé"
	}
	_ = admindb.WriteAudit(h.DB, actor, "patch", "proxy:"+id, state)
	if h.Pusher != nil {
		go h.pushProxyConfig(context.Background())
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *ProxiesHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	existing, err := h.loadProxy(r, id)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.proxy_not_found")
		return
	}
	if err != nil {
		h.Log.Error("proxies: delete load", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	userID := auth.UserIDFromContext(r.Context())
	var existingRoute router.Route
	_ = json.Unmarshal(existing.Config, &existingRoute)
	if !rbac.CanDeleteProxy(r.Context(), h.DB, userID, &existingRoute) {
		writeErr(w, r, http.StatusForbidden, "api.err.delete_admin")
		return
	}

	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM proxies WHERE id=?`, id)
	if err != nil {
		h.Log.Error("proxies: delete", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.proxy_not_found")
		return
	}

	actor := auth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "delete", "proxy:"+id, "")

	if h.Pusher != nil {
		go h.Pusher.DeleteRoute(context.Background(), id)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *ProxiesHandler) loadProxy(r *http.Request, id string) (*proxyRow, error) {
	var p proxyRow
	var cfgJSON string
	var enabled int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, name, config, enabled, created_at, updated_at FROM proxies WHERE id=?`, id,
	).Scan(&p.ID, &p.Name, &cfgJSON, &enabled, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	p.Config = json.RawMessage(cfgJSON)
	p.Enabled = enabled == 1
	return &p, nil
}

// pushProxyConfig pousse d'abord les pages d'erreur (si disponible), puis les routes.
// Évite qu'un Core applique un template_id avant d'avoir reçu le HTML.
func (h *ProxiesHandler) pushProxyConfig(ctx context.Context) {
	if ep, ok := h.Pusher.(errorPagesPusher); ok {
		ep.PushErrorPages(ctx)
	}
	h.Pusher.PushRoutes(ctx)
}

// injectRouteFields injecte id et updated_at dans le JSON brut de la config
// sans perdre les champs extra non connus de router.Route.
func injectRouteFields(raw json.RawMessage, id string, updatedAt time.Time) (string, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return string(raw), err
	}
	m["id"] = id
	m["updated_at"] = updatedAt
	b, err := json.Marshal(m)
	return string(b), err
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// jsonOK sérialise la valeur en JSON avec status 200.
func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// isCtxErr retourne true si l'erreur est due à une annulation de contexte (arrêt propre).
// À utiliser avant de loguer en ERROR pour éviter le bruit lors des redémarrages Docker.
func isCtxErr(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
