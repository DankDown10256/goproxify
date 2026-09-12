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
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/coreproxy"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/core/proxystore"
	"github.com/vincamok/goproxify/internal/core/router"
)

// listFiles lists production proxies from connected Cores (dedup by id).
func (h *ProxiesHandler) listFiles(w http.ResponseWriter, r *http.Request) {
	targets, err := coreproxy.ListTargets(r.Context(), h.DB)
	if err != nil {
		h.Log.Error("proxies/files: targets", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if len(targets) == 0 {
		jsonOK(w, []proxyRow{})
		return
	}

	client := coreproxy.NewClient()
	byID := map[string]proxyRow{}
	userID := auth.UserIDFromContext(r.Context())
	coreRef := r.URL.Query().Get("core")
	var coreAccess rbac.CoreAccess
	filterByCore := coreRef != ""
	if filterByCore {
		coreAccess = rbac.ResolveCoreAccess(r.Context(), h.DB, coreRef)
		if coreAccess.TokenID == "" {
			coreAccess.Role = "viewer"
		}
	}

	listOK := 0
	var lastListErr error
	userRole := rbac.UserRole(r.Context(), h.DB, userID)
	userGrants, _ := rbac.UserEffectiveGrants(r.Context(), h.DB, userID)
	for _, t := range targets {
		if filterByCore && t.ID != coreRef && t.NodeName != coreRef {
			continue
		}
		res, err := client.List(r.Context(), t)
		if err != nil {
			lastListErr = err
			h.Log.Warn("proxies/files: list core", "core", t.NodeName, "err", err)
			continue
		}
		listOK++
		for _, env := range res.Production {
			row := envelopeToRow(env)
			var route router.Route
			_ = json.Unmarshal(row.Config, &route)
			route.ID = row.ID
			if route.Host == "" {
				route.Host = row.Name
			}
			if !rbac.CanReadProxyWithGrants(userRole, userGrants, &route) {
				continue
			}
			if filterByCore && !rbac.RouteAllowedByToken(coreAccess.Role, coreAccess.Scopes, &route) {
				continue
			}
			byID[row.ID] = row
		}
	}
	if listOK == 0 && lastListErr != nil {
		h.Log.Error("proxies/files: aucun Core n'a répondu au list", "err", lastListErr)
		h.writeCoreErr(w, r, lastListErr)
		return
	}

	result := make([]proxyRow, 0, len(byID))
	for _, p := range byID {
		result = append(result, p)
	}
	jsonOK(w, result)
}

func (h *ProxiesHandler) getFiles(w http.ResponseWriter, r *http.Request, id string) {
	env, err := h.fetchProd(r.Context(), id)
	if errors.Is(err, errNoCore) {
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.internal")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "api.err.proxy_not_found")
		return
	}
	row := envelopeToRow(env)
	userID := auth.UserIDFromContext(r.Context())
	var route router.Route
	_ = json.Unmarshal(row.Config, &route)
	if !rbac.CanReadProxy(r.Context(), h.DB, userID, &route) {
		writeErr(w, r, http.StatusNotFound, "api.err.proxy_not_found")
		return
	}
	jsonOK(w, row)
}

func (h *ProxiesHandler) createFiles(w http.ResponseWriter, r *http.Request) {
	var body proxyBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Config) == 0 {
		writeErr(w, r, http.StatusBadRequest, "api.err.json_body")
		return
	}
	var route router.Route
	_ = json.Unmarshal(body.Config, &route)
	route.ID = uuid.New().String()
	route.UpdatedAt = time.Now()
	userID := auth.UserIDFromContext(r.Context())
	if !rbac.CanWriteProxy(r.Context(), h.DB, userID, &route) {
		writeErr(w, r, http.StatusForbidden, "api.err.out_of_scope_domain")
		return
	}
	cfgJSON, _ := injectRouteFields(body.Config, route.ID, route.UpdatedAt)
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	prod, err := h.publishAll(r.Context(), route.ID, route.Host, enabled, json.RawMessage(cfgJSON), userID)
	if err != nil {
		h.writeCoreErr(w, r, err)
		return
	}
	_ = admindb.WriteAudit(h.DB, userID, "create", "proxy:"+route.ID, route.Host)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(envelopeToRow(prod))
}

func (h *ProxiesHandler) updateFiles(w http.ResponseWriter, r *http.Request, id string) {
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
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	} else if existing, err := h.fetchProd(r.Context(), id); err == nil {
		enabled = existing.Enabled
	}
	prod, err := h.publishAll(r.Context(), id, route.Host, enabled, json.RawMessage(cfgJSON), userID)
	if err != nil {
		h.writeCoreErr(w, r, err)
		return
	}
	_ = admindb.WriteAudit(h.DB, userID, "update", "proxy:"+id, route.Host)
	jsonOK(w, envelopeToRow(prod))
}

func (h *ProxiesHandler) patchFiles(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Enabled == nil {
		http.Error(w, "corps JSON invalide : champ enabled requis", http.StatusBadRequest)
		return
	}
	existing, err := h.fetchProd(r.Context(), id)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "api.err.proxy_not_found")
		return
	}
	userID := auth.UserIDFromContext(r.Context())
	var route router.Route
	_ = json.Unmarshal(existing.Config, &route)
	route.ID = id
	if !rbac.CanWriteProxy(r.Context(), h.DB, userID, &route) {
		writeErr(w, r, http.StatusForbidden, "api.err.out_of_scope")
		return
	}
	_, err = h.publishAll(r.Context(), id, existing.Host, *body.Enabled, existing.Config, userID)
	if err != nil {
		h.writeCoreErr(w, r, err)
		return
	}
	state := "désactivé"
	if *body.Enabled {
		state = "activé"
	}
	_ = admindb.WriteAudit(h.DB, userID, "patch", "proxy:"+id, state)
	w.WriteHeader(http.StatusNoContent)
}

func (h *ProxiesHandler) deleteFiles(w http.ResponseWriter, r *http.Request, id string) {
	existing, err := h.fetchProd(r.Context(), id)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "api.err.proxy_not_found")
		return
	}
	userID := auth.UserIDFromContext(r.Context())
	var route router.Route
	_ = json.Unmarshal(existing.Config, &route)
	if !rbac.CanDeleteProxy(r.Context(), h.DB, userID, &route) {
		writeErr(w, r, http.StatusForbidden, "api.err.delete_admin")
		return
	}
	targets, err := coreproxy.ListTargets(r.Context(), h.DB)
	if err != nil || len(targets) == 0 {
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.internal")
		return
	}
	client := coreproxy.NewClient()
	var lastErr error
	for _, t := range targets {
		if err := client.Delete(r.Context(), t, id); err != nil {
			lastErr = err
			h.Log.Warn("proxies/files: delete", "core", t.NodeName, "err", err)
		}
	}
	if lastErr != nil {
		h.writeCoreErr(w, r, lastErr)
		return
	}
	_ = admindb.WriteAudit(h.DB, userID, "delete", "proxy:"+id, "")
	w.WriteHeader(http.StatusNoContent)
}

// MigrateToCoreHandler POST /api/v1/proxies/migrate-to-core
// Publie chaque proxy SQLite vers les Cores (create→dry-run→promote), puis optionnellement vide SQLite.
type MigrateProxiesHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

func (h *MigrateProxiesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
		return
	}
	var opts struct {
		PurgeSQLite bool `json:"purge_sqlite"`
	}
	_ = json.NewDecoder(r.Body).Decode(&opts)

	targets, err := coreproxy.ListTargets(r.Context(), h.DB)
	if err != nil || len(targets) == 0 {
		http.Error(w, "aucun Core joignable", http.StatusServiceUnavailable)
		return
	}
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, name, config, enabled FROM proxies ORDER BY created_at`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type item struct {
		ID     string `json:"id"`
		Host   string `json:"host"`
		OK     bool   `json:"ok"`
		Error  string `json:"error,omitempty"`
	}
	client := coreproxy.NewClient()
	results := make([]item, 0)
	actor := auth.UserIDFromContext(r.Context())
	for rows.Next() {
		var id, name, cfg string
		var enabled int
		if rows.Scan(&id, &name, &cfg, &enabled) != nil {
			continue
		}
		it := item{ID: id, Host: name}
		var lastErr error
		var prod *proxystore.Envelope
		for _, t := range targets {
			prod, err = client.Publish(r.Context(), t, id, name, enabled == 1, json.RawMessage(cfg), actor)
			if err != nil {
				lastErr = err
				h.Log.Warn("migrate proxy", "id", id, "core", t.NodeName, "err", err)
				continue
			}
			lastErr = nil
			_ = prod
		}
		if lastErr != nil {
			it.Error = lastErr.Error()
		} else {
			it.OK = true
		}
		results = append(results, it)
	}

	purged := 0
	if opts.PurgeSQLite {
		okCount := 0
		for _, it := range results {
			if it.OK {
				okCount++
			}
		}
		if okCount == len(results) && len(results) > 0 {
			res, err := h.DB.ExecContext(r.Context(), `DELETE FROM proxies`)
			if err == nil {
				n, _ := res.RowsAffected()
				purged = int(n)
			}
		}
	}
	_ = admindb.WriteAudit(h.DB, actor, "migrate", "proxies", "to-core")
	jsonOK(w, map[string]any{
		"migrated":      results,
		"purged_sqlite": purged,
	})
}

var errNoCore = errors.New("no core")

func (h *ProxiesHandler) fetchProd(ctx context.Context, id string) (*proxystore.Envelope, error) {
	targets, err := coreproxy.ListTargets(ctx, h.DB)
	if err != nil || len(targets) == 0 {
		return nil, errNoCore
	}
	client := coreproxy.NewClient()
	var last error
	for _, t := range targets {
		env, err := client.Get(ctx, t, id)
		if err == nil {
			return env, nil
		}
		last = err
	}
	if last == nil {
		last = errNoCore
	}
	return nil, last
}

func (h *ProxiesHandler) publishAll(ctx context.Context, id, host string, enabled bool, config json.RawMessage, createdBy string) (*proxystore.Envelope, error) {
	targets, err := coreproxy.ListTargets(ctx, h.DB)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, errNoCore
	}
	client := coreproxy.NewClient()
	var prod *proxystore.Envelope
	var lastErr error
	ok := 0
	for _, t := range targets {
		p, err := client.Publish(ctx, t, id, host, enabled, config, createdBy)
		if err != nil {
			lastErr = err
			h.Log.Warn("proxies/files: publish", "core", t.NodeName, "err", err)
			continue
		}
		prod = p
		ok++
	}
	if ok == 0 {
		if lastErr == nil {
			lastErr = errNoCore
		}
		return nil, lastErr
	}
	return prod, nil
}

func (h *ProxiesHandler) writeCoreErr(w http.ResponseWriter, r *http.Request, err error) {
	var he *coreproxy.HTTPError
	if errors.As(err, &he) {
		if he.Status == http.StatusUnprocessableEntity {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(he.Status)
			_, _ = w.Write([]byte(he.Body))
			return
		}
		http.Error(w, he.Body, he.Status)
		return
	}
	if errors.Is(err, errNoCore) {
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.internal")
		return
	}
	h.Log.Error("proxies/files: core injoignable", "err", err)
	writeErr(w, r, http.StatusServiceUnavailable, "api.err.core_unreachable")
}

func envelopeToRow(env *proxystore.Envelope) proxyRow {
	if env == nil {
		return proxyRow{}
	}
	row := proxyRow{
		ID:      env.ID,
		Name:    env.Host,
		Config:  env.Config,
		Enabled: env.Enabled,
		UpdatedAt: env.UpdatedAt,
	}
	if env.CreatedAt != nil {
		row.CreatedAt = *env.CreatedAt
	}
	return row
}
