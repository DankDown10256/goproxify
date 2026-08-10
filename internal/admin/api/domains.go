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
	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// DomainCertObtainer déclenche l'obtention ACME avec un provider DNS dynamique.
type DomainCertObtainer interface {
	ObtainCertWithProvider(ctx context.Context, domain, dnsProviderType string, credentials map[string]any) error
}

// DomainRoutePusher déclenche la synchronisation des délégations, routes et certificats
// (les proxies couverts par un domaine délégué doivent être retirés du Core responsable).
type DomainRoutePusher interface {
	PushDelegations(ctx context.Context)
	PushRoutes(ctx context.Context)
	PushCerts(ctx context.Context)
}

type DomainsHandler struct {
	DB      *sql.DB
	Log     *slog.Logger
	Manager DomainCertObtainer
	Pusher  DomainRoutePusher
}

// domainRow : core_id = Core d'entrée (routage / délégation / ACME UI).
// Les droits de réception des routes et certificats viennent des token_scopes, pas de core_id.
type domainRow struct {
	ID                  string     `json:"id"`
	Domain              string     `json:"domain"`
	CoreID              string     `json:"core_id"` // UUID token Core d'entrée (routage), pas un droit
	DNSProvider         string     `json:"dns_provider"`
	DNSCredentials      any        `json:"dns_credentials,omitempty"`
	CertMethod          string     `json:"cert_method"`
	DelegatedToCoreID   string     `json:"delegated_to_core_id"`
	DelegatedEndpoint   string     `json:"delegated_endpoint"`
	DelegationMode      string     `json:"delegation_mode"`
	CertExpiresAt       *time.Time `json:"cert_expires_at"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type domainRequest struct {
	Domain              string `json:"domain"`
	CoreID              string `json:"core_id"` // Core d'entrée (routage) — ne confère pas de droits token
	DNSProvider         string `json:"dns_provider"`
	DNSCredentials      any    `json:"dns_credentials"`
	CertMethod          string `json:"cert_method"`
	DelegatedToCoreID   string `json:"delegated_to_core_id"`
	DelegatedEndpoint   string `json:"delegated_endpoint"`
	DelegationMode      string `json:"delegation_mode"`
}

// resolveCoreRef convertit un identifiant Core reçu depuis l'UI/API vers l'ID token UUID.
// Rétro-compatibilité: accepte aussi le node_name (ex: "core-dev").
// Ne crée pas de token fantôme : un token Core actif doit déjà exister (droits = token_scopes).
func (h *DomainsHandler) resolveCoreRef(ctx context.Context, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", nil
	}
	var id string
	// Préfère un match exact sur id, puis un token avec node_endpoint non vide.
	err := h.DB.QueryRowContext(ctx, `
		SELECT id
		FROM tokens
		WHERE role='core' AND revoked=0
		  AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
		  AND (id=? OR node_name=?)
		ORDER BY
		  CASE WHEN id=? THEN 0 ELSE 1 END,
		  CASE WHEN COALESCE(node_endpoint,'') != '' THEN 0 ELSE 1 END,
		  created_at DESC
		LIMIT 1`, ref, ref, ref).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("core introuvable (token Core actif requis): " + ref)
	}
	if err != nil {
		return "", err
	}
	return id, nil
}

// ensureDomainScopesForCores ajoute le périmètre domaine manquant sur les tokens
// Core d'entrée / délégué (no-op si admin global sans scopes).
func (h *DomainsHandler) ensureDomainScopesForCores(ctx context.Context, domain, entryCoreID, delegatedCoreID string) []string {
	var ensured []string
	seen := map[string]struct{}{}
	for _, tokenID := range []string{entryCoreID, delegatedCoreID} {
		tokenID = strings.TrimSpace(tokenID)
		if tokenID == "" {
			continue
		}
		if _, ok := seen[tokenID]; ok {
			continue
		}
		seen[tokenID] = struct{}{}
		val, added, err := rbac.EnsureDomainScope(ctx, h.DB, tokenID, domain)
		if err != nil {
			if h.Log != nil {
				h.Log.Warn("domains: ensure scope", "token", tokenID, "domain", domain, "err", err)
			}
			continue
		}
		if added && val != "" {
			ensured = append(ensured, val)
		}
	}
	return ensured
}

func (h *DomainsHandler) resyncAfterScopeEnsure(ensured []string, forceRoutes bool) {
	if h.Pusher == nil {
		return
	}
	if len(ensured) == 0 && !forceRoutes {
		return
	}
	go func() {
		ctx := context.Background()
		h.Pusher.PushRoutes(ctx)
		h.Pusher.PushDelegations(ctx)
		if len(ensured) > 0 {
			h.Pusher.PushCerts(ctx)
		}
	}()
}

func (h *DomainsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/domains")
	path = strings.TrimPrefix(path, "/")
	id := strings.Split(path, "/")[0]
	sub := ""
	if parts := strings.SplitN(path, "/", 2); len(parts) > 1 {
		sub = parts[1]
	}

	switch {
	case r.Method == http.MethodGet && id == "":
		h.list(w, r)
	case r.Method == http.MethodPost && id == "":
		h.create(w, r)
	case r.Method == http.MethodGet && id != "":
		h.get(w, r, id)
	case r.Method == http.MethodPut && id != "" && sub == "":
		h.update(w, r, id)
	case r.Method == http.MethodDelete && id != "" && sub == "":
		h.delete(w, r, id)
	case r.Method == http.MethodPost && id != "" && sub == "renew":
		h.renew(w, r, id)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func (h *DomainsHandler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT d.id, d.domain, d.core_id, d.dns_provider, d.dns_credentials,
		       d.cert_method, d.delegated_to_core_id, d.delegated_endpoint, d.delegation_mode,
		       d.cert_expires_at, d.created_at, d.updated_at
		FROM domains d ORDER BY d.domain`)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("domains: list", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()

	result := make([]domainRow, 0)
	for rows.Next() {
		var d domainRow
		var credJSON string
		var exp sql.NullTime
		if err := rows.Scan(&d.ID, &d.Domain, &d.CoreID, &d.DNSProvider, &credJSON,
			&d.CertMethod, &d.DelegatedToCoreID, &d.DelegatedEndpoint, &d.DelegationMode,
			&exp, &d.CreatedAt, &d.UpdatedAt); err != nil {
			continue
		}
		if exp.Valid {
			d.CertExpiresAt = &exp.Time
		}
		var creds any
		if err := json.Unmarshal([]byte(credJSON), &creds); err == nil {
			d.DNSCredentials = creds
		}
		result = append(result, d)
	}
	jsonOK(w, result)
}

func (h *DomainsHandler) get(w http.ResponseWriter, r *http.Request, id string) {
	var d domainRow
	var credJSON string
	var exp sql.NullTime
	err := h.DB.QueryRowContext(r.Context(), `
		SELECT id, domain, core_id, dns_provider, dns_credentials,
		       cert_method, delegated_to_core_id, delegated_endpoint, delegation_mode,
		       cert_expires_at, created_at, updated_at
		FROM domains WHERE id=?`, id).Scan(
		&d.ID, &d.Domain, &d.CoreID, &d.DNSProvider, &credJSON,
		&d.CertMethod, &d.DelegatedToCoreID, &d.DelegatedEndpoint, &d.DelegationMode,
		&exp, &d.CreatedAt, &d.UpdatedAt)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.domain_not_found")
		return
	}
	if err != nil {
		h.Log.Error("domains: get", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if exp.Valid {
		d.CertExpiresAt = &exp.Time
	}
	var creds any
	if err := json.Unmarshal([]byte(credJSON), &creds); err == nil {
		d.DNSCredentials = creds
	}
	jsonOK(w, d)
}

func (h *DomainsHandler) create(w http.ResponseWriter, r *http.Request) {
	var req domainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		http.Error(w, "domain requis", http.StatusBadRequest)
		return
	}
	credJSON := "{}"
	if req.DNSCredentials != nil {
		if b, err := json.Marshal(req.DNSCredentials); err == nil {
			credJSON = string(b)
		}
	}
	if req.DNSProvider == "" {
		req.DNSProvider = "none"
	}
	if req.CertMethod == "" {
		req.CertMethod = "http"
	}
	if req.DelegationMode == "" {
		req.DelegationMode = "passthrough"
	}
	resolvedCoreID, err := h.resolveCoreRef(r.Context(), req.CoreID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resolvedDelegatedToCoreID, err := h.resolveCoreRef(r.Context(), req.DelegatedToCoreID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := uuid.New().String()
	_, err = h.DB.ExecContext(r.Context(), `
		INSERT INTO domains (id, domain, core_id, dns_provider, dns_credentials,
		                     cert_method, delegated_to_core_id, delegated_endpoint, delegation_mode)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, req.Domain, resolvedCoreID, req.DNSProvider, credJSON,
		req.CertMethod, resolvedDelegatedToCoreID, req.DelegatedEndpoint, req.DelegationMode)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			http.Error(w, "ce domaine existe déjà", http.StatusConflict)
			return
		}
		h.Log.Error("domains: create", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	// Déclencher ACME si un provider DNS est configuré
	if h.Manager != nil && req.DNSProvider != "" && req.DNSProvider != "none" && req.CertMethod == "dns" {
		var creds map[string]any
		if req.DNSCredentials != nil {
			if b, err2 := json.Marshal(req.DNSCredentials); err2 == nil {
				_ = json.Unmarshal(b, &creds)
			}
		}
		go func() {
			if err := h.Manager.ObtainCertWithProvider(context.Background(), req.Domain, req.DNSProvider, creds); err != nil {
				h.Log.Error("domains: obtention cert ACME", "domain", req.Domain, "err", err)
			}
		}()
	}

	ensured := h.ensureDomainScopesForCores(r.Context(), req.Domain, resolvedCoreID, resolvedDelegatedToCoreID)
	h.resyncAfterScopeEnsure(ensured, req.DelegatedToCoreID != "")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id":             id,
		"scopes_ensured": ensured,
	})
}

func (h *DomainsHandler) update(w http.ResponseWriter, r *http.Request, id string) {
	var req domainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	credJSON := "{}"
	if req.DNSCredentials != nil {
		if b, err := json.Marshal(req.DNSCredentials); err == nil {
			credJSON = string(b)
		}
	}
	if req.DelegationMode == "" {
		req.DelegationMode = "passthrough"
	}
	resolvedCoreID, err := h.resolveCoreRef(r.Context(), req.CoreID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	resolvedDelegatedToCoreID, err := h.resolveCoreRef(r.Context(), req.DelegatedToCoreID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, err := h.DB.ExecContext(r.Context(), `
		UPDATE domains SET domain=?, core_id=?, dns_provider=?, dns_credentials=?,
		                   cert_method=?, delegated_to_core_id=?, delegated_endpoint=?,
		                   delegation_mode=?, updated_at=CURRENT_TIMESTAMP
		WHERE id=?`,
		req.Domain, resolvedCoreID, req.DNSProvider, credJSON,
		req.CertMethod, resolvedDelegatedToCoreID, req.DelegatedEndpoint,
		req.DelegationMode, id)
	if err != nil {
		h.Log.Error("domains: update", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.domain_not_found")
		return
	}
	ensured := h.ensureDomainScopesForCores(r.Context(), req.Domain, resolvedCoreID, resolvedDelegatedToCoreID)
	// Toujours resync routes/délégations après update domaine (comportement historique).
	h.resyncAfterScopeEnsure(ensured, true)

	jsonOK(w, map[string]any{"scopes_ensured": ensured})
}

func (h *DomainsHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM domains WHERE id=?`, id)
	if err != nil {
		h.Log.Error("domains: delete", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.domain_not_found")
		return
	}
	if h.Pusher != nil {
		go func() {
			h.Pusher.PushRoutes(context.Background())
			h.Pusher.PushDelegations(context.Background())
		}()
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *DomainsHandler) renew(w http.ResponseWriter, r *http.Request, id string) {
	var domain, dnsProvider, credJSON string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT domain, dns_provider, dns_credentials FROM domains WHERE id=?`, id).
		Scan(&domain, &dnsProvider, &credJSON)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.domain_not_found")
		return
	}
	if err != nil {
		h.Log.Error("domains: renew lookup", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	if h.Manager == nil {
		http.Error(w, "ACME non configuré", http.StatusServiceUnavailable)
		return
	}

	var creds map[string]any
	_ = json.Unmarshal([]byte(credJSON), &creds)

	go func() {
		if err := h.Manager.ObtainCertWithProvider(context.Background(), domain, dnsProvider, creds); err != nil {
			h.Log.Error("domains: renouvellement cert", "domain", domain, "err", err)
		}
	}()

	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending", "domain": domain})
}
