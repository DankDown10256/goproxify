// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package corepush envoie les mises à jour de routes et de certificats
// aux Cores enregistrés via l'API interne :8000.
package corepush

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/admin/delegation"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	coretls "github.com/vincamok/goproxify/internal/core/tls"
	"github.com/vincamok/goproxify/internal/core/errorpages"
	"github.com/vincamok/goproxify/internal/core/router"
)

// Pusher envoie les tables de routage et les certificats aux Cores.
type Pusher struct {
	db     *sql.DB
	log    *slog.Logger
	client *http.Client
}

// New crée un Pusher.
func New(db *sql.DB, log *slog.Logger) *Pusher {
	return &Pusher{
		db:     db,
		log:    log,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// coreNode représente un Core enregistré (token actif de type core).
type coreNode struct {
	ID           string // ID dans la table tokens (pour charger les scopes)
	NodeName     string
	Token        string
	Endpoint     string // ex: http://10.0.0.5:8000
	RBACRole     string // 'admin' | 'operator' | 'viewer'
	RaftEndpoint string // ex: http://10.0.0.5:8002 (vide si pas de cluster)
}

// PushRoutes envoie la liste des routes activées à tous les Cores enregistrés.
// Chaque Core ne reçoit que les routes correspondant à son rbac_role + token_scopes.
// Bloque jusqu'à la fin des envois.
func (p *Pusher) PushRoutes(ctx context.Context) {
	cores, err := p.activeCores(ctx)
	if err != nil {
		p.log.Error("corepush: lecture des Cores", "err", err)
		return
	}

	allRoutes, err := p.activeRoutesParsed(ctx)
	if err != nil {
		p.log.Error("corepush: lecture des routes", "err", err)
		return
	}

	bindings := p.loadDelegationBindings(ctx)
	var wg sync.WaitGroup
	for _, c := range cores {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			acc := rbac.LoadCoreAccess(ctx, p.db, c.ID, c.NodeName)
			filtered := rbac.FilterRoutesByScopes(acc.Role, acc.Scopes, allRoutes)
			filtered = delegation.FilterRoutesForCore(c.ID, c.NodeName, filtered, bindings)
			body, err := json.Marshal(filtered)
			if err != nil {
				return
			}
			p.sendRoutes(ctx, c, body)
		}()
	}
	wg.Wait()
}

// PushCerts relit tous les certificats stockés en DB et les envoie à tous les Cores.
// Appelé lors de l'enregistrement d'un nouveau Core pour restaurer les certs après redémarrage.
func (p *Pusher) PushCerts(ctx context.Context) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT domain, cert_pem, key_pem FROM certs WHERE cert_pem != '' AND key_pem != ''`)
	if err != nil {
		p.log.Error("corepush: lecture certs DB", "err", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var domain, certPEM, keyPEM string
		if err := rows.Scan(&domain, &certPEM, &keyPEM); err != nil {
			continue
		}
		pemBytes := []byte(certPEM)
		keyBytes := []byte(keyPEM)
		for _, name := range coretls.PushNames(domain, pemBytes) {
			go p.PushCert(ctx, name, pemBytes, keyBytes)
		}
	}
}

// PushCert envoie un certificat déchiffré (PEM) aux Cores dont le périmètre le couvre.
// Admin sans scope → tous les Cores.
func (p *Pusher) PushCert(ctx context.Context, name string, certPEM, keyPEM []byte) {
	cores, err := p.activeCores(ctx)
	if err != nil {
		p.log.Error("corepush: lecture des Cores pour cert", "err", err)
		return
	}

	payload := map[string]any{
		"name":     name,
		"cert_pem": certPEM,
		"key_pem":  keyPEM,
	}
	body, _ := json.Marshal(payload)

	for _, c := range cores {
		scopes, _ := rbac.TokenScopes(ctx, p.db, c.ID)
		if !rbac.ShouldReceiveCert(c.RBACRole, scopes, name) {
			continue
		}
		c := c
		go p.sendCert(ctx, c, body)
	}
}

func (p *Pusher) sendRoutes(ctx context.Context, c coreNode, body []byte) {
	if err := p.post(ctx, c, "/internal/v1/routes", body, "routes"); err == nil {
		p.log.Info("corepush: routes envoyées", "core", c.NodeName)
	}
}

func (p *Pusher) loadDelegationBindings(ctx context.Context) []delegation.Binding {
	rows, err := p.db.QueryContext(ctx, `
		SELECT domain, core_id, delegated_to_core_id
		FROM domains
		WHERE delegated_to_core_id != '' AND delegated_endpoint != ''`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []delegation.Binding
	for rows.Next() {
		var b delegation.Binding
		if err := rows.Scan(&b.Domain, &b.ResponsibleCoreID, &b.TargetCoreID); err != nil {
			continue
		}
		out = append(out, b)
	}
	return out
}

// PushSnippets envoie tous les snippets actifs à tous les Cores enregistrés.
func (p *Pusher) PushSnippets(ctx context.Context) {
	cores, err := p.activeCores(ctx)
	if err != nil {
		p.log.Error("corepush: lecture des Cores pour snippets", "err", err)
		return
	}
	snippets, err := p.activeSnippets(ctx)
	if err != nil {
		p.log.Error("corepush: lecture des snippets", "err", err)
		return
	}
	body, _ := json.Marshal(snippets)
	for _, c := range cores {
		go p.post(ctx, c, "/internal/v1/snippets", body, "snippets")
	}
}

// PushAuthProviders envoie tous les fournisseurs auth à tous les Cores enregistrés.
func (p *Pusher) PushAuthProviders(ctx context.Context) {
	cores, err := p.activeCores(ctx)
	if err != nil {
		p.log.Error("corepush: lecture des Cores pour providers", "err", err)
		return
	}
	providers, err := p.activeAuthProviders(ctx)
	if err != nil {
		p.log.Error("corepush: lecture des providers", "err", err)
		return
	}
	body, _ := json.Marshal(providers)
	for _, c := range cores {
		go p.post(ctx, c, "/internal/v1/auth-providers", body, "auth-providers")
	}
}

// PushAll envoie routes, snippets, fournisseurs auth, profils IP et paramètres à tous les Cores.
// Utilisé après un enregistrement Core pour synchroniser l'ensemble de la config.
// Les Settings sont passés par l'appelant (Admin server connaît sa propre config).
func (p *Pusher) PushAll(ctx context.Context, settings Settings) {
	go p.PushRoutes(ctx)
	go p.PushSnippets(ctx)
	go p.PushAuthProviders(ctx)
	go p.PushIPProfiles(ctx)
	go p.PushBans(ctx)
	go p.PushClusterPeers(ctx)
	go p.PushSettings(ctx, settings)
	go p.PushCerts(ctx)
	go p.PushDelegations(ctx)
	go p.PushErrorPages(ctx)
}

// PushErrorPages envoie la bibliothèque de pages d'erreur aux Cores (HTTP legacy).
// Bloque jusqu'à la fin des envois (évite la course avec PushRoutes).
func (p *Pusher) PushErrorPages(ctx context.Context) {
	cores, err := p.activeCores(ctx)
	if err != nil {
		p.log.Error("corepush: lecture des Cores pour error pages", "err", err)
		return
	}
	tpls, err := p.loadErrorPages(ctx)
	if err != nil {
		p.log.Error("corepush: lecture error pages", "err", err)
		return
	}
	body, _ := json.Marshal(tpls)
	var wg sync.WaitGroup
	for _, c := range cores {
		c := c
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = p.post(ctx, c, "/internal/v1/error-pages", body, "error-pages")
		}()
	}
	wg.Wait()
}

// Settings regroupe les paramètres runtime poussés aux Cores.
type Settings struct {
	TracingEndpoint string `json:"tracing_endpoint,omitempty"`
	LogLevel        string `json:"log_level,omitempty"`
	LogFormat       string `json:"log_format,omitempty"`
	AccessLogPath   string `json:"access_log_path,omitempty"`
	AdminPublicURL  string `json:"admin_public_url,omitempty"`
}

// PushSettings envoie les paramètres runtime à tous les Cores.
// Le Core applique chaque champ uniquement si sa config locale est vide.
func (p *Pusher) PushSettings(ctx context.Context, s Settings) {
	cores, err := p.activeCores(ctx)
	if err != nil {
		p.log.Error("corepush: lecture des Cores pour settings", "err", err)
		return
	}
	body, _ := json.Marshal(s)
	for _, c := range cores {
		go p.post(ctx, c, "/internal/v1/settings", body, "settings")
	}
}

// PushClusterPeers envoie la topologie Raft (tous les Cores actifs avec raft_endpoint) à chaque Core.
func (p *Pusher) PushClusterPeers(ctx context.Context) {
	cores, err := p.activeCores(ctx)
	if err != nil {
		p.log.Error("corepush: lecture des Cores pour cluster/peers", "err", err)
		return
	}

	// Construire la map peers : nodeID → raft_endpoint (on exclut les Cores sans raft_endpoint).
	peers := make(map[string]string)
	for _, c := range cores {
		if c.RaftEndpoint != "" {
			peers[c.NodeName] = c.RaftEndpoint
		}
	}
	if len(peers) == 0 {
		return
	}

	body, _ := json.Marshal(peers)
	for _, c := range cores {
		go p.post(ctx, c, "/internal/v1/cluster/peers", body, "cluster/peers")
	}
}

// PushDelegations construit des routes synthétiques pour chaque domaine délégué
// et les envoie au Core qui reçoit le trafic (core_id), en complément de ses routes normales.
// Mode passthrough : TLSPassthrough=true, TCP forward brut vers le Core cible.
// Mode terminate   : TLSPassthrough=false, proxy HTTP(S) vers le Core cible.
func (p *Pusher) PushDelegations(ctx context.Context) {
	type delegation struct {
		ID                string
		Domain            string
		CoreID            string // Core qui reçoit le trafic
		DelegatedEndpoint string
		DelegationMode    string // passthrough | terminate
	}

	rows, err := p.db.QueryContext(ctx, `
		SELECT id, domain, core_id, delegated_endpoint, delegation_mode
		FROM domains
		WHERE delegated_to_core_id != '' AND delegated_endpoint != ''`)
	if err != nil {
		p.log.Error("corepush: lecture des délégations", "err", err)
		return
	}
	defer rows.Close()

	// Regrouper par core_id
	byCoreID := map[string][]delegation{}
	for rows.Next() {
		var d delegation
		if err := rows.Scan(&d.ID, &d.Domain, &d.CoreID, &d.DelegatedEndpoint, &d.DelegationMode); err != nil {
			continue
		}
		byCoreID[d.CoreID] = append(byCoreID[d.CoreID], d)
	}
	if len(byCoreID) == 0 {
		return
	}

	cores, err := p.activeCores(ctx)
	if err != nil {
		p.log.Error("corepush: lecture des Cores pour délégations", "err", err)
		return
	}

	for _, c := range cores {
		delegs, ok := byCoreID[c.ID]
		if !ok {
			continue
		}
		c, delegs := c, delegs
		go func() {
			routes := make([]router.Route, 0, len(delegs))
			for _, d := range delegs {
				r := router.Route{
					ID:   "deleg-" + d.ID,
					Host: d.Domain,
					Type: router.RouteHTTP,
				}
				if d.DelegationMode == "terminate" {
					// Core A termine TLS et proxy HTTP(S) vers Core B
					r.TLSEnabled = true
					r.TLSPassthrough = false
					r.PreserveHost = boolPtr(true) // core B doit recevoir le Host original pour router
					backendURL := d.DelegatedEndpoint
					if len(backendURL) > 0 && backendURL[0] != 'h' {
						backendURL = "https://" + backendURL
					}
					r.Backends = []router.Backend{{URL: backendURL}}
					// Explicite côté Admin (pas forcé par Core) — labs / Core B auto-signé.
					r.TLSSkipVerify = true
				} else {
					// Mode passthrough : TCP forward sans déchiffrement
					r.TLSEnabled = true
					r.TLSPassthrough = true
					backendURL := d.DelegatedEndpoint
					if len(backendURL) > 0 && backendURL[0] != 'h' {
						backendURL = "https://" + backendURL
					}
					r.Backends = []router.Backend{{URL: backendURL}}
				}
				routes = append(routes, r)
			}
			body, err := json.Marshal(routes)
			if err != nil {
				return
			}
			if err := p.post(ctx, c, "/internal/v1/delegations", body, "delegations"); err == nil {
				p.log.Info("corepush: délégations envoyées", "core", c.NodeName, "count", len(routes))
			}
		}()
	}
}

// DeleteRoute supprime immédiatement une route sur tous les Cores enregistrés.
func (p *Pusher) DeleteRoute(ctx context.Context, id string) {
	cores, err := p.activeCores(ctx)
	if err != nil {
		p.log.Error("corepush: lecture des Cores pour delete", "err", err)
		return
	}
	for _, c := range cores {
		go p.sendDeleteRoute(ctx, c, id)
	}
}

func (p *Pusher) sendDeleteRoute(ctx context.Context, c coreNode, id string) {
	url := fmt.Sprintf("%s/internal/v1/routes/%s", c.Endpoint, id)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := p.client.Do(req)
	if err != nil {
		p.log.Warn("corepush: suppression route échouée", "core", c.NodeName, "id", id, "err", err)
		return
	}
	resp.Body.Close()
	p.log.Info("corepush: route supprimée", "core", c.NodeName, "id", id)
}

func (p *Pusher) sendCert(ctx context.Context, c coreNode, body []byte) {
	url := c.Endpoint + "/internal/v1/certs"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		p.log.Warn("corepush: envoi cert échoué", "core", c.NodeName, "err", err)
		return
	}
	resp.Body.Close()
	p.log.Info("corepush: certificat envoyé", "core", c.NodeName)
}

// activeCores retourne les Cores actifs depuis la table tokens.
func (p *Pusher) activeCores(ctx context.Context) ([]coreNode, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT id, node_name, token, node_endpoint, COALESCE(rbac_role, 'admin'), COALESCE(raft_endpoint, '')
		 FROM tokens
		 WHERE role='core' AND revoked=0 AND node_endpoint != ''
		   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cores []coreNode
	for rows.Next() {
		var c coreNode
		if err := rows.Scan(&c.ID, &c.NodeName, &c.Token, &c.Endpoint, &c.RBACRole, &c.RaftEndpoint); err != nil {
			continue
		}
		cores = append(cores, c)
	}
	return cores, nil
}

func (p *Pusher) post(ctx context.Context, c coreNode, path string, body []byte, label string) error {
	url := c.Endpoint + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		p.log.Warn("corepush: envoi échoué", "label", label, "core", c.NodeName, "err", err)
		return err
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		p.log.Warn("corepush: token refusé (401) — vérifier le token du Core dans Admin > Tokens", "label", label, "core", c.NodeName)
		return fmt.Errorf("status 401")
	}
	if resp.StatusCode >= 300 {
		p.log.Warn("corepush: réponse inattendue", "label", label, "core", c.NodeName, "status", resp.StatusCode)
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func (p *Pusher) activeSnippets(ctx context.Context) ([]json.RawMessage, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT id, name, type, config FROM snippets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type snippet struct {
		ID     string          `json:"id"`
		Name   string          `json:"name"`
		Type   string          `json:"type"`
		Config json.RawMessage `json:"config"`
	}
	var list []json.RawMessage
	for rows.Next() {
		var s snippet
		var cfg string
		if err := rows.Scan(&s.ID, &s.Name, &s.Type, &cfg); err != nil {
			continue
		}
		s.Config = json.RawMessage(cfg)
		b, _ := json.Marshal(s)
		list = append(list, b)
	}
	if list == nil {
		list = []json.RawMessage{}
	}
	return list, nil
}

func (p *Pusher) loadErrorPages(ctx context.Context) ([]errorpages.Template, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT id, name, description, body, scope_type, scope_id
		 FROM error_page_templates WHERE scope_type='admin'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []errorpages.Template
	for rows.Next() {
		var t errorpages.Template
		if err := rows.Scan(&t.ID, &t.Name, &t.Description, &t.Body, &t.ScopeType, &t.ScopeID); err != nil {
			continue
		}
		aRows, err := p.db.QueryContext(ctx,
			`SELECT filename, content_type, content FROM error_page_assets WHERE template_id=?`, t.ID)
		if err == nil {
			for aRows.Next() {
				var a errorpages.Asset
				if err := aRows.Scan(&a.Filename, &a.ContentType, &a.Content); err != nil {
					continue
				}
				t.Assets = append(t.Assets, a)
			}
			aRows.Close()
		}
		list = append(list, t)
	}
	if list == nil {
		list = []errorpages.Template{}
	}
	return list, nil
}

func (p *Pusher) activeAuthProviders(ctx context.Context) ([]json.RawMessage, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT id, name, provider, config FROM auth_providers WHERE enabled=1`)
	if err != nil {
		// La table peut ne pas exister encore — retourner vide sans erreur.
		return []json.RawMessage{}, nil
	}
	defer rows.Close()
	type provider struct {
		ID       string          `json:"id"`
		Name     string          `json:"name"`
		Provider string          `json:"provider"`
		Config   json.RawMessage `json:"config"`
	}
	var list []json.RawMessage
	for rows.Next() {
		var pr provider
		var cfg string
		if err := rows.Scan(&pr.ID, &pr.Name, &pr.Provider, &cfg); err != nil {
			continue
		}
		pr.Config = json.RawMessage(cfg)
		b, _ := json.Marshal(pr)
		list = append(list, b)
	}
	if list == nil {
		list = []json.RawMessage{}
	}
	return list, nil
}

// PushIPProfiles envoie les profils IP actifs (avec CIDRs compilés) à tous les Cores.
func (p *Pusher) PushIPProfiles(ctx context.Context) {
	cores, err := p.activeCores(ctx)
	if err != nil {
		p.log.Error("corepush: lecture des Cores pour ip-profiles", "err", err)
		return
	}
	profiles, err := p.activeIPProfiles(ctx)
	if err != nil {
		p.log.Error("corepush: lecture des ip-profiles", "err", err)
		return
	}
	body, _ := json.Marshal(profiles)
	for _, c := range cores {
		go p.post(ctx, c, "/internal/v1/ip-profiles", body, "ip-profiles")
	}
}

// PushBans envoie les bans IP actifs à tous les Cores (HTTP legacy).
func (p *Pusher) PushBans(ctx context.Context) {
	cores, err := p.activeCores(ctx)
	if err != nil {
		p.log.Error("corepush: lecture des Cores pour bans", "err", err)
		return
	}
	list, err := p.activeBans(ctx)
	if err != nil {
		p.log.Error("corepush: lecture des bans", "err", err)
		return
	}
	body, _ := json.Marshal(list)
	for _, c := range cores {
		go p.post(ctx, c, "/internal/v1/bans", body, "bans")
	}
}

func (p *Pusher) activeBans(ctx context.Context) ([]map[string]any, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, ip, reason, source, expires_at
		FROM security_bans
		WHERE expires_at IS NULL OR expires_at = '' OR expires_at > CURRENT_TIMESTAMP`)
	if err != nil {
		return []map[string]any{}, nil
	}
	defer rows.Close()
	var list []map[string]any
	for rows.Next() {
		var id, ip, reason, source string
		var expires sql.NullString
		if err := rows.Scan(&id, &ip, &reason, &source, &expires); err != nil {
			continue
		}
		m := map[string]any{"id": id, "ip": ip, "reason": reason, "source": source}
		if expires.Valid && expires.String != "" {
			m["expires_at"] = expires.String
		}
		list = append(list, m)
	}
	if list == nil {
		list = []map[string]any{}
	}
	return list, nil
}

func (p *Pusher) activeIPProfiles(ctx context.Context) ([]json.RawMessage, error) {
	rows, err := p.db.QueryContext(ctx,
		`SELECT id, name, mode, cidrs FROM ip_profiles WHERE enabled=1`)
	if err != nil {
		return []json.RawMessage{}, nil
	}
	defer rows.Close()
	type profile struct {
		ID    string          `json:"id"`
		Name  string          `json:"name"`
		Mode  string          `json:"mode"`
		CIDRs json.RawMessage `json:"cidrs"`
	}
	var list []json.RawMessage
	for rows.Next() {
		var pr profile
		var cidrs string
		if err := rows.Scan(&pr.ID, &pr.Name, &pr.Mode, &cidrs); err != nil {
			continue
		}
		pr.CIDRs = json.RawMessage(cidrs)
		b, _ := json.Marshal(pr)
		list = append(list, b)
	}
	if list == nil {
		list = []json.RawMessage{}
	}
	return list, nil
}

// activeRoutesParsed retourne toutes les routes activées sous forme de structs (pour filtrage RBAC).
func (p *Pusher) activeRoutesParsed(ctx context.Context) ([]router.Route, error) {
	rows, err := p.db.QueryContext(ctx, `SELECT config FROM proxies WHERE enabled=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var routes []router.Route
	for rows.Next() {
		var cfg string
		if err := rows.Scan(&cfg); err != nil {
			continue
		}
		var r router.Route
		if err := json.Unmarshal([]byte(cfg), &r); err == nil {
			routes = append(routes, r)
		}
	}
	if routes == nil {
		routes = []router.Route{}
	}
	return routes, nil
}

func boolPtr(b bool) *bool { return &b }
