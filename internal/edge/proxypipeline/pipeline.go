// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxypipeline

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/proxystore"
	"github.com/vincamok/goproxify/internal/edge/router"
)

var (
	ErrInvalidTransition = errors.New("proxypipeline: transition invalide")
	ErrDryRunFailed      = errors.New("proxypipeline: dry-run échoué")
	ErrNotValidated      = errors.New("proxypipeline: révision non validée")
)

// Pipeline orchestrates pending → validated → production|rejected.
type Pipeline struct {
	store *proxystore.Store
	mu    sync.Mutex // serialize promote per process (HA = later)
}

// New creates a Pipeline bound to a proxystore.
func New(store *proxystore.Store) *Pipeline {
	return &Pipeline{store: store}
}

// Store exposes the underlying file store.
func (p *Pipeline) Store() *proxystore.Store { return p.store }

// CreateRevision writes a new pending revision (does not touch prod files).
func (p *Pipeline) CreateRevision(env *proxystore.Envelope) error {
	if env == nil {
		return fmt.Errorf("proxypipeline: envelope nil")
	}
	if env.ID == "" {
		return fmt.Errorf("proxypipeline: id requis")
	}
	if env.Revision == "" {
		return fmt.Errorf("proxypipeline: revision requise")
	}
	if env.SchemaVersion == 0 {
		env.SchemaVersion = proxystore.SchemaVersionV1
	}
	env.Config = rewriteHTTPSTypeInConfig(env.Config)
	now := time.Now().UTC()
	if env.CreatedAt == nil {
		env.CreatedAt = &now
	}
	env.UpdatedAt = now
	env.Status = proxystore.StatusPending
	env.DryRun = nil
	return p.store.WriteRevision(env)
}

// DryRun validates a revision without applying it to memory.
// On success, status becomes validated; on failure stays pending with dry_run errors.
func (p *Pipeline) DryRun(id, rev string, opts DryRunOptions) (*proxystore.Envelope, error) {
	env, err := p.store.ReadRevision(id, rev)
	if err != nil {
		return nil, err
	}
	if env.Status == proxystore.StatusRejected {
		return env, fmt.Errorf("%w: révision rejected", ErrInvalidTransition)
	}
	if env.Status == proxystore.StatusProduction {
		return env, fmt.Errorf("%w: déjà production", ErrInvalidTransition)
	}

	result := RunDryRun(env, p.collectPeers(id, rev), opts)
	now := time.Now().UTC()
	env.DryRun = &result
	env.UpdatedAt = now
	if result.OK {
		env.Status = proxystore.StatusValidated
	} else {
		env.Status = proxystore.StatusPending
	}
	if err := p.store.WriteRevision(env); err != nil {
		return nil, err
	}
	if !result.OK {
		return env, fmt.Errorf("%w: %v", ErrDryRunFailed, result.Errors)
	}
	return env, nil
}

// Promote writes the validated revision to proxies/ (durable prod).
// Does NOT apply to memory — caller (Server) must apply after success.
func (p *Pipeline) Promote(id, rev string) (*proxystore.Envelope, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	env, err := p.store.ReadRevision(id, rev)
	if err != nil {
		return nil, err
	}
	if env.Status == proxystore.StatusRejected {
		return env, fmt.Errorf("%w: rejected", ErrInvalidTransition)
	}
	if env.Status != proxystore.StatusValidated {
		return env, ErrNotValidated
	}
	if env.DryRun == nil || !env.DryRun.OK {
		return env, ErrNotValidated
	}

	// Re-check collisions at promote time.
	result := RunDryRun(env, p.collectPeers(id, rev), DryRunOptions{})
	if !result.OK {
		env.DryRun = &result
		env.Status = proxystore.StatusPending
		env.UpdatedAt = time.Now().UTC()
		_ = p.store.WriteRevision(env)
		return env, fmt.Errorf("%w: %v", ErrDryRunFailed, result.Errors)
	}

	old, _ := p.store.ReadProdByID(id)

	prod := *env
	prod.Status = proxystore.StatusProduction
	prod.Revision = ""
	prod.DryRun = nil
	prod.UpdatedAt = time.Now().UTC()
	if err := p.store.WriteProd(&prod); err != nil {
		return nil, err
	}
	if old != nil {
		_ = p.store.RemoveProdIfRenamed(old, &prod)
	}

	// Mark revision as production (audit trail of what was promoted).
	env.Status = proxystore.StatusProduction
	env.UpdatedAt = prod.UpdatedAt
	if err := p.store.WriteRevision(env); err != nil {
		return nil, err
	}
	return &prod, nil
}

// Reject marks a revision as rejected.
func (p *Pipeline) Reject(id, rev, reason string) (*proxystore.Envelope, error) {
	env, err := p.store.ReadRevision(id, rev)
	if err != nil {
		return nil, err
	}
	if env.Status == proxystore.StatusProduction {
		return env, fmt.Errorf("%w: impossible de reject une révision déjà promue", ErrInvalidTransition)
	}
	now := time.Now().UTC()
	env.Status = proxystore.StatusRejected
	env.UpdatedAt = now
	errs := []string{}
	if reason != "" {
		errs = append(errs, reason)
	}
	env.DryRun = &proxystore.DryRunResult{OK: false, CheckedAt: &now, Errors: errs}
	if err := p.store.WriteRevision(env); err != nil {
		return nil, err
	}
	return env, nil
}

func (p *Pipeline) collectPeers(excludeID, excludeRev string) []*proxystore.Envelope {
	// Uniquement la production : les révisions « validated » orphelines (dry-run OK
	// puis promote abandonné / UI) bloquaient listen_port sans apparaître dans la liste Admin.
	peers := make([]*proxystore.Envelope, 0)
	if prods, err := p.store.ListProd(); err == nil {
		for _, e := range prods {
			if e.ID == excludeID {
				continue // replaced on promote
			}
			peers = append(peers, e)
		}
	}
	_ = excludeRev
	return peers
}

// ParseRoute unmarshals envelope config into router.Route.
func ParseRoute(env *proxystore.Envelope) (*router.Route, error) {
	if env == nil || len(env.Config) == 0 {
		return nil, fmt.Errorf("proxypipeline: config vide")
	}
	var route router.Route
	if err := json.Unmarshal(env.Config, &route); err != nil {
		return nil, fmt.Errorf("proxypipeline: config JSON: %w", err)
	}
	if route.ID == "" {
		route.ID = env.ID
	}
	if route.Host == "" && env.Host != "" {
		route.Host = env.Host
	}
	normalizeRouteType(&route)
	return &route, nil
}

// normalizeRouteType maps UI aliases onto runtime types.
// "https" is the Admin UI value for HTTP + TLS (tls_enabled), not a distinct RouteType.
func normalizeRouteType(route *router.Route) {
	if route == nil {
		return
	}
	switch strings.ToLower(string(route.Type)) {
	case "https":
		route.Type = router.RouteHTTP
		route.TLSEnabled = true
	case "":
		if route.ListenPort > 0 {
			return
		}
		route.Type = router.RouteHTTP
	}
}

// rewriteHTTPSTypeInConfig patches raw config so files store canonical type "http".
func rewriteHTTPSTypeInConfig(config json.RawMessage) json.RawMessage {
	if len(config) == 0 {
		return config
	}
	var m map[string]any
	if err := json.Unmarshal(config, &m); err != nil {
		return config
	}
	t, _ := m["type"].(string)
	if !strings.EqualFold(t, "https") {
		return config
	}
	m["type"] = string(router.RouteHTTP)
	m["tls_enabled"] = true
	out, err := json.Marshal(m)
	if err != nil {
		return config
	}
	return out
}
