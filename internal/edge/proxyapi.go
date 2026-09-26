// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/proxypipeline"
	"github.com/vincamok/goproxify/internal/edge/proxystore"
	"github.com/vincamok/goproxify/internal/edge/router"
)

type proxyRevisionBody struct {
	ID        string          `json:"id,omitempty"`
	Host      string          `json:"host,omitempty"`
	Enabled   *bool           `json:"enabled,omitempty"`
	CreatedBy string          `json:"created_by,omitempty"`
	Config    json.RawMessage `json:"config"`
}

func (s *Server) handleListFileProxies(w http.ResponseWriter, r *http.Request) {
	prods, err := s.proxyStore.ListProd()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	revs, _ := s.proxyStore.ListRevisions("")
	if revs == nil {
		revs = []*proxystore.Envelope{}
	}
	writeJSON(w, map[string]any{
		"production": prods,
		"revisions":  revs,
	})
}

func (s *Server) handleGetFileProxy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	env, err := s.proxyStore.ReadProdByID(id)
	if errors.Is(err, proxystore.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, env)
}

func (s *Server) handleCreateProxyRevision(w http.ResponseWriter, r *http.Request) {
	var body proxyRevisionBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Config) == 0 {
		http.Error(w, "json body with config required", http.StatusBadRequest)
		return
	}
	var route router.Route
	_ = json.Unmarshal(body.Config, &route)
	id := body.ID
	if id == "" {
		id = route.ID
	}
	if id == "" {
		id = uuid.New().String()
	}
	host := body.Host
	if host == "" {
		host = route.Host
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	// Inject id into config if missing.
	cfg := body.Config
	if route.ID == "" {
		route.ID = id
		route.UpdatedAt = time.Now().UTC()
		if b, err := json.Marshal(route); err == nil {
			cfg = b
		}
	}
	rev := strings.ReplaceAll(uuid.New().String(), "-", "")[:12]
	env := &proxystore.Envelope{
		SchemaVersion: proxystore.SchemaVersionV1,
		ID:            id,
		Revision:      "r" + rev,
		Host:          host,
		Enabled:       enabled,
		CreatedBy:     body.CreatedBy,
		Config:        cfg,
	}
	if err := s.proxyPipe.CreateRevision(env); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, env)
}

func (s *Server) handleDryRunProxyRevision(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rev := r.PathValue("rev")
	opts := s.dryRunOptionsFromRuntime()
	env, err := s.proxyPipe.DryRun(id, rev, opts)
	if errors.Is(err, proxystore.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if errors.Is(err, proxypipeline.ErrDryRunFailed) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		writeJSON(w, env)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	writeJSON(w, env)
}

func (s *Server) handlePromoteProxyRevision(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rev := r.PathValue("rev")
	prod, err := s.proxyPipe.Promote(id, rev)
	if errors.Is(err, proxystore.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if errors.Is(err, proxypipeline.ErrNotValidated) || errors.Is(err, proxypipeline.ErrInvalidTransition) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if errors.Is(err, proxypipeline.ErrDryRunFailed) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		writeJSON(w, prod)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.ApplyFileProxy(prod); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	metrics.Edge.RouteCount.Set(float64(s.table.Len()))
	s.saveCache()
	s.log.Info("proxystore: révision promue et appliquée", "id", id, "rev", rev, "host", prod.Host)
	writeJSON(w, prod)
}

func (s *Server) handleRejectProxyRevision(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	rev := r.PathValue("rev")
	var body struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	env, err := s.proxyPipe.Reject(id, rev, body.Reason)
	if errors.Is(err, proxystore.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, env)
}

func (s *Server) handleDeleteFileProxy(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.proxyStore.DeleteProdByID(id); err != nil && !errors.Is(err, proxystore.ErrNotFound) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.table.Delete(id)
	s.invalidateRouteCache(id)
	metrics.Edge.RouteCount.Set(float64(s.table.Len()))
	s.saveCache()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListProxyRevisions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	revs, err := s.proxyStore.ListRevisions(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, revs)
}

func (s *Server) dryRunOptionsFromRuntime() proxypipeline.DryRunOptions {
	opts := proxypipeline.DryRunOptions{}
	if s.certStore != nil {
		opts.KnownCertNames = map[string]bool{}
		for _, name := range s.certStore.Names() {
			opts.KnownCertNames[name] = true
		}
	}
	if s.snippetStore != nil {
		opts.KnownSnippetIDs = map[string]bool{}
		for _, sn := range s.snippetStore.All() {
			if sn != nil {
				opts.KnownSnippetIDs[sn.ID] = true
			}
		}
	}
	if s.providerStore != nil {
		opts.KnownAuthProviders = map[string]bool{}
		for _, p := range s.providerStore.All() {
			if p != nil {
				opts.KnownAuthProviders[p.ID] = true
			}
		}
	}
	return opts
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
