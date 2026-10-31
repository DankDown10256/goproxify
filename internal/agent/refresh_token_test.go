// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/vincamok/goproxify/internal/agent/edgeset"
	agentsources "github.com/vincamok/goproxify/internal/agent/sources"
	"github.com/vincamok/goproxify/internal/config"
)

func newRefreshAgent(t *testing.T, srv *httptest.Server, gotToken *string) *Agent {
	t.Helper()
	t.Setenv("GPX_PAIRING_SECRET", "")
	t.Setenv("GPX_AGENT_PAIRING_KEY", "cle")
	t.Setenv("GPX_AGENT_PAIRING_KEY_PREVIOUS", "")
	a := &Agent{
		cfg:         &config.AgentConfig{},
		log:         slog.Default(),
		edges:       edgeset.New(srv.URL, ""),
		internalAPI: &internalAPI{},
		sources:     []*agentsources.Instance{{SetToken: func(tok string) { *gotToken = tok }}},
	}
	a.cfg.ControlPlane.EdgeEndpoint = srv.URL
	return a
}

// Chaque source scanne en parallèle et reçoit le même 401 : un seul appairage a lieu, tous reprennent son jeton, et les
// sources le reçoivent.
func TestRefreshTokenPairsOnceForConcurrentUnauthorizedStates(t *testing.T) {
	var pairs atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pairs.Add(1)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"jeton-neuf"}`))
	}))
	t.Cleanup(srv.Close)
	var sourceToken string
	a := newRefreshAgent(t, srv, &sourceToken)

	var wg sync.WaitGroup
	results := make([]string, 8)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = a.refreshToken(context.Background(), "jeton-perime")
		}()
	}
	wg.Wait()

	if n := pairs.Load(); n != 1 {
		t.Errorf("%d appairages, attendu 1", n)
	}
	for i, r := range results {
		if r != "jeton-neuf" {
			t.Errorf("appel %d : %q", i, r)
		}
	}
	if sourceToken != "jeton-neuf" || a.cfg.ControlPlane.AuthToken != "jeton-neuf" {
		t.Errorf("le jeton neuf doit atteindre les sources (%q) et la config (%q)", sourceToken, a.cfg.ControlPlane.AuthToken)
	}

	// Le jeton neuf refusé à son tour tout de suite : le délai protège la passerelle, pas de second appairage.
	if tok := a.refreshToken(context.Background(), "jeton-neuf"); tok != "" || pairs.Load() != 1 {
		t.Errorf("second réappairage trop tôt : %q, %d appairages", tok, pairs.Load())
	}
}

// Une passerelle qui refuse l'appairage n'est pas martelée par chaque envoi d'état.
func TestRefreshTokenDoesNotHammerARefusingGateway(t *testing.T) {
	var pairs atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pairs.Add(1)
		http.Error(w, "secret invalide", http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	var sourceToken string
	a := newRefreshAgent(t, srv, &sourceToken)
	a.cfg.ControlPlane.AdminEndpoint = "" // pas de repli sur l'Admin

	for i := 0; i < 5; i++ {
		if tok := a.refreshToken(context.Background(), "jeton-perime"); tok != "" {
			t.Fatalf("appel %d : %q", i, tok)
		}
	}
	if n := pairs.Load(); n != 1 {
		t.Errorf("%d requêtes d'appairage, attendu 1 pour 5 envois refusés", n)
	}
	if sourceToken != "" {
		t.Errorf("aucun jeton à donner aux sources : %q", sourceToken)
	}
}

// Un Agent qui a une passerelle ne se rabat jamais sur l'Admin quand elle ne répond pas encore (redéploiement
// simultané) : l'Admin émettrait un jeton que le magasin de la passerelle ne connaîtra jamais, et l'Agent le garderait
// dans agent.token en recevant des 401 sur chaque appel.
func TestPairNeverFallsBackToTheAdminWhenAnEdgeIsConfigured(t *testing.T) {
	var adminHits atomic.Int32
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminHits.Add(1)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"jeton-admin"}`))
	}))
	t.Cleanup(admin.Close)
	down := httptest.NewServer(http.NotFoundHandler())
	edgeURL := down.URL
	down.Close() // une passerelle qui ne répond pas

	t.Setenv("GPX_PAIRING_SECRET", "")
	t.Setenv("GPX_AGENT_PAIRING_KEY", "cle")
	t.Setenv("GPX_AGENT_PAIRING_KEY_PREVIOUS", "")
	a := &Agent{cfg: &config.AgentConfig{}, log: slog.Default(), edges: edgeset.New(edgeURL, ""), internalAPI: &internalAPI{}}
	a.cfg.ControlPlane.EdgeEndpoint = edgeURL
	a.cfg.ControlPlane.AdminEndpoint = admin.URL

	if tok, err := a.pair(context.Background()); err == nil || tok != "" {
		t.Fatalf("sans passerelle joignable, l'appairage doit échouer : %q %v", tok, err)
	}
	if n := adminHits.Load(); n != 0 {
		t.Errorf("l'Admin ne doit pas être sollicité : %d requêtes", n)
	}
	if a.cfg.ControlPlane.AuthToken != "" {
		t.Errorf("aucun jeton ne doit être retenu : %q", a.cfg.ControlPlane.AuthToken)
	}
}

// Sans passerelle configurée, l'Admin reste le seul interlocuteur.
func TestPairUsesTheAdminWhenNoEdgeIsConfigured(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"jeton-admin"}`))
	}))
	t.Cleanup(admin.Close)

	t.Setenv("GPX_PAIRING_SECRET", "")
	t.Setenv("GPX_AGENT_PAIRING_KEY", "cle")
	t.Setenv("GPX_AGENT_PAIRING_KEY_PREVIOUS", "")
	a := &Agent{cfg: &config.AgentConfig{}, log: slog.Default(), edges: edgeset.New("", ""), internalAPI: &internalAPI{}}
	a.cfg.ControlPlane.AdminEndpoint = admin.URL

	if tok, err := a.pair(context.Background()); err != nil || tok != "jeton-admin" {
		t.Fatalf("appairage par l'Admin : %q %v", tok, err)
	}
}
