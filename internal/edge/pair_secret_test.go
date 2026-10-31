// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/middleware"
	"github.com/vincamok/goproxify/internal/edge/tokens"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
	"github.com/vincamok/goproxify/internal/pairing"
)

func newPairServer(t *testing.T) *Server {
	t.Helper()
	ts, err := tokens.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ts.Close() })
	s := testEdgeServer()
	s.tokenStore = ts
	s.wsHub = edgews.NewHub("hub-secret", slog.New(slog.DiscardHandler))
	return s
}

func pairOnce(s *Server, remote, secret string) int {
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/pair", strings.NewReader(`{"secret":"`+secret+`","node_name":"n1","role":"agent"}`))
	req.RemoteAddr = remote
	rr := httptest.NewRecorder()
	s.handleEdgePair(rr, req)
	return rr.Code
}

func TestEdgePair_AcceptsDerivedKeyAndRootUnlessRefused(t *testing.T) {
	const root = "secret-racine-0123456789abcdef"
	t.Setenv("GPX_PAIRING_SECRET", root)
	s := newPairServer(t)

	if c := pairOnce(s, "10.0.0.1:1111", pairing.AgentKey(root)); c != http.StatusOK && c != http.StatusCreated {
		t.Fatalf("clé dérivée refusée : %d", c)
	}
	if c := pairOnce(s, "10.0.0.2:1111", root); c != http.StatusOK && c != http.StatusCreated {
		t.Fatalf("le secret racine doit rester accepté pendant la migration : %d", c)
	}
	t.Setenv("GPX_AGENT_PAIRING_ROOT", "false")
	if c := pairOnce(s, "10.0.0.3:1111", root); c != http.StatusForbidden {
		t.Fatalf("racine acceptée malgré GPX_AGENT_PAIRING_ROOT=false : %d", c)
	}
	if c := pairOnce(s, "10.0.0.4:1111", pairing.AgentKey(root)); c != http.StatusOK && c != http.StatusCreated {
		t.Fatalf("la clé dérivée doit rester acceptée : %d", c)
	}
}

func TestEdgePair_SecretGuessingIsLockedOut(t *testing.T) {
	const root = "secret-racine-0123456789abcdef"
	t.Setenv("GPX_PAIRING_SECRET", root)
	pairAttempts = nilSafeLimiter()
	s := newPairServer(t)

	for i := 0; i < 5; i++ {
		if c := pairOnce(s, "192.0.2.50:4000", "mauvais"); c != http.StatusForbidden {
			t.Fatalf("essai %d : %d, attendu 403", i, c)
		}
	}
	if c := pairOnce(s, "192.0.2.50:4000", pairing.AgentKey(root)); c != http.StatusTooManyRequests {
		t.Fatalf("après 5 échecs même le bon secret doit être refusé : %d", c)
	}
}

func nilSafeLimiter() *middleware.AuthFailLimiter { return middleware.NewAuthFailLimiter() }

func TestAgentInternalAuthSendsDerivedKeyNotRoot(t *testing.T) {
	const root = "secret-racine-0123456789abcdef"
	t.Setenv("GPX_PAIRING_SECRET", root)
	req := httptest.NewRequest(http.MethodPost, "http://agent:8001/internal/v1/command", nil)
	setAgentInternalAuth(req)
	got := req.Header.Get("Authorization")
	if strings.Contains(got, root) || got != "Bearer "+pairing.AgentKey(root) {
		t.Fatalf("Authorization = %q : le secret racine ne doit jamais partir vers un Agent", got)
	}
}

// Une passerelle sans le secret racine (clé des Agents fournie) appaire les Agents avec la clé dérivée, et ne peut pas
// accepter la racine puisqu'elle ne la détient pas.
func TestEdgePair_WithoutTheRoot(t *testing.T) {
	const root = "secret-racine-0123456789abcdef"
	t.Setenv("GPX_PAIRING_SECRET", "")
	t.Setenv("GPX_AGENT_PAIRING_KEY", pairing.AgentKey(root))
	s := newPairServer(t)

	if c := pairOnce(s, "10.0.1.1:1111", pairing.AgentKey(root)); c != http.StatusOK && c != http.StatusCreated {
		t.Fatalf("clé dérivée refusée sans la racine : %d", c)
	}
	if c := pairOnce(s, "10.0.1.2:1111", root); c != http.StatusForbidden {
		t.Fatalf("le secret racine ne s'accepte pas sans être détenu : %d", c)
	}

	t.Setenv("GPX_AGENT_PAIRING_KEY", "")
	if c := pairOnce(s, "10.0.1.3:1111", pairing.AgentKey(root)); c != http.StatusServiceUnavailable {
		t.Fatalf("sans clé ni racine, l'appairage n'est pas configuré : %d", c)
	}
}

func TestAgentInternalAuthUsesTheConfiguredAgentKeyWithoutTheRoot(t *testing.T) {
	const root = "secret-racine-0123456789abcdef"
	t.Setenv("GPX_PAIRING_SECRET", "")
	t.Setenv("GPX_AGENT_PAIRING_KEY", pairing.AgentKey(root))
	req := httptest.NewRequest(http.MethodGet, "http://agent:8001/x", nil)
	setAgentInternalAuth(req)
	if got := req.Header.Get("Authorization"); got != "Bearer "+pairing.AgentKey(root) {
		t.Fatalf("Authorization = %q", got)
	}
}

// Pendant une rotation de la clé des Agents, la passerelle appaire un Agent qui présente l'ancienne comme la nouvelle, et
// envoie la nouvelle aux Agents.
func TestEdgePair_AcceptsThePreviousAgentKeyDuringARotation(t *testing.T) {
	t.Setenv("GPX_PAIRING_SECRET", "")
	t.Setenv("GPX_AGENT_PAIRING_KEY", "cle-agents-nouvelle")
	t.Setenv("GPX_AGENT_PAIRING_KEY_PREVIOUS", "cle-agents-ancienne")
	s := newPairServer(t)

	if c := pairOnce(s, "10.0.2.1:1111", "cle-agents-nouvelle"); c != http.StatusOK && c != http.StatusCreated {
		t.Fatalf("clé courante refusée : %d", c)
	}
	if c := pairOnce(s, "10.0.2.2:1111", "cle-agents-ancienne"); c != http.StatusOK && c != http.StatusCreated {
		t.Fatalf("clé précédente refusée pendant la rotation : %d", c)
	}
	if c := pairOnce(s, "10.0.2.3:1111", "cle-agents-inconnue"); c != http.StatusForbidden {
		t.Fatalf("une autre clé est refusée : %d", c)
	}
	req := httptest.NewRequest(http.MethodGet, "http://agent:8001/x", nil)
	setAgentInternalAuth(req)
	if got := req.Header.Get("Authorization"); got != "Bearer cle-agents-nouvelle" {
		t.Fatalf("la passerelle envoie la clé courante : %q", got)
	}
}

// Par défaut un Agent qui présente la clé d'appairage est pré-approuvé ; GPX_AGENT_PREAPPROVAL=manual le laisse en attente
// de l'approbation d'un opérateur, tout en lui rendant son jeton.
func TestEdgePair_PreapprovalIsAutomaticUnlessManual(t *testing.T) {
	const root = "secret-racine-0123456789abcdef"
	t.Setenv("GPX_PAIRING_SECRET", root)
	s := newPairServer(t)

	if c := pairOnce(s, "10.0.3.1:1111", pairing.AgentKey(root)); c != http.StatusCreated && c != http.StatusOK {
		t.Fatalf("appairage : %d", c)
	}
	if !s.wsHub.IsPreApproved("n1") {
		t.Fatal("par défaut, l'Agent est pré-approuvé")
	}

	t.Setenv("GPX_AGENT_PREAPPROVAL", "manual")
	s = newPairServer(t)
	if c := pairOnce(s, "10.0.3.2:1111", pairing.AgentKey(root)); c != http.StatusCreated && c != http.StatusOK {
		t.Fatalf("appairage manuel : %d", c)
	}
	if s.wsHub.IsPreApproved("n1") {
		t.Fatal("en mode manuel, l'Agent attend l'approbation d'un opérateur")
	}
}

// Chaque appairage ajoutait un jeton, jamais retiré : un Agent qui s'appaire à chaque démarrage ou bascule remplissait le
// magasin (17 457 jetons pour un seul Agent). Au-delà de KeepAgentTokens, les plus anciens de ce nom sont retirés.
func TestEdgePair_PrunesOldTokensOfTheSameAgent(t *testing.T) {
	const root = "secret-racine-0123456789abcdef"
	t.Setenv("GPX_PAIRING_SECRET", root)
	s := newPairServer(t)

	const pairings = tokens.KeepAgentTokens + 5
	issued := make([]string, pairings)
	for i := range issued {
		req := httptest.NewRequest(http.MethodPost, "/internal/v1/pair",
			strings.NewReader(`{"secret":"`+pairing.AgentKey(root)+`","node_name":"n1","role":"agent"}`))
		req.RemoteAddr = "10.0.0.1:1111"
		rr := httptest.NewRecorder()
		s.handleEdgePair(rr, req)
		if rr.Code != http.StatusCreated && rr.Code != http.StatusOK {
			t.Fatalf("appairage %d : %d", i, rr.Code)
		}
		var out struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || out.Token == "" {
			t.Fatalf("appairage %d : réponse %q", i, rr.Body.String())
		}
		issued[i] = out.Token
	}

	list, _ := s.tokenStore.List()
	n := 0
	for _, tk := range list {
		if tk.Name == "n1" {
			n++
		}
	}
	if n != tokens.KeepAgentTokens {
		t.Errorf("%d jetons gardés pour n1, attendu %d", n, tokens.KeepAgentTokens)
	}
	if ok, _ := s.tokenStore.Validate(issued[pairings-1]); !ok {
		t.Error("le dernier jeton émis doit rester valide")
	}
	if ok, _ := s.tokenStore.Validate(issued[0]); ok {
		t.Error("le plus ancien jeton doit avoir été retiré")
	}
}
