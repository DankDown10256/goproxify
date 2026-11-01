// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/edge/router"
)

const (
	// GatewayChallengePath reçoit la solution du défi de la passerelle, distinct de celui d'une route (botChallengePath).
	GatewayChallengePath   = "/.gpx/ephor-challenge"
	gatewayChallengeCookie = "_gpx_ephor"
)

// GatewayChallengeConfig règle le défi à preuve de travail que la passerelle impose à une IP dont la note monte, à la
// place d'un refus (ADR 0020, étape 1.b).
type GatewayChallengeConfig struct {
	Difficulty  int      // bits de tête à zéro (défaut 16, max 24)
	TTL         string   // durée de la preuve, ex. "24h" (défaut 24 h)
	ExemptPaths []string // préfixes jamais défiés
	Secret      string   // signature, à partager entre les membres d'un groupe HA ; vide : propre à ce processus
}

// GatewayChallenge impose le défi existant (preuve de travail) sans que la route l'ait demandé. Il a son cookie et son URL
// de vérification : une route qui a son propre défi, à son propre secret, n'est pas dérangée.
type GatewayChallenge struct {
	c *botChallenge
}

func NewGatewayChallenge(cfg GatewayChallengeConfig) *GatewayChallenge {
	secret := cfg.Secret
	if secret == "" {
		secret = processBotSecret()
	}
	c := newBotChallenge(&router.BotConfig{
		ChallengeProvider:    "pow",
		ChallengeDifficulty:  cfg.Difficulty,
		ChallengeTTL:         cfg.TTL,
		ChallengeExemptPaths: cfg.ExemptPaths,
	}, secret)
	c.cookie, c.verifyPath = gatewayChallengeCookie, GatewayChallengePath
	return &GatewayChallenge{c: c}
}

// IsVerify : la requête apporte une solution du défi de la passerelle.
func (g *GatewayChallenge) IsVerify(r *http.Request) bool {
	return r.Method == http.MethodPost && r.URL.Path == GatewayChallengePath
}

// Verify contrôle la solution et pose le cookie de preuve. Faux si elle est refusée.
func (g *GatewayChallenge) Verify(w http.ResponseWriter, r *http.Request) bool {
	rec := &statusRecorder{ResponseWriter: w}
	g.c.handleVerify(rec, r)
	return rec.status == http.StatusNoContent
}

// HasProof : le client a déjà résolu le défi (cookie valide, lié à son IP et à son User-Agent).
func (g *GatewayChallenge) HasProof(r *http.Request) bool { return g.c.hasProof(r) }

// Serve répond à la place du backend avec la page de défi.
func (g *GatewayChallenge) Serve(w http.ResponseWriter, r *http.Request) { g.c.serve(w, r) }

// StripProof retire le cookie de preuve de la requête transmise au backend : il ne le concerne pas.
func (g *GatewayChallenge) StripProof(r *http.Request) {
	if strings.Contains(r.Header.Get("Cookie"), g.c.cookie) {
		stripCookie(r, g.c.cookie)
	}
}

// Applies : cette requête peut recevoir une page de défi. Seule une navigation (GET ou HEAD qui demande du HTML) le peut :
// un client d'API, une image ou une requête POST ne sauraient pas l'exécuter. Ils restent sur la voie du ban. Jamais les
// mises à niveau (WebSocket), les validations ACME, ni les chemins exemptés par la passerelle ou par la route.
func (g *GatewayChallenge) Applies(r *http.Request, route *router.Route) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if r.Header.Get("Upgrade") != "" {
		return false
	}
	p := r.URL.Path
	if strings.HasPrefix(p, "/.well-known/") || p == GatewayChallengePath || g.c.isExempt(p) {
		return false
	}
	if route != nil && route.Bot != nil && route.Bot.Enabled {
		if route.Bot.JSChallenge || strings.EqualFold(strings.TrimSpace(route.Bot.Mode), "challenge") {
			return false // la route défie déjà tous ses visiteurs
		}
		for _, e := range route.Bot.ChallengeExemptPaths {
			if e != "" && strings.HasPrefix(p, e) {
				return false
			}
		}
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html") || r.Header.Get("Sec-Fetch-Mode") == "navigate"
}

// statusRecorder retient le statut écrit par handleVerify sans changer ce qui part vers le client.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}
