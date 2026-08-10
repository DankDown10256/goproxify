// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
	"github.com/vincamok/goproxify/internal/ssrf"
)

const (
	oidcCallbackPath = "/_gpx/oidc/callback"
	oidcCookieName   = "_gpx_oidc"
	oidcStateCookie  = "_gpx_oidc_state"
)

// OIDCAuth retourne un middleware Authorization Code Flow pour Pocket ID et tout provider OIDC.
func OIDCAuth(cfg *router.SSOConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil || !cfg.Enabled || cfg.OIDC == nil {
			return next
		}
		p, err := newOIDCProvider(cfg.OIDC)
		if err != nil {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "OIDC: configuration invalide — "+err.Error(), http.StatusInternalServerError)
			})
		}
		return &oidcHandler{cfg: cfg.OIDC, provider: p, next: next}
	}
}

// --- Provider (discovery) ------------------------------------------------

type oidcProvider struct {
	AuthURL  string
	TokenURL string
	JWKSURL  string
	Issuer   string
	mu       sync.Mutex
}

func newOIDCProvider(cfg *router.OIDCConfig) (*oidcProvider, error) {
	issuer := strings.TrimRight(cfg.IssuerURL, "/")
	p := &oidcProvider{Issuer: issuer}
	if err := p.discover(issuer); err != nil {
		// Non bloquant au démarrage : on réessaiera au premier appel
		p.AuthURL = issuer + "/authorize"
		p.TokenURL = issuer + "/token"
		// JWKSURL laissé vide → RS* échoue tant que discovery n'a pas réussi
	}
	return p, nil
}

func (p *oidcProvider) discover(issuer string) error {
	well := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	if err := ssrf.ValidateHTTPURL(well, true); err != nil { // IdP souvent en LAN
		return fmt.Errorf("issuer URL: %w", err)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(well)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var doc struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JWKSURI               string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return err
	}
	if err := oidcEndpointsValid(doc.AuthorizationEndpoint, doc.TokenEndpoint); err != nil {
		return err
	}
	p.mu.Lock()
	p.AuthURL = doc.AuthorizationEndpoint
	p.TokenURL = doc.TokenEndpoint
	p.JWKSURL = doc.JWKSURI
	if doc.Issuer != "" {
		p.Issuer = strings.TrimRight(doc.Issuer, "/")
	}
	p.mu.Unlock()
	return nil
}

// oidcEndpointsValid refuse une discovery OpenID avec authorize/token vides (revue P1 #12).
func oidcEndpointsValid(authURL, tokenURL string) error {
	if strings.TrimSpace(authURL) == "" {
		return fmt.Errorf("oidc: authorization_endpoint manquant")
	}
	if strings.TrimSpace(tokenURL) == "" {
		return fmt.Errorf("oidc: token_endpoint manquant")
	}
	return nil
}

// --- Handler -------------------------------------------------------------

type oidcHandler struct {
	cfg      *router.OIDCConfig
	provider *oidcProvider
	next     http.Handler
}

func (h *oidcHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Callback OIDC
	if r.URL.Path == oidcCallbackPath {
		h.handleCallback(w, r)
		return
	}

	// Vérifie session
	if user := h.sessionUser(r); user != "" {
		r.Header.Set("X-Remote-User", user)
		h.next.ServeHTTP(w, r)
		return
	}

	// Lance le flux OIDC
	h.startFlow(w, r)
}

// startFlow redirige vers l'endpoint authorize du provider.
func (h *oidcHandler) startFlow(w http.ResponseWriter, r *http.Request) {
	state := randomBase64(16)
	nonce := randomBase64(16)
	// Sauvegardes state + URL originale dans un cookie signé
	statePayload, _ := json.Marshal(map[string]string{
		"state":    state,
		"nonce":    nonce,
		"redirect": r.URL.RequestURI(),
	})
	signed := h.sign(statePayload)
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookie,
		Value:    base64.URLEncoding.EncodeToString(signed),
		Path:     "/",
		HttpOnly: true,
		Secure:   CookieSecure(r),
		MaxAge:   300, // 5 min pour terminer le flux
		SameSite: http.SameSiteLaxMode,
	})

	scopes := h.cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}

	h.provider.mu.Lock()
	authURL := h.provider.AuthURL
	h.provider.mu.Unlock()

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", h.cfg.ClientID)
	q.Set("redirect_uri", h.cfg.RedirectURL)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	http.Redirect(w, r, authURL+"?"+q.Encode(), http.StatusFound)
}

// handleCallback échange le code et crée la session.
func (h *oidcHandler) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Vérifie le state via cookie signé
	stateCookie, err := r.Cookie(oidcStateCookie)
	if err != nil {
		http.Error(w, "OIDC: state cookie manquant", http.StatusBadRequest)
		return
	}
	raw, err := base64.URLEncoding.DecodeString(stateCookie.Value)
	if err != nil {
		http.Error(w, "OIDC: state invalide", http.StatusBadRequest)
		return
	}
	payload := h.unsign(raw)
	if payload == nil {
		http.Error(w, "OIDC: signature invalide", http.StatusBadRequest)
		return
	}
	var stateData map[string]string
	if err := json.Unmarshal(payload, &stateData); err != nil {
		http.Error(w, "OIDC: state corrompu", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != stateData["state"] {
		http.Error(w, "OIDC: state mismatch", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		errMsg := r.URL.Query().Get("error_description")
		if errMsg == "" {
			errMsg = r.URL.Query().Get("error")
		}
		http.Error(w, "OIDC: code manquant — "+errMsg, http.StatusBadRequest)
		return
	}

	// Échange code → tokens
	tokenResp, err := h.exchangeCode(r.Context(), code)
	if err != nil {
		http.Error(w, "OIDC: échange code échoué — "+err.Error(), http.StatusBadGateway)
		return
	}

	h.provider.mu.Lock()
	jwksURL, issuer := h.provider.JWKSURL, h.provider.Issuer
	h.provider.mu.Unlock()
	if issuer == "" {
		issuer = strings.TrimRight(h.cfg.IssuerURL, "/")
	}
	if jwksURL == "" && issuer != "" {
		_ = h.provider.discover(issuer)
		h.provider.mu.Lock()
		jwksURL = h.provider.JWKSURL
		if h.provider.Issuer != "" {
			issuer = h.provider.Issuer
		}
		h.provider.mu.Unlock()
	}
	claims, err := VerifyOIDCIDToken(tokenResp.IDToken, jwksURL, issuer, h.cfg.ClientID, stateData["nonce"], h.cfg.ClientSecret)
	if err != nil {
		http.Error(w, "OIDC: id_token invalide — "+err.Error(), http.StatusUnauthorized)
		return
	}
	claim := h.cfg.UsernameClaim
	if claim == "" {
		claim = "preferred_username"
	}
	username := ClaimString(claims, claim)
	if username == "" {
		username = ClaimString(claims, "email")
	}
	if username == "" {
		username = ClaimString(claims, "sub")
	}
	if username == "" {
		http.Error(w, "OIDC: username claim vide", http.StatusBadGateway)
		return
	}

	// Crée la session
	maxAge := h.cfg.SessionMaxAge
	if maxAge <= 0 {
		maxAge = 86400
	}
	session := sessionPayload{User: username, Exp: time.Now().Add(time.Duration(maxAge) * time.Second).Unix()}
	sessionBytes, _ := json.Marshal(session)
	http.SetCookie(w, &http.Cookie{
		Name:     oidcCookieName,
		Value:    base64.URLEncoding.EncodeToString(h.sign(sessionBytes)),
		Path:     "/",
		HttpOnly: true,
		Secure:   CookieSecure(r),
		MaxAge:   maxAge,
		SameSite: http.SameSiteLaxMode,
	})
	// Supprime le cookie state
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", MaxAge: -1, Path: "/", Secure: CookieSecure(r)})

	http.Redirect(w, r, SafeLocalRedirect(stateData["redirect"]), http.StatusFound)
}

// --- Token exchange -------------------------------------------------------

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

func (h *oidcHandler) exchangeCode(ctx context.Context, code string) (*tokenResponse, error) {
	h.provider.mu.Lock()
	tokenURL := h.provider.TokenURL
	h.provider.mu.Unlock()

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", h.cfg.RedirectURL)
	form.Set("client_id", h.cfg.ClientID)
	form.Set("client_secret", h.cfg.ClientSecret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("token endpoint: %d %s", resp.StatusCode, b)
	}
	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

// --- Session helpers ------------------------------------------------------

type sessionPayload struct {
	User string `json:"u"`
	Exp  int64  `json:"e"`
}

func (h *oidcHandler) sessionUser(r *http.Request) string {
	ck, err := r.Cookie(oidcCookieName)
	if err != nil {
		return ""
	}
	raw, err := base64.URLEncoding.DecodeString(ck.Value)
	if err != nil {
		return ""
	}
	payload := h.unsign(raw)
	if payload == nil {
		return ""
	}
	var s sessionPayload
	if err := json.Unmarshal(payload, &s); err != nil {
		return ""
	}
	if time.Now().Unix() > s.Exp {
		return ""
	}
	return s.User
}

// sign retourne HMAC-SHA256(secret, payload) || payload.
func (h *oidcHandler) sign(payload []byte) []byte {
	mac := hmac.New(sha256.New, []byte(h.cfg.SessionSecret))
	mac.Write(payload)
	sig := mac.Sum(nil)
	return append(sig, payload...)
}

// unsign vérifie la signature et retourne payload, ou nil si invalide.
func (h *oidcHandler) unsign(data []byte) []byte {
	if len(data) < 32 {
		return nil
	}
	sig := data[:32]
	payload := data[32:]
	mac := hmac.New(sha256.New, []byte(h.cfg.SessionSecret))
	mac.Write(payload)
	expected := mac.Sum(nil)
	if !hmac.Equal(sig, expected) {
		return nil
	}
	return payload
}

func randomBase64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
