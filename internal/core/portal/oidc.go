// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

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

	"github.com/vincamok/goproxify/internal/core/middleware"
	"github.com/vincamok/goproxify/internal/core/router"
	"github.com/vincamok/goproxify/internal/ssrf"
)

const (
	portalOIDCStateCookie = "_gpx_portal_oidc_state"
	portalOIDCCallback    = "/api/oidc/callback"
)

var oidcFormProviders = map[string]bool{
	"basic": true, "ldap": true, "ldap_ad": true,
}

func providerSupportsOIDC(sso *router.SSOConfig) bool {
	if sso == nil || sso.OIDC == nil {
		return false
	}
	if sso.OIDC.IssuerURL == "" || sso.OIDC.ClientID == "" {
		return false
	}
	p := strings.ToLower(sso.Provider)
	switch p {
	case "basic", "ldap", "ldap_ad", "forward", "github", "saml":
		return false
	default:
		return true // oidc, pocket_id, keycloak, authentik (mode OIDC), etc.
	}
}

func (h *HTTPServer) portalOIDCRedirectURI(sso *router.SSOConfig) string {
	if sso != nil && sso.OIDC != nil && strings.TrimSpace(sso.OIDC.RedirectURL) != "" {
		return strings.TrimSpace(sso.OIDC.RedirectURL)
	}
	host := strings.TrimSpace(h.cfg.PublicHost)
	if host == "" {
		return ""
	}
	return "https://" + host + portalOIDCCallback
}

func (h *HTTPServer) oidcSessionSecret(sso *router.SSOConfig) (string, error) {
	if sso != nil && sso.OIDC != nil && strings.TrimSpace(sso.OIDC.SessionSecret) != "" {
		return strings.TrimSpace(sso.OIDC.SessionSecret), nil
	}
	if strings.TrimSpace(h.masterSecret) != "" {
		return h.masterSecret, nil
	}
	return "", fmt.Errorf("OIDC: session_secret ou secret portal requis (pas de fallback)")
}

func (h *HTTPServer) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	sso, _, err := h.resolveSSO()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !providerSupportsOIDC(sso) {
		http.Error(w, "OIDC non configuré pour ce portail", http.StatusBadRequest)
		return
	}
	redirectURI := h.portalOIDCRedirectURI(sso)
	if redirectURI == "" {
		http.Error(w, "public_host ou oidc.redirect_url requis", http.StatusBadRequest)
		return
	}

	prov, err := newPortalOIDCProvider(sso.OIDC.IssuerURL)
	if err != nil {
		http.Error(w, "OIDC discovery: "+err.Error(), http.StatusBadGateway)
		return
	}

	state := randomB64(16)
	nonce := randomB64(16)
	statePayload, _ := json.Marshal(map[string]string{
		"state": state, "nonce": nonce,
	})
	secret, err := h.oidcSessionSecret(sso)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     portalOIDCStateCookie,
		Value:    base64.URLEncoding.EncodeToString(signHMAC(secret, statePayload)),
		Path:     "/",
		HttpOnly: true,
		MaxAge:   300,
		SameSite: http.SameSiteLaxMode,
		Secure:   strings.HasPrefix(redirectURI, "https://"),
	})

	scopes := sso.OIDC.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", sso.OIDC.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	http.Redirect(w, r, prov.authURL()+"?"+q.Encode(), http.StatusFound)
}

func (h *HTTPServer) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	sso, _, err := h.resolveSSO()
	if err != nil || !providerSupportsOIDC(sso) {
		http.Error(w, "OIDC non configuré", http.StatusBadRequest)
		return
	}
	redirectURI := h.portalOIDCRedirectURI(sso)
	secret, err := h.oidcSessionSecret(sso)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	ck, err := r.Cookie(portalOIDCStateCookie)
	if err != nil {
		http.Error(w, "OIDC: state cookie manquant", http.StatusBadRequest)
		return
	}
	raw, err := base64.URLEncoding.DecodeString(ck.Value)
	if err != nil {
		http.Error(w, "OIDC: state invalide", http.StatusBadRequest)
		return
	}
	payload := unsignHMAC(secret, raw)
	if payload == nil {
		http.Error(w, "OIDC: signature invalide", http.StatusBadRequest)
		return
	}
	var stateData map[string]string
	if json.Unmarshal(payload, &stateData) != nil {
		http.Error(w, "OIDC: state corrompu", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != stateData["state"] {
		http.Error(w, "OIDC: state mismatch", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		msg := r.URL.Query().Get("error_description")
		if msg == "" {
			msg = r.URL.Query().Get("error")
		}
		http.Error(w, "OIDC: "+msg, http.StatusBadRequest)
		return
	}

	prov, err := newPortalOIDCProvider(sso.OIDC.IssuerURL)
	if err != nil {
		http.Error(w, "OIDC discovery: "+err.Error(), http.StatusBadGateway)
		return
	}
	tr, err := prov.exchangeCode(r.Context(), sso.OIDC, redirectURI, code)
	if err != nil {
		http.Error(w, "OIDC token: "+err.Error(), http.StatusBadGateway)
		return
	}

	prov.mu.Lock()
	jwksURL, issuer := prov.JWKSURL, prov.Issuer
	prov.mu.Unlock()
	if issuer == "" {
		issuer = strings.TrimRight(sso.OIDC.IssuerURL, "/")
	}
	claims, err := middleware.VerifyOIDCIDToken(tr.IDToken, jwksURL, issuer, sso.OIDC.ClientID, stateData["nonce"], sso.OIDC.ClientSecret)
	if err != nil {
		http.Error(w, "OIDC: id_token invalide — "+err.Error(), http.StatusUnauthorized)
		return
	}
	claim := sso.OIDC.UsernameClaim
	if claim == "" {
		claim = "preferred_username"
	}
	username := middleware.ClaimString(claims, claim)
	if username == "" {
		username = middleware.ClaimString(claims, "email")
	}
	if username == "" {
		username = middleware.ClaimString(claims, "sub")
	}
	if username == "" {
		http.Error(w, "OIDC: username claim vide", http.StatusBadGateway)
		return
	}

	u, err := h.store.EnsureSSOUser(username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	key := DeriveSSOVaultKey(h.masterSecret, u.ID)
	if len(h.store.VaultBlob(u.ID)) == 0 {
		sealed, _ := SealVault(key, VaultPayload{})
		_ = h.store.SetVaultBlob(u.ID, sealed)
	}

	http.SetCookie(w, &http.Cookie{Name: portalOIDCStateCookie, Value: "", MaxAge: -1, Path: "/"})
	h.finishOIDCRedirect(w, r, u, key)
}

// finishOIDCRedirect applique les mêmes garde-fous que finishLogin, puis redirige
// vers le fragment #sso=… ou #sso_2fa=… (compatible navigateur après callback IdP).
func (h *HTTPServer) finishOIDCRedirect(w http.ResponseWriter, r *http.Request, u UserRecord, key [32]byte) {
	if u.Status == UserStatusDisabled {
		http.Error(w, "compte désactivé", http.StatusForbidden)
		return
	}
	require := h.cfg != nil && h.cfg.Require2FA
	has := UserHas2FA(u)
	if require && !has {
		http.Error(w, "2FA requise — activez TOTP ou OTP email avant de vous connecter", http.StatusForbidden)
		return
	}
	if has {
		ch := newMFAChallenge(u.ID, u.Username, key)
		h.challenges.Put(ch)
		methods := strings.Join(User2FAMethods(u), ",")
		http.Redirect(w, r, "/#sso_2fa="+url.QueryEscape(ch.ID)+
			"&user="+url.QueryEscape(u.Username)+
			"&methods="+url.QueryEscape(methods), http.StatusFound)
		return
	}
	tok, err := h.issueToken(u.ID, u.Username, key)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/#sso="+url.QueryEscape(tok), http.StatusFound)
}

type portalOIDCProvider struct {
	mu       sync.Mutex
	AuthURL  string
	TokenURL string
	JWKSURL  string
	Issuer   string
}

func newPortalOIDCProvider(issuer string) (*portalOIDCProvider, error) {
	issuer = strings.TrimRight(issuer, "/")
	if issuer == "" {
		return nil, fmt.Errorf("issuer_url vide")
	}
	p := &portalOIDCProvider{Issuer: issuer}
	well := issuer + "/.well-known/openid-configuration"
	if err := ssrf.ValidateHTTPURL(well, true); err != nil {
		return nil, fmt.Errorf("issuer URL: %w", err)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(well)
	if err != nil {
		p.AuthURL = issuer + "/authorize"
		p.TokenURL = issuer + "/token"
		return p, nil
	}
	defer resp.Body.Close()
	var doc struct {
		Issuer                string `json:"issuer"`
		AuthorizationEndpoint string `json:"authorization_endpoint"`
		TokenEndpoint         string `json:"token_endpoint"`
		JWKSURI               string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil || doc.AuthorizationEndpoint == "" {
		p.AuthURL = issuer + "/authorize"
		p.TokenURL = issuer + "/token"
		return p, nil
	}
	p.AuthURL = doc.AuthorizationEndpoint
	p.TokenURL = doc.TokenEndpoint
	p.JWKSURL = doc.JWKSURI
	if doc.Issuer != "" {
		p.Issuer = strings.TrimRight(doc.Issuer, "/")
	}
	return p, nil
}

func (p *portalOIDCProvider) authURL() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.AuthURL
}

type oidcTokenResp struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
}

func (p *portalOIDCProvider) exchangeCode(ctx context.Context, cfg *router.OIDCConfig, redirectURI, code string) (*oidcTokenResp, error) {
	p.mu.Lock()
	tokenURL := p.TokenURL
	p.mu.Unlock()
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", cfg.ClientID)
	form.Set("client_secret", cfg.ClientSecret)
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
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("%d %s", resp.StatusCode, b)
	}
	var tr oidcTokenResp
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, err
	}
	if tr.IDToken == "" {
		return nil, fmt.Errorf("id_token manquant")
	}
	return &tr, nil
}

func extractJWTClaim(idToken, claim string) string {
	if claim == "" {
		return ""
	}
	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return ""
	}
	payload := parts[1]
	for len(payload)%4 != 0 {
		payload += "="
	}
	b, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		b, err = base64.StdEncoding.DecodeString(payload)
		if err != nil {
			return ""
		}
	}
	var claims map[string]any
	if json.Unmarshal(b, &claims) != nil {
		return ""
	}
	if v, ok := claims[claim]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func signHMAC(secret string, payload []byte) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return append(mac.Sum(nil), payload...)
}

func unsignHMAC(secret string, data []byte) []byte {
	if len(data) < 32 {
		return nil
	}
	sig, payload := data[:32], data[32:]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil
	}
	return payload
}

func randomB64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
