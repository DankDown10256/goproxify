// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
)

const (
	githubCallbackPath = "/_gpx/github/callback"
	githubCookieName   = "_gpx_github"
	githubStateCookie  = "_gpx_github_state"
)

// GitHubOAuth retourne un middleware OAuth2 GitHub.
func GitHubOAuth(cfg *router.GitHubOAuthConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil {
			return next
		}
		return &githubHandler{cfg: cfg, next: next}
	}
}

type githubHandler struct {
	cfg  *router.GitHubOAuthConfig
	next http.Handler
}

func (h *githubHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == githubCallbackPath {
		h.handleCallback(w, r)
		return
	}

	if user := h.sessionUser(r); user != "" {
		r.Header.Set("X-Remote-User", user)
		h.next.ServeHTTP(w, r)
		return
	}

	h.startFlow(w, r)
}

func (h *githubHandler) startFlow(w http.ResponseWriter, r *http.Request) {
	state := randomBase64(16)
	payload, _ := json.Marshal(map[string]string{"state": state, "redirect": r.URL.RequestURI()})
	signed := cookieSign(h.cfg.SessionSecret, payload)
	http.SetCookie(w, &http.Cookie{
		Name:     githubStateCookie,
		Value:    base64.URLEncoding.EncodeToString(signed),
		Path:     "/",
		HttpOnly: true,
		Secure:   CookieSecure(r),
		MaxAge:   300,
		SameSite: http.SameSiteLaxMode,
	})

	scopes := "read:user,user:email"
	if len(h.cfg.AllowedOrgs) > 0 || len(h.cfg.AllowedTeams) > 0 {
		scopes += ",read:org"
	}

	q := url.Values{}
	q.Set("client_id", h.cfg.ClientID)
	q.Set("redirect_uri", h.cfg.RedirectURL)
	q.Set("scope", scopes)
	q.Set("state", state)
	http.Redirect(w, r, "https://github.com/login/oauth/authorize?"+q.Encode(), http.StatusFound)
}

func (h *githubHandler) handleCallback(w http.ResponseWriter, r *http.Request) {
	// Vérifier le state
	stateCookie, err := r.Cookie(githubStateCookie)
	if err != nil {
		http.Error(w, "GitHub OAuth: state manquant", http.StatusBadRequest)
		return
	}
	raw, err := base64.URLEncoding.DecodeString(stateCookie.Value)
	if err != nil {
		http.Error(w, "GitHub OAuth: state invalide", http.StatusBadRequest)
		return
	}
	statePayload := cookieUnsign(h.cfg.SessionSecret, raw)
	if statePayload == nil {
		http.Error(w, "GitHub OAuth: signature invalide", http.StatusBadRequest)
		return
	}
	var stateData map[string]string
	json.Unmarshal(statePayload, &stateData) //nolint:errcheck
	if r.URL.Query().Get("state") != stateData["state"] {
		http.Error(w, "GitHub OAuth: state mismatch", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "GitHub OAuth: code manquant", http.StatusBadRequest)
		return
	}

	// Échange code → access token
	token, err := h.exchangeCode(r.Context(), code)
	if err != nil {
		http.Error(w, "GitHub OAuth: échange code échoué — "+err.Error(), http.StatusBadGateway)
		return
	}

	// Récupérer l'utilisateur GitHub
	login, email, err := h.fetchUser(r.Context(), token)
	if err != nil {
		http.Error(w, "GitHub OAuth: profil inaccessible", http.StatusBadGateway)
		return
	}

	// Vérifier les restrictions org/team
	if len(h.cfg.AllowedOrgs) > 0 || len(h.cfg.AllowedTeams) > 0 {
		if err := h.checkMembership(r.Context(), token, login); err != nil {
			http.Error(w, "GitHub OAuth: accès refusé — "+err.Error(), http.StatusForbidden)
			return
		}
	}

	maxAge := h.cfg.SessionMaxAge
	if maxAge <= 0 {
		maxAge = 86400
	}
	type ghSess struct {
		User  string `json:"u"`
		Email string `json:"e,omitempty"`
		Exp   int64  `json:"x"`
	}
	b, _ := json.Marshal(ghSess{User: login, Email: email,
		Exp: time.Now().Add(time.Duration(maxAge) * time.Second).Unix()})
	signed := cookieSign(h.cfg.SessionSecret, b)
	http.SetCookie(w, &http.Cookie{
		Name:     githubCookieName,
		Value:    base64.URLEncoding.EncodeToString(signed),
		Path:     "/",
		HttpOnly: true,
		Secure:   CookieSecure(r),
		MaxAge:   maxAge,
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{Name: githubStateCookie, MaxAge: -1, Path: "/", Secure: CookieSecure(r)})

	http.Redirect(w, r, SafeLocalRedirect(stateData["redirect"]), http.StatusFound)
}

func (h *githubHandler) sessionUser(r *http.Request) string {
	ck, err := r.Cookie(githubCookieName)
	if err != nil {
		return ""
	}
	raw, err := base64.URLEncoding.DecodeString(ck.Value)
	if err != nil {
		return ""
	}
	payload := cookieUnsign(h.cfg.SessionSecret, raw)
	if payload == nil {
		return ""
	}
	var s struct {
		User string `json:"u"`
		Exp  int64  `json:"x"`
	}
	if err := json.Unmarshal(payload, &s); err != nil || time.Now().Unix() > s.Exp {
		return ""
	}
	return s.User
}

func (h *githubHandler) exchangeCode(ctx context.Context, code string) (string, error) {
	body := url.Values{
		"client_id":     {h.cfg.ClientID},
		"client_secret": {h.cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {h.cfg.RedirectURL},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://github.com/login/oauth/access_token",
		strings.NewReader(body.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if result.Error != "" {
		return "", fmt.Errorf("%s", result.Error)
	}
	return result.AccessToken, nil
}

func (h *githubHandler) fetchUser(ctx context.Context, token string) (login, email string, err error) {
	doGet := func(path string, dest any) error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com"+path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		return json.NewDecoder(resp.Body).Decode(dest)
	}

	var user struct {
		Login string `json:"login"`
		Email string `json:"email"`
	}
	if err := doGet("/user", &user); err != nil {
		return "", "", err
	}
	login = user.Login
	email = user.Email

	// Si email non public → chercher dans /user/emails
	if email == "" {
		var emails []struct {
			Email   string `json:"email"`
			Primary bool   `json:"primary"`
		}
		if err := doGet("/user/emails", &emails); err == nil {
			for _, e := range emails {
				if e.Primary {
					email = e.Email
					break
				}
			}
		}
	}
	return login, email, nil
}

func (h *githubHandler) checkMembership(ctx context.Context, token, login string) error {
	client := &http.Client{Timeout: 10 * time.Second}

	// Vérifier les orgs
	for _, org := range h.cfg.AllowedOrgs {
		u := fmt.Sprintf("https://api.github.com/orgs/%s/members/%s", org, login)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusNoContent {
				return nil // membre de l'org → accès OK
			}
		}
	}

	// Vérifier les teams (format "org/team")
	for _, team := range h.cfg.AllowedTeams {
		parts := strings.SplitN(team, "/", 2)
		if len(parts) != 2 {
			continue
		}
		u := fmt.Sprintf("https://api.github.com/orgs/%s/teams/%s/memberships/%s", parts[0], parts[1], login)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/vnd.github+json")
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
	}

	return fmt.Errorf("non membre des orgs/teams autorisés")
}
