// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
)

// oidcPresets mappe chaque provider à son IssuerURL par défaut.
// L'utilisateur peut toujours surcharger via cfg.OIDC.IssuerURL.
var oidcPresets = map[string]string{
	"google":    "https://accounts.google.com",
	"microsoft": "https://login.microsoftonline.com/{tenant}/v2.0",
	"entra":     "https://login.microsoftonline.com/{tenant}/v2.0",
	"auth0":     "https://{domain}.auth0.com",
	"okta":      "https://{domain}.okta.com",
	"keycloak":  "https://{host}/realms/{realm}",
	"zitadel":   "https://{host}",
	"casdoor":   "https://{host}",
	"dex":       "https://{host}/dex",
}

// SSOAuth retourne un middleware d'authentification SSO.
func SSOAuth(cfg *router.SSOConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil || !cfg.Enabled {
			return next
		}
		switch cfg.Provider {
		case "authentik", "authelia", "forward":
			return forwardAuthMiddleware(cfg, next)
		case "basic":
			return basicAuthMiddleware(cfg, next)
		case "github":
			return GitHubOAuth(cfg.GitHub)(next)
		case "ldap", "ldap_ad":
			return LDAPAuth(cfg.LDAP)(next)
		case "saml":
			return SAMLAuth(cfg.SAML)(next)
		case "pocket_id", "oidc",
			"google", "microsoft", "entra",
			"auth0", "okta", "keycloak", "zitadel",
			"casdoor", "dex":
			// Injecter l'IssuerURL du preset si absent
			if cfg.OIDC != nil && cfg.OIDC.IssuerURL == "" {
				if preset, ok := oidcPresets[cfg.Provider]; ok {
					cfg.OIDC.IssuerURL = preset
				}
			}
			return OIDCAuth(cfg)(next)
		default:
			return next
		}
	}
}

// forwardAuthMiddleware délègue l'authentification à un service externe.
// Compatible avec Authentik (outpost) et Authelia.
func forwardAuthMiddleware(cfg *router.SSOConfig, next http.Handler) http.Handler {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	headersToForward := cfg.HeadersToForward
	if len(headersToForward) == 0 {
		headersToForward = []string{
			"X-Remote-User", "X-Remote-Name", "X-Remote-Email",
			"X-Remote-Groups", "Remote-User", "Remote-Name", "Remote-Email",
		}
	}
	upstreamHeaders := []string{
		"Authorization", "Cookie", "X-Forwarded-For", "X-Real-IP",
		"X-Forwarded-Proto", "X-Forwarded-Host",
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, cfg.ForwardAuthURL, nil)
		if err != nil {
			http.Error(w, "SSO: erreur interne", http.StatusInternalServerError)
			return
		}
		for _, h := range upstreamHeaders {
			if v := r.Header.Get(h); v != "" {
				authReq.Header.Set(h, v)
			}
		}
		authReq.Header.Set("X-Original-URL", fmt.Sprintf("%s://%s%s", requestScheme(r), r.Host, r.RequestURI))
		authReq.Header.Set("X-Original-Method", r.Method)

		resp, err := client.Do(authReq)
		if err != nil {
			http.Error(w, "SSO: service injoignable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			for k, vs := range resp.Header {
				for _, v := range vs {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)
			return
		}
		for _, h := range headersToForward {
			if v := resp.Header.Get(h); v != "" {
				r.Header.Set(h, v)
			}
		}
		next.ServeHTTP(w, r)
	})
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		return proto
	}
	return "http"
}

func basicAuthMiddleware(cfg *router.SSOConfig, next http.Handler) http.Handler {
	realm := cfg.Realm
	if realm == "" {
		realm = "Goproxify"
	}
	users := make(map[string]string, len(cfg.BasicUsers))
	for _, u := range cfg.BasicUsers {
		users[u.Username] = u.Password
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := parseBasicAuth(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}
		expected, exists := users[user]
		if !exists || expected != pass {
			w.Header().Set("WWW-Authenticate", `Basic realm="`+realm+`"`)
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}
		r.Header.Set("X-Remote-User", user)
		next.ServeHTTP(w, r)
	})
}

func parseBasicAuth(r *http.Request) (user, pass string, ok bool) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Basic ") {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return "", "", false
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return parts[0], parts[1], true
}
