// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"html"
	"strings"
	"sync"
)

// Clés templates Access v1 (KTD2 / R20).
const (
	PageLogin         = "login"
	PageVerifyEmail   = "verify-email"
	PageSetPassword   = "set-password"
	Page2FAChallenge  = "2fa-challenge"
	PageCatalog       = "catalog"
	PageVault         = "vault"
	PageSessions      = "sessions"
	PageLayout        = "layout"
)

// PageTemplateKeys liste stable des pages éditables.
var PageTemplateKeys = []string{
	PageLogin, PageVerifyEmail, PageSetPassword, Page2FAChallenge,
	PageCatalog, PageVault, PageSessions, PageLayout,
}

// PageTemplate est un fragment HTML poussé depuis l'Admin.
type PageTemplate struct {
	Key  string `json:"key"`
	Name string `json:"name,omitempty"`
	Body string `json:"body"`
}

// PageVars variables injectées (KTD2).
type PageVars struct {
	Brand     string
	UserEmail string
	CoreName  string
	CSRF      string
	Content   string // HTML partiel — non échappé
}

// ApplyPageTemplate remplace {{brand}}, {{user_email}}, {{core_name}}, {{csrf}}, {{content}}.
func ApplyPageTemplate(body string, v PageVars) string {
	repl := map[string]string{
		"brand":      html.EscapeString(v.Brand),
		"user_email": html.EscapeString(v.UserEmail),
		"core_name":  html.EscapeString(v.CoreName),
		"csrf":       html.EscapeString(v.CSRF),
		"content":    v.Content,
	}
	out := body
	for key, val := range repl {
		out = strings.ReplaceAll(out, "{{"+key+"}}", val)
		out = strings.ReplaceAll(out, "{{ "+key+" }}", val)
	}
	return out
}

// IsKnownPageKey indique si la clé fait partie du catalogue v1.
func IsKnownPageKey(key string) bool {
	key = strings.TrimSpace(key)
	for _, k := range PageTemplateKeys {
		if k == key {
			return true
		}
	}
	return false
}

// DefaultPageFallback HTML minimal si template custom absent (hors SPA login).
func DefaultPageFallback(key string) string {
	switch key {
	case PageLayout:
		return `<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"/><title>{{brand}}</title></head><body>{{content}}</body></html>`
	case PageLogin:
		return `<section data-page="login"><h1>{{brand}}</h1><p>Connexion Access — {{core_name}}</p></section>`
	case PageVerifyEmail:
		return `<section data-page="verify-email"><h1>{{brand}}</h1><p>Vérifiez votre email.</p></section>`
	case PageSetPassword:
		return `<section data-page="set-password"><h1>{{brand}}</h1><p>Définir le mot de passe — {{user_email}}</p></section>`
	case Page2FAChallenge:
		return `<section data-page="2fa-challenge"><h1>{{brand}}</h1><p>Vérification 2FA</p></section>`
	case PageVault:
		return `<section data-page="vault"><h1>{{brand}}</h1><p>Coffre</p></section>`
	case PageSessions:
		return `<section data-page="sessions"><h1>{{brand}}</h1><p>Sessions</p></section>`
	case PageCatalog:
		return `<section data-page="catalog"><h1>{{brand}}</h1><p>Catalogue</p></section>`
	default:
		return `<section><h1>{{brand}}</h1></section>`
	}
}

// TemplateStore détient les templates custom en mémoire.
type TemplateStore struct {
	mu   sync.RWMutex
	byKey map[string]string
}

// NewTemplateStore crée un store vide.
func NewTemplateStore() *TemplateStore {
	return &TemplateStore{byKey: map[string]string{}}
}

// ReplaceAll remplace atomiquement toutes les pages (payload Admin).
func (s *TemplateStore) ReplaceAll(tpls []PageTemplate) {
	next := map[string]string{}
	for _, t := range tpls {
		key := strings.TrimSpace(t.Key)
		if !IsKnownPageKey(key) {
			continue
		}
		next[key] = t.Body
	}
	s.mu.Lock()
	s.byKey = next
	s.mu.Unlock()
}

// Get retourne le corps custom si présent et non vide.
func (s *TemplateStore) Get(key string) (string, bool) {
	if s == nil {
		return "", false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	body, ok := s.byKey[key]
	if !ok || strings.TrimSpace(body) == "" {
		return "", false
	}
	return body, true
}

// Snapshot copie la map courante.
func (s *TemplateStore) Snapshot() map[string]string {
	if s == nil {
		return map[string]string{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]string, len(s.byKey))
	for k, v := range s.byKey {
		out[k] = v
	}
	return out
}

// ResolvePage retourne le HTML final pour une clé : custom → fallback embarqué.
// Si useSPAFallback et clé login sans custom : false pour laisser servir la SPA.
func (s *TemplateStore) ResolvePage(key string, v PageVars, useSPAFallback bool) (htmlOut string, usedCustom bool) {
	if body, ok := s.Get(key); ok {
		return ApplyPageTemplate(body, v), true
	}
	if useSPAFallback && key == PageLogin {
		return "", false
	}
	return ApplyPageTemplate(DefaultPageFallback(key), v), false
}

// RenderIndex compose layout+login custom, ou login seul, ou indique SPA.
func (s *TemplateStore) RenderIndex(v PageVars) (htmlOut string, useSPA bool) {
	loginBody, loginCustom := s.Get(PageLogin)
	layoutBody, layoutCustom := s.Get(PageLayout)
	if !loginCustom {
		return "", true
	}
	inner := ApplyPageTemplate(loginBody, v)
	if layoutCustom {
		v2 := v
		v2.Content = inner
		return ApplyPageTemplate(layoutBody, v2), false
	}
	return inner, false
}
