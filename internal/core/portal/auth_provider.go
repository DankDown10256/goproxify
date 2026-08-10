// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/vincamok/goproxify/internal/core/middleware"
	"github.com/vincamok/goproxify/internal/core/router"
)

// AuthProviderLookup résout un fournisseur Auth Admin/Core par ID.
type AuthProviderLookup interface {
	Get(idOrName string) (*router.AuthProvider, bool)
}

// DeriveSSOVaultKey dérive une clé vault stable pour un user SSO (pas de mot de passe local).
func DeriveSSOVaultKey(masterSecret, userID string) [32]byte {
	return DeriveVaultKey(userID, "sso:"+masterSecret)
}

// resolveSSO charge la SSOConfig du fournisseur configuré (nil si absent).
func (h *HTTPServer) resolveSSO() (*router.SSOConfig, *router.AuthProvider, error) {
	id := strings.TrimSpace(h.cfg.AuthProviderID)
	if id == "" || h.providers == nil {
		return nil, nil, nil
	}
	p, ok := h.providers.Get(id)
	if !ok {
		return nil, nil, fmt.Errorf("auth_provider %q introuvable", id)
	}
	var sso router.SSOConfig
	if len(p.Config) > 0 {
		if err := json.Unmarshal(p.Config, &sso); err != nil {
			return nil, p, fmt.Errorf("config auth_provider invalide: %w", err)
		}
	}
	if sso.Provider == "" {
		sso.Provider = p.Type
	}
	sso.Enabled = true
	return &sso, p, nil
}

// authenticateProvider valide username/password via basic ou LDAP.
// Retourne (ok, err). err non nil = config/infra ; ok=false = mauvais identifiants.
func authenticateProvider(sso *router.SSOConfig, username, password string) (bool, error) {
	if sso == nil {
		return false, nil
	}
	switch strings.ToLower(sso.Provider) {
	case "basic":
		for _, u := range sso.BasicUsers {
			if u.Username != username {
				continue
			}
			if matchBasicPassword(u.Password, password) {
				return true, nil
			}
		}
		return false, nil
	case "ldap", "ldap_ad":
		if sso.LDAP == nil {
			return false, fmt.Errorf("ldap: config absente")
		}
		_, _, err := middleware.LDAPAuthenticate(sso.LDAP, username, password)
		if err != nil {
			return false, nil // mauvais login / groupe → 401, pas 500
		}
		return true, nil
	default:
		return false, fmt.Errorf("auth_provider type %q : utilisez Connexion SSO (OIDC) ou un provider basic/ldap", sso.Provider)
	}
}

// providerSupportsForm indique si le fournisseur accepte username/password.
func providerSupportsForm(sso *router.SSOConfig) bool {
	if sso == nil {
		return false
	}
	return oidcFormProviders[strings.ToLower(sso.Provider)]
}

// matchBasicPassword accepte bcrypt ($2a$/$2b$/$2y$) ou plaintext legacy (comparaison constant-time).
func matchBasicPassword(stored, password string) bool {
	stored = strings.TrimSpace(stored)
	if stored == "" {
		return false
	}
	if strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") || strings.HasPrefix(stored, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(password)) == 1
}
