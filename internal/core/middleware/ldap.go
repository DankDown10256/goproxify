// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/vincamok/goproxify/internal/core/router"
)

const ldapCookieName = "_gpx_ldap"

// LDAPAuth retourne un middleware d'authentification LDAP / Active Directory.
// L'utilisateur saisit ses identifiants via Basic Auth → le middleware effectue un bind LDAP.
func LDAPAuth(cfg *router.LDAPConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// 1. Session cookie existante ?
			if user, name, email := ldapSessionGet(r, cfg.SessionSecret); user != "" {
				r.Header.Set("X-Remote-User", user)
				if name != "" {
					r.Header.Set("X-Remote-Name", name)
				}
				if email != "" {
					r.Header.Set("X-Remote-Email", email)
				}
				next.ServeHTTP(w, r)
				return
			}

			// 2. Credentials Basic Auth
			username, password, ok := parseBasicAuth(r)
			if !ok {
				w.Header().Set("WWW-Authenticate", `Basic realm="LDAP"`)
				http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
				return
			}

			// 3. Authentification LDAP
			displayName, email, err := ldapAuthenticate(cfg, username, password)
			if err != nil {
				w.Header().Set("WWW-Authenticate", `Basic realm="LDAP"`)
				http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
				return
			}

			// 4. Écrire la session cookie
			maxAge := cfg.SessionMaxAge
			if maxAge <= 0 {
				maxAge = 86400
			}
			ldapSessionSet(w, r, cfg.SessionSecret, username, displayName, email, maxAge)

			r.Header.Set("X-Remote-User", username)
			if displayName != "" {
				r.Header.Set("X-Remote-Name", displayName)
			}
			if email != "" {
				r.Header.Set("X-Remote-Email", email)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// --- session helpers ---------------------------------------------------------

type ldapSession struct {
	User  string `json:"u"`
	Name  string `json:"n,omitempty"`
	Email string `json:"e,omitempty"`
	Exp   int64  `json:"x"`
}

func ldapSessionSet(w http.ResponseWriter, r *http.Request, secret, user, name, email string, maxAge int) {
	sess := ldapSession{User: user, Name: name, Email: email,
		Exp: time.Now().Add(time.Duration(maxAge) * time.Second).Unix()}
	b, _ := json.Marshal(sess)
	http.SetCookie(w, &http.Cookie{
		Name:     ldapCookieName,
		Value:    base64.URLEncoding.EncodeToString(cookieSign(secret, b)),
		Path:     "/",
		HttpOnly: true,
		Secure:   CookieSecure(r),
		MaxAge:   maxAge,
		SameSite: http.SameSiteLaxMode,
	})
}

func ldapSessionGet(r *http.Request, secret string) (user, name, email string) {
	ck, err := r.Cookie(ldapCookieName)
	if err != nil {
		return "", "", ""
	}
	raw, err := base64.URLEncoding.DecodeString(ck.Value)
	if err != nil {
		return "", "", ""
	}
	payload := cookieUnsign(secret, raw)
	if payload == nil {
		return "", "", ""
	}
	var s ldapSession
	if err := json.Unmarshal(payload, &s); err != nil || time.Now().Unix() > s.Exp {
		return "", "", ""
	}
	return s.User, s.Name, s.Email
}

// cookieSign / cookieUnsign : HMAC-SHA256(secret, payload) || payload
func cookieSign(secret string, payload []byte) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return append(mac.Sum(nil), payload...)
}

func cookieUnsign(secret string, data []byte) []byte {
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

// LDAPAuthenticate vérifie username/password contre un annuaire LDAP/AD.
// Exposé pour le portail d'accès et autres surfaces hors middleware HTTP.
func LDAPAuthenticate(cfg *router.LDAPConfig, username, password string) (displayName, email string, err error) {
	return ldapAuthenticate(cfg, username, password)
}

// --- LDAP authentication -----------------------------------------------------

func ldapAuthenticate(cfg *router.LDAPConfig, username, password string) (displayName, email string, err error) {
	if password == "" {
		return "", "", fmt.Errorf("ldap: mot de passe vide")
	}

	conn, err := ldapDial(cfg)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()

	// Bind service account
	if cfg.BindDN != "" {
		if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
			return "", "", fmt.Errorf("ldap: bind service account : %w", err)
		}
	}

	// Attributs à récupérer
	usernameAttr := cfg.UsernameAttr
	if usernameAttr == "" {
		usernameAttr = "sAMAccountName"
	}
	emailAttr := cfg.EmailAttr
	if emailAttr == "" {
		emailAttr = "mail"
	}

	// Filtre de recherche
	userFilter := cfg.UserFilter
	if userFilter == "" {
		userFilter = "(|(sAMAccountName=%s)(uid=%s))"
	}
	esc := ldap.EscapeFilter(username)
	filter := fmt.Sprintf(userFilter, esc, esc)

	searchReq := ldap.NewSearchRequest(
		cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, 10, false,
		filter,
		[]string{"dn", usernameAttr, emailAttr, "displayName", "cn", "memberOf"},
		nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil || len(result.Entries) == 0 {
		return "", "", fmt.Errorf("ldap: utilisateur introuvable")
	}
	entry := result.Entries[0]

	// Bind utilisateur → vérifie le mot de passe
	if err := conn.Bind(entry.DN, password); err != nil {
		return "", "", fmt.Errorf("ldap: authentification échouée")
	}

	// Vérifier les groupes si restreint
	if len(cfg.AllowedGroups) > 0 {
		memberOf := entry.GetAttributeValues("memberOf")
		if !ldapInAllowedGroup(cfg.AllowedGroups, memberOf) {
			return "", "", fmt.Errorf("ldap: groupe non autorisé")
		}
	}

	displayName = entry.GetAttributeValue("displayName")
	if displayName == "" {
		displayName = entry.GetAttributeValue("cn")
	}
	email = entry.GetAttributeValue(emailAttr)
	return displayName, email, nil
}

func ldapDial(cfg *router.LDAPConfig) (*ldap.Conn, error) {
	if strings.HasPrefix(cfg.URL, "ldaps://") {
		tlsCfg := &tls.Config{InsecureSkipVerify: cfg.TLSSkipVerify} //nolint:gosec
		return ldap.DialURL(cfg.URL, ldap.DialWithTLSConfig(tlsCfg))
	}
	conn, err := ldap.DialURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("ldap: connexion : %w", err)
	}
	// STARTTLS optionnel si demandé
	if cfg.TLSSkipVerify {
		_ = conn.StartTLS(&tls.Config{InsecureSkipVerify: true}) //nolint:gosec
	}
	return conn, nil
}

func ldapInAllowedGroup(allowed, memberOf []string) bool {
	for _, g := range allowed {
		for _, m := range memberOf {
			if strings.EqualFold(m, g) ||
				strings.Contains(strings.ToLower(m), strings.ToLower("CN="+g+",")) {
				return true
			}
		}
	}
	return false
}
