// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/vincamok/goproxify/internal/core/router"
)

const samlSessionCookie = "_gpx_saml"

// SAMLAuth retourne un middleware SAML 2.0 Service Provider.
func SAMLAuth(cfg *router.SAMLConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil {
			return next
		}
		sp, err := newSAMLSP(cfg)
		if err != nil {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "SAML: configuration invalide — "+err.Error(), http.StatusInternalServerError)
			})
		}
		return &samlHandler{cfg: cfg, sp: sp, next: next}
	}
}

type samlHandler struct {
	cfg  *router.SAMLConfig
	sp   *samlsp.Middleware
	next http.Handler
}

func (h *samlHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	acsPath := h.cfg.ACSPath
	if acsPath == "" {
		acsPath = "/saml/acs"
	}
	metaPath := h.cfg.MetadataPath
	if metaPath == "" {
		metaPath = "/saml/metadata"
	}

	switch r.URL.Path {
	case metaPath:
		b, err := xml.MarshalIndent(h.sp.ServiceProvider.Metadata(), "", "  ")
		if err != nil {
			http.Error(w, "SAML: métadonnées", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		w.Write(b) //nolint:errcheck
		return
	case acsPath:
		h.handleACS(w, r)
		return
	}

	if user := h.sessionUser(r); user != "" {
		r.Header.Set("X-Remote-User", user)
		h.next.ServeHTTP(w, r)
		return
	}
	h.sp.HandleStartAuthFlow(w, r)
}

func (h *samlHandler) handleACS(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "SAML: formulaire invalide", http.StatusBadRequest)
		return
	}
	assertion, err := h.sp.ServiceProvider.ParseResponse(r, nil)
	if err != nil {
		http.Error(w, "SAML: assertion invalide — "+err.Error(), http.StatusForbidden)
		return
	}

	user, email, groups := samlExtractAttrs(assertion, h.cfg)

	if len(h.cfg.AllowedGroups) > 0 && !ldapInAllowedGroup(h.cfg.AllowedGroups, groups) {
		http.Error(w, "SAML: groupe non autorisé", http.StatusForbidden)
		return
	}

	maxAge := h.cfg.SessionMaxAge
	if maxAge <= 0 {
		maxAge = 86400
	}
	type sess struct {
		User  string `json:"u"`
		Email string `json:"e,omitempty"`
		Exp   int64  `json:"x"`
	}
	b, _ := json.Marshal(sess{User: user, Email: email,
		Exp: time.Now().Add(time.Duration(maxAge) * time.Second).Unix()})
	signed := cookieSign(h.cfg.SessionSecret, b)
	http.SetCookie(w, &http.Cookie{
		Name:     samlSessionCookie,
		Value:    base64.URLEncoding.EncodeToString(signed),
		Path:     "/",
		HttpOnly: true,
		Secure:   CookieSecure(r),
		MaxAge:   maxAge,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, "/", http.StatusFound)
}

func (h *samlHandler) sessionUser(r *http.Request) string {
	ck, err := r.Cookie(samlSessionCookie)
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

func samlExtractAttrs(assertion *saml.Assertion, cfg *router.SAMLConfig) (user, email string, groups []string) {
	usernameAttr := cfg.UsernameAttr
	if usernameAttr == "" {
		usernameAttr = "uid"
	}
	emailAttr := cfg.EmailAttr
	if emailAttr == "" {
		emailAttr = "mail"
	}
	groupsAttr := cfg.GroupsAttr
	if groupsAttr == "" {
		groupsAttr = "memberOf"
	}

	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			val := ""
			if len(attr.Values) > 0 {
				val = attr.Values[0].Value
			}
			switch attr.Name {
			case usernameAttr:
				user = val
			case emailAttr:
				email = val
			case groupsAttr:
				for _, v := range attr.Values {
					groups = append(groups, v.Value)
				}
			}
		}
	}
	if user == "" && assertion.Subject != nil && assertion.Subject.NameID != nil {
		user = assertion.Subject.NameID.Value
	}
	return
}

// newSAMLSP instancie le middleware samlsp.
func newSAMLSP(cfg *router.SAMLConfig) (*samlsp.Middleware, error) {
	if cfg.CertPEM == "" || cfg.KeyPEM == "" {
		return nil, fmt.Errorf("cert_pem et key_pem sont requis")
	}
	cert, err := tls.X509KeyPair([]byte(cfg.CertPEM), []byte(cfg.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("paire de clés invalide : %w", err)
	}
	if cert.Leaf == nil {
		if block, _ := pem.Decode([]byte(cfg.CertPEM)); block != nil {
			cert.Leaf, _ = x509.ParseCertificate(block.Bytes)
		}
	}

	rootURL, err := url.Parse(cfg.EntityID)
	if err != nil {
		return nil, fmt.Errorf("entity_id invalide : %w", err)
	}
	rootURL = &url.URL{Scheme: rootURL.Scheme, Host: rootURL.Host}

	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("clé privée ne supporte pas crypto.Signer")
	}
	opts := samlsp.Options{
		URL:         *rootURL,
		Key:         signer,
		Certificate: cert.Leaf,
		EntityID:    cfg.EntityID,
	}

	if cfg.IDPMetadataURL != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		idpMeta, err := samlsp.FetchMetadata(ctx, &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
		}, *must(url.Parse(cfg.IDPMetadataURL)))
		if err != nil {
			return nil, fmt.Errorf("métadonnées IdP : %w", err)
		}
		opts.IDPMetadata = idpMeta
	} else if cfg.IDPMetadataXML != "" {
		var meta saml.EntityDescriptor
		if err := xml.Unmarshal([]byte(cfg.IDPMetadataXML), &meta); err != nil {
			return nil, fmt.Errorf("XML métadonnées IdP : %w", err)
		}
		opts.IDPMetadata = &meta
	} else {
		return nil, fmt.Errorf("idp_metadata_url ou idp_metadata_xml requis")
	}

	return samlsp.New(opts)
}

func must(u *url.URL, _ error) *url.URL { return u }
