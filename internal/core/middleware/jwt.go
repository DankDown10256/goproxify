// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
)

// jwtContextKey est le type du contexte pour les claims.
type jwtContextKey struct{}

// JWTValidation retourne un middleware de validation JWT via JWKS.
func JWTValidation(cfg *router.JWTConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil || !cfg.Enabled {
			return next
		}
		cache := &jwksCache{url: cfg.JWKSURL, client: &http.Client{Timeout: 10 * time.Second}}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := extractBearerToken(r, cfg.HeaderName)
			if raw == "" {
				http.Error(w, `{"error":"missing token"}`, http.StatusUnauthorized)
				return
			}
			claims, err := validateJWT(raw, cache, cfg.Issuer, cfg.Audience)
			if err != nil {
				http.Error(w, `{"error":"invalid token"}`, http.StatusUnauthorized)
				return
			}
			if cfg.ClaimsHeader != "" {
				claimsJSON, _ := json.Marshal(claims)
				r.Header.Set(cfg.ClaimsHeader, string(claimsJSON))
			}
			ctx := context.WithValue(r.Context(), jwtContextKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func extractBearerToken(r *http.Request, headerName string) string {
	if headerName != "" {
		return r.Header.Get(headerName)
	}
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return auth[7:]
	}
	return ""
}

// --- JWKS cache -------------------------------------------------------------

type jwksCache struct {
	url    string
	client *http.Client
	mu     sync.RWMutex
	keys   map[string]*rsa.PublicKey
	expiry time.Time
}

func (c *jwksCache) get(kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	fresh := time.Now().Before(c.expiry)
	cached := c.keys[kid]
	c.mu.RUnlock()
	if fresh && cached != nil {
		return cached, nil
	}
	if err := c.refresh(); err != nil {
		// Revue P2 #13 : servir la clé encore en cache si le refresh JWKS échoue.
		c.mu.RLock()
		defer c.mu.RUnlock()
		if k := c.keys[kid]; k != nil {
			return k, nil
		}
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	k := c.keys[kid]
	if k == nil {
		return nil, fmt.Errorf("jwt: kid=%q introuvable dans JWKS", kid)
	}
	return k, nil
}

type jwksDoc struct {
	Keys []jwkKey `json:"keys"`
}

type jwkKey struct {
	Kid string   `json:"kid"`
	Kty string   `json:"kty"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

func (c *jwksCache) refresh() error {
	resp, err := c.client.Get(c.url)
	if err != nil {
		return fmt.Errorf("jwks: fetch: %w", err)
	}
	defer resp.Body.Close()
	var doc jwksDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return fmt.Errorf("jwks: decode: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := jwkKeyToRSA(k)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}
	c.mu.Lock()
	c.keys = keys
	c.expiry = time.Now().Add(5 * time.Minute)
	c.mu.Unlock()
	return nil
}

func jwkKeyToRSA(k jwkKey) (*rsa.PublicKey, error) {
	if len(k.X5c) > 0 {
		der, err := base64.StdEncoding.DecodeString(k.X5c[0])
		if err != nil {
			return nil, err
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("jwks: x5c: pas RSA")
		}
		return pub, nil
	}
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("jwks: n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("jwks: e: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())
	return &rsa.PublicKey{N: n, E: e}, nil
}

// --- Validation JWT ---------------------------------------------------------

func validateJWT(raw string, cache *jwksCache, issuer, audience string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jwt: format invalide")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwt: header: %w", err)
	}
	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("jwt: header JSON: %w", err)
	}
	alg := strings.TrimSpace(header.Alg)
	if alg == "" || strings.EqualFold(alg, "none") {
		return nil, fmt.Errorf("jwt: algorithme non supporté: %q", header.Alg)
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt: payload: %w", err)
	}
	sigData, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jwt: sig: %w", err)
	}
	msg := []byte(parts[0] + "." + parts[1])

	// Vérifier la signature avant de faire confiance aux claims (revue P0 #1).
	switch {
	case strings.HasPrefix(alg, "RS"):
		if cache == nil || strings.TrimSpace(cache.url) == "" {
			return nil, fmt.Errorf("jwt: jwks_url requis pour %s", alg)
		}
		pub, err := cache.get(header.Kid)
		if err != nil {
			return nil, err
		}
		if err := verifyRSA(alg, pub, msg, sigData); err != nil {
			return nil, fmt.Errorf("jwt: signature invalide: %w", err)
		}
	case strings.HasPrefix(alg, "HS"):
		// JWTValidation ne configure pas de secret HMAC : HS* non supporté ici.
		return nil, fmt.Errorf("jwt: algorithme non supporté: %s", alg)
	default:
		return nil, fmt.Errorf("jwt: algorithme non supporté: %s", alg)
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("jwt: payload JSON: %w", err)
	}
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, fmt.Errorf("jwt: token expiré")
		}
	}
	if issuer != "" {
		if iss, _ := claims["iss"].(string); iss != issuer {
			return nil, fmt.Errorf("jwt: issuer invalide")
		}
	}
	if audience != "" {
		if !checkAudience(claims["aud"], audience) {
			return nil, fmt.Errorf("jwt: audience invalide")
		}
	}
	return claims, nil
}

func verifyRSA(alg string, pub *rsa.PublicKey, msg, sig []byte) error {
	var hashID crypto.Hash
	var digest []byte
	switch alg {
	case "RS256":
		hashID = crypto.SHA256
		h := sha256.Sum256(msg)
		digest = h[:]
	case "RS384":
		hashID = crypto.SHA384
		h := sha512.New384()
		h.Write(msg)
		digest = h.Sum(nil)
	case "RS512":
		hashID = crypto.SHA512
		h := sha512.New()
		h.Write(msg)
		digest = h.Sum(nil)
	default:
		return fmt.Errorf("jwt: algorithme non supporté: %s", alg)
	}
	return rsa.VerifyPKCS1v15(pub, hashID, digest, sig)
}

func checkAudience(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// parsePEMPublicKey parse une clé publique PEM RSA.
func parsePEMPublicKey(pemData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("jwt: PEM invalide")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("jwt: pas RSA")
	}
	return rsaPub, nil
}

var _ = parsePEMPublicKey
