// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// VerifyOIDCIDToken valide un id_token OIDC : signature (JWKS RS* ou HS* client_secret),
// issuer, audience (client_id) et nonce.
func VerifyOIDCIDToken(raw, jwksURL, issuer, audience, expectedNonce, clientSecret string) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("oidc: id_token format invalide")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("oidc: header: %w", err)
	}
	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("oidc: header JSON: %w", err)
	}
	if header.Alg == "" || header.Alg == "none" {
		return nil, fmt.Errorf("oidc: algorithme interdit")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("oidc: payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("oidc: payload JSON: %w", err)
	}
	msg := []byte(parts[0] + "." + parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("oidc: signature: %w", err)
	}

	switch {
	case strings.HasPrefix(header.Alg, "RS"):
		if strings.TrimSpace(jwksURL) == "" {
			return nil, fmt.Errorf("oidc: jwks_uri requis pour %s", header.Alg)
		}
		cache := &jwksCache{url: jwksURL, client: &http.Client{Timeout: 10 * time.Second}}
		pub, err := cache.get(header.Kid)
		if err != nil {
			return nil, err
		}
		if err := verifyRSA(header.Alg, pub, msg, sig); err != nil {
			return nil, fmt.Errorf("oidc: signature invalide: %w", err)
		}
	case strings.HasPrefix(header.Alg, "HS"):
		if strings.TrimSpace(clientSecret) == "" {
			return nil, fmt.Errorf("oidc: client_secret requis pour %s", header.Alg)
		}
		if err := verifyHMACJWT(header.Alg, clientSecret, msg, sig); err != nil {
			return nil, fmt.Errorf("oidc: signature invalide: %w", err)
		}
	default:
		return nil, fmt.Errorf("oidc: algorithme non supporté: %s", header.Alg)
	}

	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, fmt.Errorf("oidc: id_token expiré")
		}
	}
	issuer = strings.TrimRight(strings.TrimSpace(issuer), "/")
	if issuer != "" {
		iss, _ := claims["iss"].(string)
		if strings.TrimRight(iss, "/") != issuer {
			return nil, fmt.Errorf("oidc: issuer invalide")
		}
	}
	if audience != "" && !checkAudience(claims["aud"], audience) {
		return nil, fmt.Errorf("oidc: audience invalide")
	}
	if expectedNonce != "" {
		nonce, _ := claims["nonce"].(string)
		if nonce != expectedNonce {
			return nil, fmt.Errorf("oidc: nonce mismatch")
		}
	}
	return claims, nil
}

func verifyHMACJWT(alg, secret string, msg, sig []byte) error {
	var h func() hash.Hash
	switch alg {
	case "HS256":
		h = sha256.New
	case "HS384":
		h = sha512.New384
	case "HS512":
		h = sha512.New
	default:
		return fmt.Errorf("hmac alg: %s", alg)
	}
	mac := hmac.New(h, []byte(secret))
	mac.Write(msg)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return fmt.Errorf("hmac mismatch")
	}
	return nil
}

// ClaimString extrait un claim string depuis un map de claims JWT.
func ClaimString(claims map[string]any, key string) string {
	if claims == nil || key == "" {
		return ""
	}
	if v, ok := claims[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

// SafeLocalRedirect n'autorise que des chemins relatifs same-origin (/…),
// refuse //evil, URLs absolues et schémas.
func SafeLocalRedirect(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "/"
	}
	if strings.HasPrefix(raw, "//") || strings.HasPrefix(raw, "\\\\") {
		return "/"
	}
	if strings.Contains(raw, "://") {
		return "/"
	}
	if strings.ContainsAny(raw, "\r\n") {
		return "/"
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "/"
	}
	if u.Scheme != "" || u.Host != "" || u.User != nil {
		return "/"
	}
	if u.Path == "" {
		return "/"
	}
	if !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	out := u.Path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		out += "#" + u.Fragment
	}
	return out
}
