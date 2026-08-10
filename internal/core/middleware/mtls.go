// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/vincamok/goproxify/internal/core/router"
)

// MTLSValidation retourne un middleware de validation mTLS.
func MTLSValidation(cfg *router.MTLSConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil || !cfg.Enabled {
			return next
		}
		pool, err := buildCAPool(cfg)
		if err != nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
				if cfg.RequireClientCert {
					http.Error(w, "mTLS: certificat client requis", http.StatusUnauthorized)
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			leaf := r.TLS.PeerCertificates[0]
			opts := x509.VerifyOptions{
				Roots:     pool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			}
			if _, err := leaf.Verify(opts); err != nil {
				http.Error(w, "mTLS: certificat client invalide", http.StatusUnauthorized)
				return
			}
			if len(cfg.AllowedSANs) > 0 && !matchSANs(leaf, cfg.AllowedSANs) {
				http.Error(w, "mTLS: SAN non autorisé", http.StatusForbidden)
				return
			}
			if cfg.SubjectHeader != "" {
				r.Header.Set(cfg.SubjectHeader, leaf.Subject.String())
			}
			next.ServeHTTP(w, r)
		})
	}
}

// TLSConfigWithClientAuth retourne une config TLS avec mTLS activé.
func TLSConfigWithClientAuth(cfg *router.MTLSConfig) (*tls.Config, error) {
	if cfg == nil || !cfg.Enabled {
		return &tls.Config{MinVersion: tls.VersionTLS12}, nil
	}
	pool, err := buildCAPool(cfg)
	if err != nil {
		return nil, err
	}
	authType := tls.RequireAndVerifyClientCert
	if !cfg.RequireClientCert {
		authType = tls.RequestClientCert
	}
	return &tls.Config{
		ClientCAs:  pool,
		ClientAuth: authType,
		MinVersion: tls.VersionTLS12,
	}, nil
}

func buildCAPool(cfg *router.MTLSConfig) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	var pemData []byte
	if cfg.CACertPEM != "" {
		pemData = []byte(cfg.CACertPEM)
	} else if cfg.CACertFile != "" {
		var err error
		pemData, err = os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("mtls: lecture CA: %w", err)
		}
	} else {
		return nil, fmt.Errorf("mtls: aucun CA configuré")
	}
	for len(pemData) > 0 {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		pool.AddCert(cert)
	}
	return pool, nil
}

func matchSANs(cert *x509.Certificate, allowed []string) bool {
	for _, san := range allowed {
		for _, dns := range cert.DNSNames {
			if matchWildcard(dns, san) {
				return true
			}
		}
		for _, ip := range cert.IPAddresses {
			if ip.String() == san {
				return true
			}
		}
		for _, email := range cert.EmailAddresses {
			if email == san {
				return true
			}
		}
	}
	return false
}

func matchWildcard(name, pattern string) bool {
	if !strings.HasPrefix(pattern, "*.") {
		return name == pattern
	}
	suffix := pattern[1:]
	return strings.HasSuffix(name, suffix)
}
