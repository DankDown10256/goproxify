// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
)

// CachedCert conserve un certificat et sa clé privée sous forme PEM.
// Le champ KeyPEM est inclus uniquement dans le cache chiffré AES-256-GCM du Core.
type CachedCert struct {
	Name    string `json:"name"`
	CertPEM []byte `json:"cert_pem"`
	KeyPEM  []byte `json:"key_pem"`
}

// CertStore conserve les certificats TLS en RAM uniquement.
// GetCertificate est passé directement au tls.Config — aucune écriture disque en clair.
type CertStore struct {
	mu    sync.RWMutex
	certs map[string]*tls.Certificate
	pems  map[string]CachedCert // PEM originaux pour export dans le cache chiffré
}

func NewCertStore() *CertStore {
	return &CertStore{
		certs: make(map[string]*tls.Certificate),
		pems:  make(map[string]CachedCert),
	}
}

// Store ajoute ou remplace un certificat (sans conservation des PEM originaux).
func (s *CertStore) Store(name string, cert *tls.Certificate) {
	s.mu.Lock()
	s.certs[name] = cert
	s.mu.Unlock()
}

// StorePEM parse et stocke un certificat PEM + clé privée PEM.
// Les PEM originaux sont conservés en RAM pour export dans le cache chiffré.
func (s *CertStore) StorePEM(name string, certPEM, keyPEM []byte) error {
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("parsing certificat %q : %w", name, err)
	}
	s.mu.Lock()
	s.certs[name] = &cert
	s.pems[name] = CachedCert{Name: name, CertPEM: certPEM, KeyPEM: keyPEM}
	s.mu.Unlock()
	return nil
}

// Delete supprime un certificat.
func (s *CertStore) Delete(name string) {
	s.mu.Lock()
	delete(s.certs, name)
	delete(s.pems, name)
	s.mu.Unlock()
}

// AllPEMs retourne tous les certificats avec leurs clés privées PEM.
// Utilisé exclusivement pour la sauvegarde dans le cache chiffré AES-256-GCM.
func (s *CertStore) AllPEMs() []CachedCert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]CachedCert, 0, len(s.pems))
	for _, c := range s.pems {
		result = append(result, c)
	}
	return result
}

// Names retourne les noms de tous les certificats stockés.
func (s *CertStore) Names() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.certs))
	for n := range s.certs {
		names = append(names, n)
	}
	return names
}

// Len retourne le nombre de certificats.
func (s *CertStore) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.certs)
}

// GetCertificate implémente tls.Config.GetCertificate.
// Résolution par ServerName exact, puis par wildcard (*.example.fr).
func (s *CertStore) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName
	s.mu.RLock()
	defer s.mu.RUnlock()

	if c, ok := s.certs[name]; ok {
		return c, nil
	}
	// Essai wildcard : *.example.fr pour sub.example.fr
	if len(name) > 0 {
		if dot := indexOf(name, '.'); dot >= 0 {
			wild := "*" + name[dot:]
			if c, ok := s.certs[wild]; ok {
				return c, nil
			}
		}
	}
	// Essai wildcard apex : *.example.com pour vincz.fr (cert wildcard couvre aussi l'apex)
	if c, ok := s.certs["*."+name]; ok {
		return c, nil
	}
	return nil, fmt.Errorf("aucun certificat pour %q", name)
}

func indexOf(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

// DNSNamesFromPEM extrait les SAN DNS du certificat feuille.
func DNSNamesFromPEM(certPEM []byte) []string {
	var names []string
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		names = append(names, cert.DNSNames...)
		break // feuille uniquement
	}
	return names
}

// PushNames retourne les clés sous lesquelles stocker/pousser un certificat.
// Les SAN du PEM font foi ; à défaut on utilise le nom stocké en DB.
func PushNames(dbDomain string, certPEM []byte) []string {
	seen := make(map[string]struct{})
	var out []string
	add := func(n string) {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			return
		}
		if _, ok := seen[n]; ok {
			return
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	for _, n := range DNSNamesFromPEM(certPEM) {
		add(n)
	}
	if len(out) == 0 {
		add(dbDomain)
	}
	return out
}
