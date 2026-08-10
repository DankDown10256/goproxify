// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"
	"time"

	xacme "golang.org/x/crypto/acme"

	coretls "github.com/vincamok/goproxify/internal/core/tls"
)

// CertPusher envoie le certificat déchiffré aux Cores.
type CertPusher interface {
	PushCert(ctx context.Context, name string, certPEM, keyPEM []byte)
}

// Manager gère l'obtention et le renouvellement des certificats Let's Encrypt.
type Manager struct {
	db       *sql.DB
	log      *slog.Logger
	pusher   CertPusher
	provider DNSProvider
	email    string
	// DirectoryURL vide → Let's Encrypt production.
	DirectoryURL string
}

// New crée un Manager ACME.
func New(db *sql.DB, log *slog.Logger, pusher CertPusher, provider DNSProvider, email string) *Manager {
	return &Manager{db: db, log: log, pusher: pusher, provider: provider, email: email}
}

// Start lance la goroutine de renouvellement automatique.
// Elle vérifie toutes les 12 h et renouvelle les certs expirant dans ≤ 30 j.
func (m *Manager) Start(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(12 * time.Hour)
		defer ticker.Stop()
		m.renewExpiring(ctx)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.renewExpiring(ctx)
			}
		}
	}()
}

// ObtainCertWithProvider demande un cert wildcard en utilisant un provider DNS dynamique.
// Les credentials du domaine priment ; les champs vides sont complétés depuis l'env Admin
// (ex. CF_API_TOKEN → api_token pour Cloudflare).
func (m *Manager) ObtainCertWithProvider(ctx context.Context, domain, dnsProviderType string, credentials map[string]any) error {
	if dnsProviderType == "" || dnsProviderType == "none" {
		return m.ObtainCert(ctx, domain)
	}
	params := mergeProviderParams(dnsProviderType, credentials)
	cfg := ProviderConfig{Type: dnsProviderType, Params: params}
	prov, err := NewProvider(cfg)
	if err != nil {
		return fmt.Errorf("acme: provider DNS %q : %w", dnsProviderType, err)
	}
	return m.obtainCertWithProv(ctx, domain, prov)
}

// mergeProviderParams : env Admin en base, credentials domaine non vides en surcharge.
func mergeProviderParams(dnsType string, credentials map[string]any) map[string]string {
	params := ProviderConfigFromEnv(dnsType).Params
	if params == nil {
		params = map[string]string{}
	}
	for k, v := range credentials {
		if s, ok := v.(string); ok && s != "" {
			params[k] = s
		}
	}
	return params
}

// ObtainCert demande un certificat wildcard pour le domaine donné via DNS-01.
func (m *Manager) ObtainCert(ctx context.Context, domain string) error {
	return m.obtainCertWithProv(ctx, domain, m.provider)
}

func (m *Manager) obtainCertWithProv(ctx context.Context, domain string, prov DNSProvider) error {
	// Conserve l'intention : "*.x" → wildcard seul ; "x" / "a.x" → ce nom exact.
	// Ne plus ajouter l'apex implicitement (deux TXT sur _acme-challenge → Incorrect TXT).
	names := acmeNames(domain)
	if len(names) == 0 {
		return fmt.Errorf("acme: domaine vide")
	}
	apex := strings.TrimPrefix(domain, "*.")

	accountKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("acme: génération clé compte : %w", err)
	}

	dir := m.DirectoryURL
	if dir == "" {
		dir = xacme.LetsEncryptURL
	}

	client := &xacme.Client{Key: accountKey, DirectoryURL: dir}
	acct := &xacme.Account{Contact: []string{"mailto:" + m.email}}
	if _, err := client.Register(ctx, acct, xacme.AcceptTOS); err != nil {
		return fmt.Errorf("acme: enregistrement compte : %w", err)
	}

	order, err := client.AuthorizeOrder(ctx, xacme.DomainIDs(names...))
	if err != nil {
		return fmt.Errorf("acme: autorisation commande : %w", err)
	}

	if err := m.fulfillAllDNS01(ctx, client, order.AuthzURLs, prov); err != nil {
		return err
	}

	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("acme: génération clé cert : %w", err)
	}

	csr, err := buildCSR(names, certKey)
	if err != nil {
		return fmt.Errorf("acme: CSR : %w", err)
	}

	der, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return fmt.Errorf("acme: création cert : %w", err)
	}

	certPEM := encodeCertChain(der)
	keyPEM, err := encodeECKey(certKey)
	if err != nil {
		return fmt.Errorf("acme: encodage clé : %w", err)
	}

	leaf, err := x509.ParseCertificate(der[0])
	if err != nil {
		return fmt.Errorf("acme: parse cert : %w", err)
	}

	// Clé DB = nom ACME demandé (apex et wildcard sont des lignes distinctes).
	certName := names[0]
	if err := m.saveCertMeta(certName, "letsencrypt", leaf.NotAfter, certPEM, keyPEM); err != nil {
		m.log.Error("acme: sauvegarde méta cert", "domain", certName, "err", err)
	}

	if m.pusher != nil {
		for _, n := range coretls.PushNames(certName, certPEM) {
			m.pusher.PushCert(ctx, n, certPEM, keyPEM)
		}
	}

	m.log.Info("acme: certificat obtenu", "names", names, "apex", apex, "expires", leaf.NotAfter)
	return nil
}

// acmeNames dérive les identifiants ACME depuis le domaine saisi (sans forcer l'apex).
func acmeNames(domain string) []string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil
	}
	return []string{domain}
}

type dns01Challenge struct {
	authURL string
	domain  string // apex sans "*."
	chal    *xacme.Challenge
	txt     string
}

// fulfillAllDNS01 pose tous les TXT DNS-01, attend la propagation, puis valide.
func (m *Manager) fulfillAllDNS01(ctx context.Context, client *xacme.Client, authURLs []string, prov DNSProvider) error {
	var pending []dns01Challenge
	cleanupDomains := map[string]struct{}{}

	for _, authURL := range authURLs {
		auth, err := client.GetAuthorization(ctx, authURL)
		if err != nil {
			return fmt.Errorf("acme: get auth : %w", err)
		}
		if auth.Status == "valid" {
			continue
		}
		var chal *xacme.Challenge
		for _, c := range auth.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			return fmt.Errorf("acme: pas de challenge dns-01 pour %s", auth.Identifier.Value)
		}
		txt, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return fmt.Errorf("acme: calcul keyAuth : %w", err)
		}
		apex := strings.TrimPrefix(auth.Identifier.Value, "*.")
		pending = append(pending, dns01Challenge{authURL: authURL, domain: apex, chal: chal, txt: txt})
		cleanupDomains[apex] = struct{}{}
	}
	if len(pending) == 0 {
		return nil
	}

	// Nettoyer d'éventuels TXT périmés, puis poser tous les records de cette commande.
	for d := range cleanupDomains {
		_ = prov.DeleteTXTRecord(ctx, d)
	}
	for _, p := range pending {
		if err := prov.SetTXTRecord(ctx, p.domain, p.txt); err != nil {
			return fmt.Errorf("acme: SetTXTRecord : %w", err)
		}
	}
	defer func() {
		for d := range cleanupDomains {
			_ = prov.DeleteTXTRecord(ctx, d)
		}
	}()

	// Propagation DNS (TTL Cloudflare souvent 60 s)
	time.Sleep(60 * time.Second)

	for _, p := range pending {
		if _, err := client.Accept(ctx, p.chal); err != nil {
			return fmt.Errorf("acme: accept challenge : %w", err)
		}
	}
	for _, p := range pending {
		if _, err := client.WaitAuthorization(ctx, p.authURL); err != nil {
			return fmt.Errorf("acme: wait auth : %w", err)
		}
	}
	return nil
}

func (m *Manager) renewExpiring(ctx context.Context) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT domain FROM certs WHERE expires_at <= datetime('now', '+30 days') AND issuer='letsencrypt'`)
	if err != nil {
		m.log.Error("acme: lecture certs à renouveler", "err", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			continue
		}
		m.log.Info("acme: renouvellement", "domain", domain)
		if err := m.ObtainCert(ctx, domain); err != nil {
			m.log.Error("acme: renouvellement échoué", "domain", domain, "err", err)
		}
	}
}

func (m *Manager) saveCertMeta(domain, issuer string, expiresAt time.Time, certPEM, keyPEM []byte) error {
	_, err := m.db.Exec(
		`INSERT INTO certs (id, domain, issuer, expires_at, cert_pem, key_pem)
		 VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?, ?)
		 ON CONFLICT(domain) DO UPDATE SET
		   issuer=excluded.issuer, expires_at=excluded.expires_at,
		   cert_pem=excluded.cert_pem, key_pem=excluded.key_pem,
		   updated_at=CURRENT_TIMESTAMP`,
		domain, issuer, expiresAt, string(certPEM), string(keyPEM),
	)
	if err != nil {
		return err
	}
	// Uniquement le domaine dont le nom ACME correspond (ne pas marquer apex + wildcard d'un seul coup).
	_, _ = m.db.Exec(
		`UPDATE domains SET cert_expires_at=?, updated_at=CURRENT_TIMESTAMP WHERE domain=?`,
		expiresAt, domain,
	)
	return nil
}

// --- Helpers PEM ------------------------------------------------------------

func buildCSR(names []string, key crypto.Signer) ([]byte, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("acme: aucun nom pour le CSR")
	}
	tpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: names[0]},
		DNSNames: names,
	}
	return x509.CreateCertificateRequest(rand.Reader, tpl, key)
}

func encodeCertChain(der [][]byte) []byte {
	var buf []byte
	for _, d := range der {
		buf = append(buf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	return buf
}

func encodeECKey(key *ecdsa.PrivateKey) ([]byte, error) {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), nil
}
