// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package internalca génère et gère une autorité de certification interne
// (root CA) pour émettre des certificats serveur/client internes, hors ACME.
package internalca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Manager gère la CA interne : création de racines, émission et révocation de certificats.
type Manager struct {
	db      *sql.DB
	log     *slog.Logger
	certDir string // répertoire de persistance des clés/certs sur disque (certs/internal-ca/)
}

func New(db *sql.DB, log *slog.Logger) *Manager {
	return &Manager{db: db, log: log}
}

// SetCertDir configure le répertoire de persistance sur disque.
func (m *Manager) SetCertDir(dir string) {
	m.certDir = dir
}

// CA représente une autorité de certification interne.
type CA struct {
	ID        string
	Name      string
	Subject   string
	CertPEM   string
	NotAfter  time.Time
	CreatedAt time.Time
}

// IssuedCert représente un certificat émis par une CA interne.
type IssuedCert struct {
	ID         string
	CAID       string
	CommonName string
	Usage      string // "server" ou "client"
	SANs       []string
	Serial     string
	CertPEM    string
	NotAfter   time.Time
	Revoked    bool
	CreatedAt  time.Time
}

// CreateCA génère une nouvelle autorité racine (clé ECDSA P-256, auto-signée)
// et persiste la clé privée sur disque et le certificat en DB.
func (m *Manager) CreateCA(ctx context.Context, name, commonName string, validity time.Duration) (*CA, error) {
	if name == "" {
		return nil, fmt.Errorf("internalca: nom requis")
	}
	if validity <= 0 {
		validity = 10 * 365 * 24 * time.Hour
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("internalca: génération clé CA: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	notAfter := now.Add(validity)
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"GoProxify Internal CA"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("internalca: création certificat racine: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM, err := encodeECKey(key)
	if err != nil {
		return nil, err
	}

	id := randomID()
	if err := m.writeCAKeyFiles(id, certPEM, keyPEM); err != nil {
		return nil, err
	}
	if _, err := m.db.ExecContext(ctx,
		`INSERT INTO internal_ca (id, name, subject, cert_pem, not_after) VALUES (?, ?, ?, ?, ?)`,
		id, name, commonName, string(certPEM), notAfter,
	); err != nil {
		return nil, fmt.Errorf("internalca: insertion DB: %w", err)
	}
	return &CA{ID: id, Name: name, Subject: commonName, CertPEM: string(certPEM), NotAfter: notAfter, CreatedAt: now}, nil
}

// IssueCert émet un certificat feuille (serveur ou client) signé par la CA identifiée par caID.
func (m *Manager) IssueCert(ctx context.Context, caID, commonName string, sans []string, usage string, validity time.Duration) (*IssuedCert, error) {
	if usage != "server" && usage != "client" {
		return nil, fmt.Errorf("internalca: usage invalide %q (server|client)", usage)
	}
	if validity <= 0 {
		validity = 397 * 24 * time.Hour // ~13 mois, borne CA/Browser Forum pour les certs serveur
	}
	caKey, caCert, err := m.loadCAKeyPair(ctx, caID)
	if err != nil {
		return nil, err
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("internalca: génération clé: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	notAfter := now.Add(validity)
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     notAfter,
	}
	for _, san := range sans {
		if ip := parseIP(san); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, san)
		}
	}
	switch usage {
	case "server":
		tpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	case "client":
		tpl.KeyUsage = x509.KeyUsageDigitalSignature
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("internalca: signature certificat: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM, err := encodeECKey(key)
	if err != nil {
		return nil, err
	}

	id := randomID()
	if err := m.writeIssuedCertFiles(caID, id, certPEM, keyPEM); err != nil {
		return nil, err
	}
	sansJSON := jsonStrings(sans)
	if _, err := m.db.ExecContext(ctx,
		`INSERT INTO internal_ca_certs (id, ca_id, common_name, usage, sans_json, serial, cert_pem, not_after)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, caID, commonName, usage, sansJSON, serial.String(), string(certPEM), notAfter,
	); err != nil {
		return nil, fmt.Errorf("internalca: insertion DB: %w", err)
	}
	return &IssuedCert{
		ID: id, CAID: caID, CommonName: commonName, Usage: usage, SANs: sans,
		Serial: serial.String(), CertPEM: string(certPEM), NotAfter: notAfter, CreatedAt: now,
	}, nil
}

// RevokeCert marque un certificat émis comme révoqué.
func (m *Manager) RevokeCert(ctx context.Context, certID string) error {
	_, err := m.db.ExecContext(ctx, `UPDATE internal_ca_certs SET revoked = 1 WHERE id = ?`, certID)
	return err
}

// ListCAs liste les autorités internes.
func (m *Manager) ListCAs(ctx context.Context) ([]CA, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT id, name, subject, cert_pem, not_after, created_at FROM internal_ca ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CA
	for rows.Next() {
		var c CA
		if err := rows.Scan(&c.ID, &c.Name, &c.Subject, &c.CertPEM, &c.NotAfter, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListCerts liste les certificats émis par une CA.
func (m *Manager) ListCerts(ctx context.Context, caID string) ([]IssuedCert, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, ca_id, common_name, usage, sans_json, serial, cert_pem, not_after, revoked, created_at
		 FROM internal_ca_certs WHERE ca_id = ? ORDER BY created_at DESC`, caID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IssuedCert
	for rows.Next() {
		var c IssuedCert
		var sansJSON string
		var revoked int
		if err := rows.Scan(&c.ID, &c.CAID, &c.CommonName, &c.Usage, &sansJSON, &c.Serial, &c.CertPEM, &c.NotAfter, &revoked, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.SANs = parseJSONStrings(sansJSON)
		c.Revoked = revoked != 0
		out = append(out, c)
	}
	return out, rows.Err()
}

// --- Persistance disque -----------------------------------------------------

func (m *Manager) caDir(caID string) string {
	return filepath.Join(m.certDir, "internal-ca", caID)
}

func (m *Manager) writeCAKeyFiles(caID string, certPEM, keyPEM []byte) error {
	if m.certDir == "" {
		return fmt.Errorf("internalca: certDir non configuré")
	}
	dir := m.caDir(caID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("internalca: création répertoire CA: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), certPEM, 0o600); err != nil {
		return fmt.Errorf("internalca: écriture ca.crt: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), keyPEM, 0o600); err != nil {
		return fmt.Errorf("internalca: écriture ca.key: %w", err)
	}
	return nil
}

func (m *Manager) writeIssuedCertFiles(caID, certID string, certPEM, keyPEM []byte) error {
	if m.certDir == "" {
		return fmt.Errorf("internalca: certDir non configuré")
	}
	dir := filepath.Join(m.caDir(caID), "certs")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("internalca: création répertoire certs: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, certID+".crt"), certPEM, 0o600); err != nil {
		return fmt.Errorf("internalca: écriture cert: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, certID+".key"), keyPEM, 0o600); err != nil {
		return fmt.Errorf("internalca: écriture clé: %w", err)
	}
	return nil
}

func (m *Manager) loadCAKeyPair(ctx context.Context, caID string) (*ecdsa.PrivateKey, *x509.Certificate, error) {
	var exists int
	if err := m.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM internal_ca WHERE id = ?`, caID).Scan(&exists); err != nil {
		return nil, nil, err
	}
	if exists == 0 {
		return nil, nil, fmt.Errorf("internalca: CA %q introuvable", caID)
	}
	keyPEM, err := os.ReadFile(filepath.Join(m.caDir(caID), "ca.key"))
	if err != nil {
		return nil, nil, fmt.Errorf("internalca: lecture clé CA: %w", err)
	}
	certPEM, err := os.ReadFile(filepath.Join(m.caDir(caID), "ca.crt"))
	if err != nil {
		return nil, nil, fmt.Errorf("internalca: lecture certificat CA: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("internalca: clé CA illisible")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("internalca: parsing clé CA: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("internalca: certificat CA illisible")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("internalca: parsing certificat CA: %w", err)
	}
	return key, cert, nil
}

// --- Helpers -----------------------------------------------------------------

func randomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

func encodeECKey(key *ecdsa.PrivateKey) ([]byte, error) {
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b}), nil
}

func jsonStrings(ss []string) string {
	if len(ss) == 0 {
		return "[]"
	}
	quoted := make([]string, len(ss))
	for i, s := range ss {
		quoted[i] = `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
	}
	return "[" + strings.Join(quoted, ",") + "]"
}

func parseIP(s string) net.IP {
	return net.ParseIP(s)
}

func parseJSONStrings(s string) []string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.TrimPrefix(p, `"`)
		p = strings.TrimSuffix(p, `"`)
		out = append(out, strings.ReplaceAll(p, `\"`, `"`))
	}
	return out
}
