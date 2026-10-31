// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package launcher

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/vincamok/goproxify/internal/pairing"
)

// Secrets sont les secrets de l'installation. Seul l'Admin reçoit le secret racine : les passerelles et les Agents
// reçoivent les clés qui en sont dérivées (ADR 0015).
type Secrets struct {
	JWT           string
	Root          string
	AdminPassword string
	// Backup chiffre la partie secrets des sauvegardes de l'Admin (GPX_BACKUP_KEY). Sans elle une sauvegarde sort sans
	// secrets, donc sans de quoi reconstruire l'Admin ; il faut la garder hors de l'Admin pour relire une sauvegarde.
	Backup string
}

// NewSecrets tire un secret racine, un secret JWT et une clé de sauvegarde. Un mot de passe vide en génère un.
func NewSecrets(adminPassword string) (*Secrets, error) {
	jwt, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	root, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	backup, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	if adminPassword == "" {
		if adminPassword, err = randomHex(10); err != nil {
			return nil, err
		}
	}
	return &Secrets{JWT: jwt, Root: root, AdminPassword: adminPassword, Backup: backup}, nil
}

// AgentKey est la clé d'appairage des Agents.
func (s *Secrets) AgentKey() string { return pairing.AgentKey(s.Root) }

// EdgeChannelKey est la clé du canal Admin → passerelle d'une passerelle, d'après l'identifiant de son nœud (dn_…) : l'Admin
// essaie celle-là en premier, et elle survit à un renommage.
func (s *Secrets) EdgeChannelKey(nodeID string) string {
	return pairing.EdgeChannelKey(s.Root, nodeID)
}

// PortalKey est la clé maître du portail Access d'une passerelle ; les membres d'un groupe HA partagent la même, elle
// est donc dérivée du groupe quand il y en a un.
func (s *Secrets) PortalKey(scope string) string {
	sum := sha256.Sum256([]byte("goproxify/portal-master/v1:" + scope + ":" + s.Root))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("tirage aléatoire : %w", err)
	}
	return hex.EncodeToString(b), nil
}

// AdminCert est le certificat TLS de l'Admin, auto-signé : son empreinte, donnée par un autre canal (le QR code), est ce
// qui permet à un hôte qui rejoint de savoir à quel Admin il parle (ADR 0019, section 5).
type AdminCert struct {
	CertPEM     string
	KeyPEM      string
	Fingerprint string // SHA-256 du certificat DER, en hexadécimal minuscule
}

// NewAdminCert crée un certificat valable deux ans pour les adresses données (IP ou noms DNS).
func NewAdminCert(hosts []string, now time.Time) (*AdminCert, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("clé du certificat : %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	if err != nil {
		return nil, fmt.Errorf("numéro de série : %w", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "GoProxify Admin", Organization: []string{"GoProxify"}},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	seen := map[string]bool{}
	for _, h := range hosts {
		if h == "" || seen[h] {
			continue
		}
		seen[h] = true
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("certificat : %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("clé privée : %w", err)
	}
	sum := sha256.Sum256(der)
	return &AdminCert{
		CertPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		KeyPEM:      string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
		Fingerprint: hex.EncodeToString(sum[:]),
	}, nil
}
