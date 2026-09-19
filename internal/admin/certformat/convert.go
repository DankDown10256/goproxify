// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package certformat convertit des certificats PEM/clé stockés en DB vers les
// formats demandés par les clients (DER, PKCS#12, PEM fullchain, JSON…).
package certformat

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	goPKCS12 "software.sslmate.com/src/go-pkcs12"
)

// Format est l'identifiant du format de sortie.
type Format string

const (
	FormatPEM       Format = "pem"       // certificat seul (PEM)
	FormatKey       Format = "key"       // clé privée seule (PEM)
	FormatFullChain Format = "fullchain" // cert + clé concaténés (PEM)
	FormatDERCert   Format = "der"       // certificat seul (DER binaire)
	FormatDERKey    Format = "der_key"   // clé privée seule (DER/PKCS#8 binaire)
	FormatPKCS12    Format = "pkcs12"    // bundle PKCS#12 / PFX (password requis)
	FormatJSON      Format = "json"      // JSON {domain, cert_pem, key_pem, chain_pem}
)

// ValidFormats liste tous les formats supportés.
var ValidFormats = []Format{
	FormatPEM, FormatKey, FormatFullChain,
	FormatDERCert, FormatDERKey, FormatPKCS12, FormatJSON,
}

// Bundle regroupe les données converties et les métadonnées de livraison.
type Bundle struct {
	Data        []byte
	ContentType string
	Filename    string
}

// Convert convertit certPEM + keyPEM vers le format demandé.
// password est utilisé uniquement pour PKCS#12 (peut être vide → sans mot de passe).
func Convert(domain string, certPEM, keyPEM []byte, format Format, password string) (*Bundle, error) {
	switch format {
	case FormatPEM:
		return &Bundle{
			Data:        certPEM,
			ContentType: "application/x-pem-file",
			Filename:    domain + ".pem",
		}, nil

	case FormatKey:
		return &Bundle{
			Data:        keyPEM,
			ContentType: "application/x-pem-file",
			Filename:    domain + ".key",
		}, nil

	case FormatFullChain:
		full := append(certPEM, '\n')
		full = append(full, keyPEM...)
		return &Bundle{
			Data:        full,
			ContentType: "application/x-pem-file",
			Filename:    domain + "-fullchain.pem",
		}, nil

	case FormatDERCert:
		der, err := pemToDER(certPEM, "CERTIFICATE")
		if err != nil {
			return nil, fmt.Errorf("DER cert: %w", err)
		}
		return &Bundle{
			Data:        der,
			ContentType: "application/pkix-cert",
			Filename:    domain + ".crt",
		}, nil

	case FormatDERKey:
		der, err := keyPEMToDER(keyPEM)
		if err != nil {
			return nil, fmt.Errorf("DER key: %w", err)
		}
		return &Bundle{
			Data:        der,
			ContentType: "application/pkcs8",
			Filename:    domain + ".key.der",
		}, nil

	case FormatPKCS12:
		p12, err := buildPKCS12(certPEM, keyPEM, domain, password)
		if err != nil {
			return nil, fmt.Errorf("PKCS#12: %w", err)
		}
		return &Bundle{
			Data:        p12,
			ContentType: "application/x-pkcs12",
			Filename:    domain + ".p12",
		}, nil

	case FormatJSON:
		type payload struct {
			Domain   string `json:"domain"`
			CertPEM  string `json:"cert_pem"`
			KeyPEM   string `json:"key_pem"`
			ChainPEM string `json:"chain_pem"`
		}
		b, _ := json.Marshal(payload{
			Domain:   domain,
			CertPEM:  string(certPEM),
			KeyPEM:   string(keyPEM),
			ChainPEM: string(certPEM),
		})
		return &Bundle{
			Data:        b,
			ContentType: "application/json",
			Filename:    domain + "-cert.json",
		}, nil

	default:
		return nil, fmt.Errorf("format inconnu: %s", format)
	}
}

// IsValid retourne true si le format est supporté.
func IsValid(f string) bool {
	for _, v := range ValidFormats {
		if Format(f) == v {
			return true
		}
	}
	return false
}

// ── helpers ───────────────────────────────────────────────────────────────

func pemToDER(pemBytes []byte, blockType string) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("pas de bloc PEM trouvé")
	}
	if blockType != "" && block.Type != blockType {
		return nil, fmt.Errorf("type PEM inattendu: %s (attendu: %s)", block.Type, blockType)
	}
	return block.Bytes, nil
}

func keyPEMToDER(keyPEM []byte) ([]byte, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("pas de bloc PEM clé trouvé")
	}
	// Tente de parser comme clé générique puis convertit en PKCS#8 DER
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return x509.MarshalPKCS8PrivateKey(key)
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return x509.MarshalPKCS8PrivateKey(key)
	case "PRIVATE KEY":
		// déjà PKCS#8 DER
		return block.Bytes, nil
	default:
		// tentative générique
		return block.Bytes, nil
	}
}

func buildPKCS12(certPEMBytes, keyPEMBytes []byte, friendlyName, password string) ([]byte, error) {
	tlsCert, err := tls.X509KeyPair(certPEMBytes, keyPEMBytes)
	if err != nil {
		return nil, fmt.Errorf("X509KeyPair: %w", err)
	}
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse leaf: %w", err)
	}

	// Certs CA de la chaîne (tout sauf le leaf)
	var caCerts []*x509.Certificate
	for _, derCert := range tlsCert.Certificate[1:] {
		ca, err := x509.ParseCertificate(derCert)
		if err != nil {
			continue
		}
		caCerts = append(caCerts, ca)
	}

	// Récupère la clé privée parsée
	privKey := tlsCert.PrivateKey
	switch privKey.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		// ok
	default:
		return nil, fmt.Errorf("type de clé non supporté pour PKCS#12")
	}

	encoder := goPKCS12.Legacy
	return encoder.Encode(privKey, leaf, caCerts, password)
}
