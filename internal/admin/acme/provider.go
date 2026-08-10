// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package acme gère l'obtention et le renouvellement des certificats Let's Encrypt
// pour l'Administration via ACME DNS-01 (wildcards).
// Les clés privées ne sont jamais écrites en base — elles sont poussées en RAM vers les Cores.
package acme

import (
	"context"
	"fmt"
)

// DNSProvider sait écrire et supprimer un enregistrement TXT DNS.
type DNSProvider interface {
	SetTXTRecord(ctx context.Context, domain, value string) error
	DeleteTXTRecord(ctx context.Context, domain string) error
}

// ProviderConfig contient les paramètres d'un fournisseur DNS.
type ProviderConfig struct {
	Type   string            `json:"type"`
	Params map[string]string `json:"params"`
}

// NewProvider instancie le bon fournisseur selon le type.
func NewProvider(cfg ProviderConfig) (DNSProvider, error) {
	switch cfg.Type {
	case "ovh":
		return newOVHProvider(cfg.Params)
	case "cloudflare":
		return newCloudflareProvider(cfg.Params)
	case "route53":
		return newRoute53Provider(cfg.Params)
	case "hetzner":
		return newHetznerProvider(cfg.Params)
	case "gandi":
		return newGandiProvider(cfg.Params)
	default:
		return nil, fmt.Errorf("acme: fournisseur DNS inconnu %q", cfg.Type)
	}
}
