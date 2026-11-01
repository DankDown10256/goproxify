// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package domainwatch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type resolverClient struct {
	server string
}

// NewDNS construit un client DNS vers resolver (« hôte:port »), ou vers le premier résolveur du système quand resolver est vide.
func NewDNS(resolver string) (DNSClient, error) {
	resolver = strings.TrimSpace(resolver)
	if resolver == "" {
		cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil || len(cfg.Servers) == 0 {
			return nil, errors.New("aucun résolveur système lisible : renseignez resolver")
		}
		resolver = net.JoinHostPort(cfg.Servers[0], cfg.Port)
	}
	return &resolverClient{server: resolver}, nil
}

func (r *resolverClient) exchange(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	c := &dns.Client{Timeout: 5 * time.Second}
	resp, _, err := c.ExchangeContext(ctx, m, r.server)
	if err == nil && resp.Truncated {
		c.Net = "tcp"
		resp, _, err = c.ExchangeContext(ctx, m, r.server)
	}
	return resp, err
}

// CAA rend les enregistrements CAA du nom ou, à défaut, de son plus proche ancêtre qui en a (RFC 8659). L'arbre n'est pas remonté
// au-delà des deux derniers libellés : la liste des suffixes publics n'est pas connue ici.
func (r *resolverClient) CAA(ctx context.Context, name string) ([]CAARecord, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for {
		resp, err := r.exchange(ctx, name, dns.TypeCAA)
		if err != nil {
			return nil, err
		}
		switch resp.Rcode {
		case dns.RcodeSuccess, dns.RcodeNameError:
		default:
			return nil, fmt.Errorf("réponse DNS %s pour %s", dns.RcodeToString[resp.Rcode], name)
		}
		var out []CAARecord
		for _, rr := range resp.Answer {
			if c, ok := rr.(*dns.CAA); ok {
				out = append(out, CAARecord{Tag: c.Tag, Value: c.Value})
			}
		}
		if len(out) > 0 {
			return out, nil
		}
		i := strings.IndexByte(name, '.')
		if i < 0 || strings.Count(name, ".") < 2 {
			return nil, nil
		}
		name = name[i+1:]
	}
}

// Dangling rend la cible du CNAME d'un nom qui, suivie jusqu'au bout, n'existe pas. Un résolveur récursif répond NXDOMAIN en gardant
// le CNAME dans la réponse.
func (r *resolverClient) Dangling(ctx context.Context, name string) (string, error) {
	resp, err := r.exchange(ctx, name, dns.TypeA)
	if err != nil {
		return "", err
	}
	if resp.Rcode != dns.RcodeNameError {
		return "", nil
	}
	target := ""
	for _, rr := range resp.Answer {
		if c, ok := rr.(*dns.CNAME); ok {
			target = strings.TrimSuffix(strings.ToLower(c.Target), ".")
		}
	}
	return target, nil
}
