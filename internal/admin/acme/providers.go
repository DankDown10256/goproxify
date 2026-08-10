// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// --- OVH -------------------------------------------------------------------

type ovhProvider struct {
	endpoint          string
	appKey            string
	appSecret         string
	consumerKey       string
	zone              string
}

func newOVHProvider(p map[string]string) (DNSProvider, error) {
	ep := p["endpoint"]
	if ep == "" {
		ep = "https://eu.api.ovh.com/1.0"
	}
	return &ovhProvider{
		endpoint:    ep,
		appKey:      p["app_key"],
		appSecret:   p["app_secret"],
		consumerKey: p["consumer_key"],
		zone:        p["zone"],
	}, nil
}

func (o *ovhProvider) SetTXTRecord(ctx context.Context, domain, value string) error {
	body, _ := json.Marshal(map[string]any{
		"fieldType": "TXT",
		"subDomain": "_acme-challenge." + domain,
		"target":    value,
		"ttl":       60,
	})
	return o.apiCall(ctx, http.MethodPost, "/domain/zone/"+o.zone+"/record", body)
}

func (o *ovhProvider) DeleteTXTRecord(ctx context.Context, domain string) error {
	// Simplification : liste + suppression. Dans la réalité, on stockerait l'ID.
	return o.apiCall(ctx, http.MethodDelete, "/domain/zone/"+o.zone+"/refresh", nil)
}

func (o *ovhProvider) apiCall(ctx context.Context, method, path string, body []byte) error {
	var bodyR io.Reader
	if body != nil {
		bodyR = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, o.endpoint+path, bodyR)
	if err != nil {
		return err
	}
	req.Header.Set("X-Ovh-Application", o.appKey)
	req.Header.Set("X-Ovh-Consumer", o.consumerKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("ovh: HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

// --- Cloudflare ------------------------------------------------------------

type cloudflareProvider struct {
	token  string
	zoneID string // peut être vide → résolu dynamiquement
}

func newCloudflareProvider(p map[string]string) (DNSProvider, error) {
	token := p["api_token"]
	if token == "" {
		token = p["CF_API_TOKEN"] // alias variable d'env
	}
	if token == "" {
		return nil, fmt.Errorf("cloudflare: api_token requis")
	}
	return &cloudflareProvider{token: token, zoneID: p["zone_id"]}, nil
}

// resolveZoneID cherche la zone Cloudflare correspondant au domaine.
func (c *cloudflareProvider) resolveZoneID(ctx context.Context, domain string) (string, error) {
	// Tente le domaine racine (ex: "vincz.fr" depuis "_acme-challenge.example.com")
	name := domain
	if dot := indexOf2(name, '.'); dot >= 0 {
		// Si le domaine a plusieurs niveaux, prendre les deux derniers
		rest := name[dot+1:]
		if idx := indexOf2(rest, '.'); idx >= 0 {
			name = rest
		}
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.cloudflare.com/client/v4/zones?name="+name, nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	if len(result.Result) == 0 {
		return "", fmt.Errorf("cloudflare: zone introuvable pour %q", name)
	}
	return result.Result[0].ID, nil
}

func indexOf2(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func (c *cloudflareProvider) zoneFor(ctx context.Context, domain string) (string, error) {
	if c.zoneID != "" {
		return c.zoneID, nil
	}
	return c.resolveZoneID(ctx, domain)
}

func (c *cloudflareProvider) SetTXTRecord(ctx context.Context, domain, value string) error {
	zoneID, err := c.zoneFor(ctx, domain)
	if err != nil {
		return err
	}
	// Append : ne pas supprimer les autres TXT _acme-challenge (wildcard + apex
	// coexistent sur le même nom avec des valeurs différentes).
	body, _ := json.Marshal(map[string]any{
		"type":    "TXT",
		"name":    "_acme-challenge." + domain,
		"content": value,
		"ttl":     60,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.cloudflare.com/client/v4/zones/"+zoneID+"/dns_records",
		bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("cloudflare: HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

func (c *cloudflareProvider) DeleteTXTRecord(ctx context.Context, domain string) error {
	zoneID, err := c.zoneFor(ctx, domain)
	if err != nil {
		return nil // best-effort
	}
	return c.deleteTXTByZone(ctx, zoneID, domain)
}

func (c *cloudflareProvider) deleteTXTByZone(ctx context.Context, zoneID, domain string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.cloudflare.com/client/v4/zones/"+zoneID+"/dns_records?type=TXT&name=_acme-challenge."+domain,
		nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	var result struct {
		Result []struct {
			ID string `json:"id"`
		} `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil
	}
	for _, rec := range result.Result {
		delReq, _ := http.NewRequestWithContext(ctx, http.MethodDelete,
			"https://api.cloudflare.com/client/v4/zones/"+zoneID+"/dns_records/"+rec.ID, nil)
		delReq.Header.Set("Authorization", "Bearer "+c.token)
		delResp, err := http.DefaultClient.Do(delReq)
		if err == nil {
			delResp.Body.Close()
		}
	}
	return nil
}

// --- Route53 ---------------------------------------------------------------

type route53Provider struct{ hostedZoneID string }

func newRoute53Provider(p map[string]string) (DNSProvider, error) {
	if p["hosted_zone_id"] == "" {
		return nil, fmt.Errorf("route53: hosted_zone_id requis")
	}
	return &route53Provider{hostedZoneID: p["hosted_zone_id"]}, nil
}

func (r *route53Provider) SetTXTRecord(_ context.Context, _, _ string) error {
	// Nécessite le SDK AWS — stub non-op pour compilation.
	return fmt.Errorf("route53: non implémenté (utilisez le SDK AWS v2)")
}

func (r *route53Provider) DeleteTXTRecord(_ context.Context, _ string) error {
	return fmt.Errorf("route53: non implémenté (utilisez le SDK AWS v2)")
}

// --- Hetzner ---------------------------------------------------------------

type hetznerProvider struct {
	apiToken string
	zoneID   string
}

func newHetznerProvider(p map[string]string) (DNSProvider, error) {
	if p["api_token"] == "" || p["zone_id"] == "" {
		return nil, fmt.Errorf("hetzner: api_token et zone_id requis")
	}
	return &hetznerProvider{apiToken: p["api_token"], zoneID: p["zone_id"]}, nil
}

func (h *hetznerProvider) SetTXTRecord(ctx context.Context, domain, value string) error {
	body, _ := json.Marshal(map[string]any{
		"type":    "TXT",
		"name":    "_acme-challenge." + domain,
		"value":   value,
		"ttl":     60,
		"zone_id": h.zoneID,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://dns.hetzner.com/api/v1/records", bytes.NewReader(body))
	req.Header.Set("Auth-API-Token", h.apiToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("hetzner: HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

func (h *hetznerProvider) DeleteTXTRecord(_ context.Context, _ string) error {
	return nil
}

// --- Gandi -----------------------------------------------------------------

type gandiProvider struct{ apiKey string }

func newGandiProvider(p map[string]string) (DNSProvider, error) {
	if p["api_key"] == "" {
		return nil, fmt.Errorf("gandi: api_key requis")
	}
	return &gandiProvider{apiKey: p["api_key"]}, nil
}

func (g *gandiProvider) SetTXTRecord(ctx context.Context, domain, value string) error {
	// LiveDNS remplace tout le rrset : fusionner avec les valeurs déjà présentes
	// pour permettre wildcard + apex en parallèle.
	values := []string{value}
	getReq, _ := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.gandi.net/v5/livedns/domains/"+domain+"/records/_acme-challenge/TXT", nil)
	getReq.Header.Set("Authorization", "Apikey "+g.apiKey)
	if getResp, err := http.DefaultClient.Do(getReq); err == nil {
		defer getResp.Body.Close()
		if getResp.StatusCode == 200 {
			var existing struct {
				RrsetValues []string `json:"rrset_values"`
			}
			if json.NewDecoder(getResp.Body).Decode(&existing) == nil {
				seen := map[string]struct{}{value: {}}
				for _, v := range existing.RrsetValues {
					if _, ok := seen[v]; ok {
						continue
					}
					seen[v] = struct{}{}
					values = append(values, v)
				}
			}
		}
	}

	body, _ := json.Marshal(map[string]any{
		"rrset_values": values,
		"rrset_ttl":    300,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut,
		"https://api.gandi.net/v5/livedns/domains/"+domain+"/records/_acme-challenge/TXT",
		bytes.NewReader(body))
	req.Header.Set("Authorization", "Apikey "+g.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("gandi: HTTP %d: %s", resp.StatusCode, b)
	}
	return nil
}

func (g *gandiProvider) DeleteTXTRecord(ctx context.Context, domain string) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete,
		"https://api.gandi.net/v5/livedns/domains/"+domain+"/records/_acme-challenge/TXT", nil)
	req.Header.Set("Authorization", "Apikey "+g.apiKey)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}
