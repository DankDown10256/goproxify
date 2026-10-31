// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgeproxy

import (
	"context"
	"net/http"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/ssrf"
)

// NewBulkClient : client des exports de logs. La passerelle prend jusqu'à une minute pour lire 100 000 lignes.
func NewBulkClient() *Client {
	return &Client{HTTP: ssrf.SelfHostedClient(75 * time.Second)}
}

// LogSearch demande une page de lignes à la base de logs de la passerelle (ou à sa copie dans le volume de logs de l'Admin).
func (c *Client) LogSearch(ctx context.Context, t Target, p logapi.Params) (*logapi.SearchResponse, error) {
	var out logapi.SearchResponse
	if err := c.do(ctx, t, http.MethodGet, logapi.PathSearch+"?"+p.Values().Encode(), nil, &out); err != nil {
		return nil, err
	}
	out.Via = t.ID
	return &out, nil
}

// LogHistogram demande l'histogramme de la passerelle.
func (c *Client) LogHistogram(ctx context.Context, t Target, p logapi.Params) (*logapi.HistogramResponse, error) {
	var out logapi.HistogramResponse
	if err := c.do(ctx, t, http.MethodGet, logapi.PathHistogram+"?"+p.Values().Encode(), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// LogFacets demande les facettes de la passerelle.
func (c *Client) LogFacets(ctx context.Context, t Target, p logapi.Params) (*logapi.FacetsResponse, error) {
	var out logapi.FacetsResponse
	if err := c.do(ctx, t, http.MethodGet, logapi.PathFacets+"?"+p.Values().Encode(), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// LogReveal demande l'IP réelle d'une ligne pseudonymisée de la passerelle.
func (c *Client) LogReveal(ctx context.Context, t Target, req logapi.RevealRequest) (*logapi.RevealResponse, error) {
	var out logapi.RevealResponse
	if err := c.do(ctx, t, http.MethodPost, logapi.PathReveal, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// LogTop demande un regroupement par champ à la base de logs de la passerelle.
func (c *Client) LogTop(ctx context.Context, t Target, p logapi.Params, req logapi.TopRequest) (*logapi.TopResponse, error) {
	var out logapi.TopResponse
	if err := c.do(ctx, t, http.MethodPost, logapi.PathTop+"?"+p.Values().Encode(), req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// LogUniqueIPs demande le résumé des IP distinctes de la passerelle.
func (c *Client) LogUniqueIPs(ctx context.Context, t Target, p logapi.Params) (*logapi.UniqueIPsResponse, error) {
	var out logapi.UniqueIPsResponse
	if err := c.do(ctx, t, http.MethodGet, logapi.PathUniqueIPs+"?"+p.Values().Encode(), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// EphorSimulate demande à la passerelle de rejouer ses accès récents contre deux configurations Ephor.
func (c *Client) EphorSimulate(ctx context.Context, t Target, req logapi.EphorSimRequest) (*logapi.EphorSimResponse, error) {
	var out logapi.EphorSimResponse
	if err := c.do(ctx, t, http.MethodPost, logapi.PathEphorSim, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// EphorReferences demande à la passerelle ce qu'elle a appris pour la note commune d'Ephor.
func (c *Client) EphorReferences(ctx context.Context, t Target) (*logapi.EphorReferencesResponse, error) {
	var out logapi.EphorReferencesResponse
	if err := c.do(ctx, t, http.MethodGet, logapi.PathEphorReferences, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// LogErase demande à la passerelle d'effacer une IP de ses logs et de l'historique de ses bans, et rend ce qu'elle a supprimé.
func (c *Client) LogErase(ctx context.Context, t Target, ip string) (*logapi.EraseResponse, error) {
	var out logapi.EraseResponse
	if err := c.do(ctx, t, http.MethodPost, logapi.PathErase, logapi.EraseRequest{IP: ip}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
