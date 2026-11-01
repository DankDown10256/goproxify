// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgeproxy

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/surface"
)

// SurfaceList demande à la passerelle les proxies dont elle apprend la surface (ADR 0016).
func (c *Client) SurfaceList(ctx context.Context, t Target) (*logapi.SurfaceListResponse, error) {
	var out logapi.SurfaceListResponse
	if err := c.do(ctx, t, http.MethodGet, logapi.PathSurface, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Inventory demande à la passerelle les applications reconnues derrière ses proxies (ou ceux de route), ADR 0017.
func (c *Client) Inventory(ctx context.Context, t Target, route string) (*logapi.InventoryResponse, error) {
	path := logapi.PathInventory
	if route != "" {
		path += "?route=" + url.QueryEscape(route)
	}
	var out logapi.InventoryResponse
	if err := c.do(ctx, t, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Rejections demande à la passerelle ce que son entrée a refusé depuis son démarrage (ADR 0020, étape 1.c).
func (c *Client) Rejections(ctx context.Context, t Target) (*logapi.RejectionsResponse, error) {
	var out logapi.RejectionsResponse
	if err := c.do(ctx, t, http.MethodGet, logapi.PathRejections, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SurfaceReport demande à la passerelle le rapport d'un proxy (identifiant ou hôte). Rend nil, nil quand elle n'a aucun
// profil pour lui : ce n'est pas une panne.
func (c *Client) SurfaceReport(ctx context.Context, t Target, route string) (*surface.Report, error) {
	var out surface.Report
	err := c.do(ctx, t, http.MethodGet, logapi.PathSurfaceReport+"?route="+url.QueryEscape(route), nil, &out)
	var he *HTTPError
	if errors.As(err, &he) && he.Status == http.StatusNotFound && strings.Contains(he.Body, "aucun profil") {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// SurfaceProposals demande à la passerelle les réglages que le profil d'un proxy permet de proposer. Rend nil, nil quand elle
// n'a aucun profil pour lui.
func (c *Client) SurfaceProposals(ctx context.Context, t Target, route string) (*surface.Proposals, error) {
	var out surface.Proposals
	err := c.do(ctx, t, http.MethodGet, logapi.PathSurfaceProposals+"?route="+url.QueryEscape(route), nil, &out)
	var he *HTTPError
	if errors.As(err, &he) && he.Status == http.StatusNotFound && strings.Contains(he.Body, "aucun profil") {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// SurfaceOpenAPI demande à la passerelle la politique OpenAPI générée à partir du profil d'un proxy. Rend nil, nil quand elle
// n'a aucun profil pour lui.
func (c *Client) SurfaceOpenAPI(ctx context.Context, t Target, route string, lowSupport bool) (*surface.OpenAPIResult, error) {
	q := logapi.PathSurfaceOpenAPI + "?route=" + url.QueryEscape(route)
	if lowSupport {
		q += "&include_low_support=1"
	}
	var out surface.OpenAPIResult
	err := c.do(ctx, t, http.MethodGet, q, nil, &out)
	var he *HTTPError
	if errors.As(err, &he) && he.Status == http.StatusNotFound && strings.Contains(he.Body, "aucun profil") {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// SurfaceForget demande à la passerelle d'effacer des violations (« raison MÉTHODE chemin ») du profil d'un proxy : la politique les
// couvre désormais.
func (c *Client) SurfaceForget(ctx context.Context, t Target, route string, keys []string) (*logapi.SurfaceForgetResponse, error) {
	var out logapi.SurfaceForgetResponse
	if err := c.do(ctx, t, http.MethodPost, logapi.PathSurfaceForget, logapi.SurfaceForgetRequest{Route: route, Keys: keys}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SurfaceReset demande à la passerelle d'effacer le profil d'un proxy.
func (c *Client) SurfaceReset(ctx context.Context, t Target, route string) (*logapi.SurfaceResetResponse, error) {
	var out logapi.SurfaceResetResponse
	if err := c.do(ctx, t, http.MethodPost, logapi.PathSurfaceReset, logapi.SurfaceResetRequest{Route: route}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Seasonal demande à la passerelle la référence saisonnière de son trafic (ADR 0020, étape 3).
func (c *Client) Seasonal(ctx context.Context, t Target) (*logapi.SeasonalResponse, error) {
	var out logapi.SeasonalResponse
	if err := c.do(ctx, t, http.MethodGet, logapi.PathSeasonal, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
