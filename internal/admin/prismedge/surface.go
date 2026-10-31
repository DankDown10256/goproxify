// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package prismedge

import (
	"context"
	"sync"

	"github.com/vincamok/goproxify/internal/admin/analytics"
	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/edge/surface"
)

// GatewaySurface : les proxies dont une passerelle apprend la surface.
type GatewaySurface struct {
	NodeID   string            `json:"node_id"`
	NodeName string            `json:"node_name"`
	Proxies  []surface.Summary `json:"proxies"`
}

// GatewayReport : le rapport d'un proxy vu par une passerelle ; Report est nil quand elle n'a pas de profil pour lui. Une
// passerelle de groupe HA rend le profil fusionné de ses pairs : Members le dit.
type GatewayReport struct {
	NodeID   string          `json:"node_id"`
	NodeName string          `json:"node_name"`
	Report   *surface.Report `json:"report"`
}

// GatewayProposals : les réglages qu'une passerelle propose pour un proxy ; Proposals est nil quand elle n'a pas de profil pour lui.
type GatewayProposals struct {
	NodeID    string             `json:"node_id"`
	NodeName  string             `json:"node_name"`
	Proposals *surface.Proposals `json:"proposals"`
}

// GatewayOpenAPI : la politique OpenAPI qu'une passerelle génère pour un proxy ; OpenAPI est nil quand elle n'a pas de profil pour lui.
type GatewayOpenAPI struct {
	NodeID   string                 `json:"node_id"`
	NodeName string                 `json:"node_name"`
	OpenAPI  *surface.OpenAPIResult `json:"openapi"`
}

// GatewayForget : combien de violations la passerelle a effacées.
type GatewayForget struct {
	NodeID    string `json:"node_id"`
	NodeName  string `json:"node_name"`
	Forgotten int    `json:"forgotten"`
}

// GatewayReset : ce que la passerelle a effacé.
type GatewayReset struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name"`
	Reset    bool   `json:"reset"`
}

// onGateways exécute call sur chaque passerelle (ou sur celle de nodeName), en parallèle, et rend les réponses dans l'ordre
// des passerelles qui ont répondu. Les autres sont dans Meta.
func onGateways[T any](ctx context.Context, s *Source, nodeName string, call func(context.Context, *edgeproxy.Client, edgeproxy.Target) (T, error), add func(edgeproxy.Target, T)) (Meta, error) {
	targets, err := s.memberTargets(ctx, analytics.Params{NodeName: nodeName})
	if err != nil {
		return Meta{}, err
	}
	if len(targets) == 0 {
		return Meta{}, ErrNoGateway
	}
	if s.Bulk == nil {
		s.Bulk = edgeproxy.NewBulkClient()
	}
	resps := make([]T, len(targets))
	errs := make([]error, len(targets))
	var wg sync.WaitGroup
	for i := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, bulkTimeout)
			defer cancel()
			resps[i], errs[i] = call(cctx, s.Bulk, targets[i])
		}()
	}
	wg.Wait()
	failed := map[int]error{}
	for i := range targets {
		if errs[i] != nil {
			failed[i] = errs[i]
			continue
		}
		add(targets[i], resps[i])
	}
	return meta(targets, failed, false)
}

// SurfaceList demande à chaque passerelle les proxies dont elle apprend la surface.
func (s *Source) SurfaceList(ctx context.Context, nodeName string) ([]GatewaySurface, Meta, error) {
	out := []GatewaySurface{}
	m, err := onGateways(ctx, s, nodeName,
		func(ctx context.Context, c *edgeproxy.Client, t edgeproxy.Target) ([]surface.Summary, error) {
			r, err := c.SurfaceList(ctx, t)
			if err != nil {
				return nil, err
			}
			return r.Proxies, nil
		},
		func(t edgeproxy.Target, p []surface.Summary) {
			out = append(out, GatewaySurface{NodeID: t.ID, NodeName: t.NodeName, Proxies: p})
		})
	return out, m, err
}

// SurfaceReport demande à chaque passerelle le rapport d'un proxy.
func (s *Source) SurfaceReport(ctx context.Context, nodeName, route string) ([]GatewayReport, Meta, error) {
	out := []GatewayReport{}
	m, err := onGateways(ctx, s, nodeName,
		func(ctx context.Context, c *edgeproxy.Client, t edgeproxy.Target) (*surface.Report, error) {
			return c.SurfaceReport(ctx, t, route)
		},
		func(t edgeproxy.Target, r *surface.Report) {
			out = append(out, GatewayReport{NodeID: t.ID, NodeName: t.NodeName, Report: r})
		})
	return out, m, err
}

// SurfaceProposals demande à chaque passerelle les réglages que le profil d'un proxy permet de proposer.
func (s *Source) SurfaceProposals(ctx context.Context, nodeName, route string) ([]GatewayProposals, Meta, error) {
	out := []GatewayProposals{}
	m, err := onGateways(ctx, s, nodeName,
		func(ctx context.Context, c *edgeproxy.Client, t edgeproxy.Target) (*surface.Proposals, error) {
			return c.SurfaceProposals(ctx, t, route)
		},
		func(t edgeproxy.Target, p *surface.Proposals) {
			out = append(out, GatewayProposals{NodeID: t.ID, NodeName: t.NodeName, Proposals: p})
		})
	return out, m, err
}

// SurfaceOpenAPI demande à chaque passerelle la politique OpenAPI générée à partir du profil d'un proxy.
func (s *Source) SurfaceOpenAPI(ctx context.Context, nodeName, route string, lowSupport bool) ([]GatewayOpenAPI, Meta, error) {
	out := []GatewayOpenAPI{}
	m, err := onGateways(ctx, s, nodeName,
		func(ctx context.Context, c *edgeproxy.Client, t edgeproxy.Target) (*surface.OpenAPIResult, error) {
			return c.SurfaceOpenAPI(ctx, t, route, lowSupport)
		},
		func(t edgeproxy.Target, r *surface.OpenAPIResult) {
			out = append(out, GatewayOpenAPI{NodeID: t.ID, NodeName: t.NodeName, OpenAPI: r})
		})
	return out, m, err
}

// SurfaceForget demande à chaque passerelle (tous les membres d'un groupe HA) d'effacer des violations du profil d'un proxy.
func (s *Source) SurfaceForget(ctx context.Context, nodeName, route string, keys []string) ([]GatewayForget, Meta, error) {
	out := []GatewayForget{}
	m, err := onGateways(ctx, s, nodeName,
		func(ctx context.Context, c *edgeproxy.Client, t edgeproxy.Target) (int, error) {
			r, err := c.SurfaceForget(ctx, t, route, keys)
			if err != nil {
				return 0, err
			}
			return r.Forgotten, nil
		},
		func(t edgeproxy.Target, n int) {
			out = append(out, GatewayForget{NodeID: t.ID, NodeName: t.NodeName, Forgotten: n})
		})
	return out, m, err
}

// SurfaceReset demande à chaque passerelle d'effacer le profil d'un proxy : dans un groupe HA tous les membres doivent le
// faire, sinon un pair rendrait son profil à celui qui vient de l'oublier.
func (s *Source) SurfaceReset(ctx context.Context, nodeName, route string) ([]GatewayReset, Meta, error) {
	out := []GatewayReset{}
	m, err := onGateways(ctx, s, nodeName,
		func(ctx context.Context, c *edgeproxy.Client, t edgeproxy.Target) (bool, error) {
			r, err := c.SurfaceReset(ctx, t, route)
			if err != nil {
				return false, err
			}
			return r.Reset, nil
		},
		func(t edgeproxy.Target, reset bool) {
			out = append(out, GatewayReset{NodeID: t.ID, NodeName: t.NodeName, Reset: reset})
		})
	return out, m, err
}
