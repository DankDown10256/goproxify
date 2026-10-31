// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/edge/proxypipeline"
	"github.com/vincamok/goproxify/internal/edge/proxystore"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// Routes implicites : générées par GoProxify (hôtes du portail Access, délégations de domaine) plutôt que créées
// par l'opérateur. Leur emplacement (hôte, backend, mode TLS) découle d'un autre réglage et reste généré ; tout
// le reste (sécurité, en-têtes, limites, cache…) se surcharge par un proxy-fichier du même ID — la surcouche.
// Elle vit dans proxies/ et survit donc à une coupure de l'Admin et à un redémarrage de la passerelle.

func isImplicitRoute(id string) bool {
	return strings.HasPrefix(id, portalPublicRouteID) || strings.HasPrefix(id, "deleg-")
}

// generatedSkeleton ne garde de la route que ce que le générateur décide.
func generatedSkeleton(gen *router.Route) *router.Route {
	return withGeneratedFields(&router.Route{}, gen)
}

// withGeneratedFields rend la surcouche avec les champs générés de gen par-dessus. Les champs qui détournent
// le trafic vers un autre backend (statique, split, canary, shadow) sont retirés : le backend reste celui du générateur.
func withGeneratedFields(overlay, gen *router.Route) *router.Route {
	out := *overlay
	out.ID = gen.ID
	out.Host = gen.Host
	out.Aliases = gen.Aliases
	out.Type = gen.Type
	out.Backends = gen.Backends
	out.DelegateAPIEndpoint = gen.DelegateAPIEndpoint
	out.TLSEnabled = gen.TLSEnabled
	out.TLSPassthrough = gen.TLSPassthrough
	out.TLSSkipVerify = gen.TLSSkipVerify
	if gen.PreserveHost != nil {
		out.PreserveHost = gen.PreserveHost
	}
	out.Static = nil
	out.Split = nil
	out.Canary = nil
	out.Shadow = nil
	return &out
}

// effectiveImplicitEnvelope rend l'enveloppe d'une route implicite avec les champs que le générateur impose (hôte, backends, TLS)
// tels que la table les sert : le fichier de surcouche peut en garder une ancienne copie, ignorée au routage, que l'Admin
// ne doit pas présenter comme la configuration en vigueur.
func (s *Server) effectiveImplicitEnvelope(env *proxystore.Envelope) *proxystore.Envelope {
	live, ok := s.table.ByID(env.ID)
	if !ok {
		return env
	}
	var overlay router.Route
	if json.Unmarshal(env.Config, &overlay) != nil {
		return env
	}
	cfg, err := json.Marshal(withGeneratedFields(&overlay, live))
	if err != nil {
		return env
	}
	cp := *env
	cp.Config = cfg
	return &cp
}

// implicitOverlay lit la surcouche d'une route implicite ; nil si elle n'en a pas.
func (s *Server) implicitOverlay(id string) (route *router.Route, enabled bool) {
	if s.proxyStore == nil {
		return nil, true
	}
	env, err := s.proxyStore.ReadProdByID(id)
	if err != nil {
		return nil, true
	}
	route, err = proxypipeline.ParseRoute(env)
	if err != nil {
		s.log.Warn("proxystore: surcouche invalide ignorée", "id", id, "err", err)
		return nil, true
	}
	return route, env.Enabled
}

// upsertImplicitRoute publie une route générée avec sa surcouche. Une surcouche désactivée retire la route.
func (s *Server) upsertImplicitRoute(gen *router.Route) {
	s.implicitSkeleton.Store(gen.ID, generatedSkeleton(gen))
	overlay, enabled := s.implicitOverlay(gen.ID)
	switch {
	case overlay == nil:
		s.table.Upsert(gen)
	case enabled:
		s.table.Upsert(withGeneratedFields(overlay, gen))
	default:
		s.table.Delete(gen.ID)
	}
}

// refreshImplicitRoute rejoue la surcouche d'une route implicite après l'écriture ou la suppression de son fichier.
func (s *Server) refreshImplicitRoute(id string) {
	if strings.HasPrefix(id, portalPublicRouteID) {
		if hosts, _ := s.portalRoutes(); hosts[id] == "" {
			s.table.Delete(id)
			s.implicitSkeleton.Delete(id)
			s.invalidateRouteCache(id)
			return
		}
	}
	skel, _ := s.implicitSkeleton.Load(id)
	base, _ := skel.(*router.Route)
	if cur, ok := s.table.ByID(id); ok {
		base = generatedSkeleton(cur)
		s.implicitSkeleton.Store(id, base)
	}
	overlay, enabled := s.implicitOverlay(id)
	switch {
	case overlay == nil:
		if base != nil {
			s.table.Upsert(base)
		}
	case !enabled:
		s.table.Delete(id)
	case base != nil:
		s.table.Upsert(withGeneratedFields(overlay, base))
	default:
		s.table.Upsert(overlay)
	}
	s.invalidateRouteCache(id)
}

// implicitEnvelopes décrit les routes implicites actives qui n'ont pas encore de surcouche, pour que l'Admin les liste
// et les ouvre en édition comme n'importe quel proxy.
func (s *Server) implicitEnvelopes(hasFile map[string]bool) []*proxystore.Envelope {
	var out []*proxystore.Envelope
	for _, rt := range s.table.All() {
		// Un passthrough TLS est un tunnel TCP opaque : aucun réglage HTTP à surcharger.
		if !isImplicitRoute(rt.ID) || hasFile[rt.ID] || rt.TLSPassthrough {
			continue
		}
		if env := implicitEnvelope(rt); env != nil {
			out = append(out, env)
		}
	}
	return out
}

func implicitEnvelope(rt *router.Route) *proxystore.Envelope {
	cfg, err := json.Marshal(rt)
	if err != nil {
		return nil
	}
	now := time.Now().UTC()
	return &proxystore.Envelope{
		SchemaVersion: proxystore.SchemaVersionV1,
		ID:            rt.ID,
		Host:          rt.Host,
		Enabled:       true,
		Status:        proxystore.StatusProduction,
		UpdatedAt:     now,
		Implicit:      true,
		Config:        cfg,
	}
}
