// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"os"
	"time"

	edgews "github.com/vincamok/goproxify/internal/edge/ws"

	"github.com/vincamok/goproxify/internal/edge/geoip"
	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/middleware"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/surface"
	"github.com/vincamok/goproxify/internal/edge/threat"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
)

// Apprentissage de la surface d'un proxy (ADR 0016, étape 1) : en mode `learn` la passerelle observe le trafic légitime d'un
// proxy et en tire un profil. Rien n'est bloqué. Le profil est copié chiffré en local et se partage entre les membres d'un
// groupe HA sans l'Admin.

func newSurfaceCollector(s *Server) *surface.Collector {
	return surface.NewCollector(surface.Options{Country: s.surfaceCountry, ASN: s.surfaceASN})
}

// surfaceCountry rend le pays d'une IP. La base MaxMind se télécharge au démarrage : tant qu'elle manque, on réessaie au plus
// une fois par minute.
func (s *Server) surfaceCountry(ip string) string {
	fn := s.geoCountry.Load()
	if fn == nil {
		now := time.Now().Unix()
		if last := s.geoCountryTry.Load(); now-last < 60 || !s.geoCountryTry.CompareAndSwap(last, now) {
			return ""
		}
		path := geoip.DefaultDBPath
		if s.cfg != nil && s.cfg.GeoIP.DBPath != "" {
			path = s.cfg.GeoIP.DBPath
		}
		f, err := middleware.CountryLookup(path)
		if err != nil {
			return ""
		}
		s.geoCountry.Store(&f)
		fn = &f
	}
	a := net.ParseIP(ip)
	if a == nil {
		return ""
	}
	return (*fn)(a)
}

func (s *Server) surfaceASN(ip string) uint32 {
	db := s.asnDB.Load()
	if db == nil {
		return 0
	}
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return 0
	}
	return db.Lookup(a)
}

// surfaceClean dit que l'IP de la requête n'a rien de suspect : ni signal d'Ephor, ni règle WAF déclenchée, ni note de risque.
// Seul le trafic propre enseigne ce qui est légitime.
func (s *Server) surfaceClean(r *http.Request, ip string) bool {
	if threat.SignalFromContext(r.Context()) != "" || behavior.ObservationFrom(r.Context()).WAFScore() > 0 {
		return false
	}
	if s.threatEngine != nil && s.threatEngine.IPScore(ip) > 0 {
		return false
	}
	if s.behavior != nil {
		if score, _ := s.behavior.Score(ip); score > 0 {
			return false
		}
	}
	return true
}

// surfaceCleanApartFromWAF : l'IP n'a rien de suspect si l'on met de côté ce que le WAF lui reproche. Sert à distinguer, parmi les
// règles du WAF déclenchées, celles qui visent des clients ordinaires (faux positifs probables) de celles qui visent des attaquants,
// dont les autres signaux (Ephor, comportement) remontent vite.
func (s *Server) surfaceCleanApartFromWAF(r *http.Request, ip string) bool {
	if threat.SignalFromContext(r.Context()) != "" {
		return false
	}
	if s.threatEngine != nil && s.threatEngine.IPScore(ip) > 0 {
		return false
	}
	if s.behavior != nil {
		for _, sg := range s.behavior.Signals(ip) {
			if sg.Name != behavior.SignalWAFAccumulation {
				return false
			}
		}
	}
	return true
}

// surfaceWAFHits convertit les règles du WAF consignées sur l'observation de la requête.
func surfaceWAFHits(o *behavior.Observation) []surface.WAFHit {
	hits := o.WAFHits()
	if len(hits) == 0 {
		return nil
	}
	out := make([]surface.WAFHit, len(hits))
	for i, h := range hits {
		out[i] = surface.WAFHit{RuleID: h.RuleID, Category: h.Category, Message: h.Message, Target: h.Target}
	}
	return out
}

func surfaceMode(rt *router.Route) string {
	if rt.Surface == nil || rt.Surface.Mode == "" {
		return surface.ModeOff
	}
	return rt.Surface.Mode
}

// surfaceStatePath est la copie locale chiffrée des profils (ADR 0006).
func surfaceStatePath() string {
	if p := os.Getenv("GPX_SURFACE_STATE_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/surface-state.gpx"
}

func (s *Server) loadSurfaceStateFromDisk() {
	var st surface.State
	ok, err := s.cache.LoadFile(surfaceStatePath(), &st)
	if err != nil {
		s.log.Warn("surface: état local illisible — l'apprentissage repart de zéro", "err", err)
		return
	}
	if !ok {
		return
	}
	s.surface.Restore(st)
	s.log.Info("surface: profils restaurés depuis le disque", "proxies", len(st.Routes), "pairs", len(st.Peers))
}

func (s *Server) saveSurfaceState() {
	if s.surface == nil {
		return
	}
	// Un proxy supprimé n'a plus de profil à garder ; table vide = pas encore chargée, on ne juge rien.
	if s.table.Len() > 0 {
		s.surface.Forget(func(id string) bool { _, ok := s.table.ByID(id); return ok })
	}
	if err := s.cache.SaveFile(surfaceStatePath(), s.surface.Snapshot()); err != nil {
		s.log.Warn("surface: sauvegarde de l'état échouée", "err", err)
	}
}

// syncSurfaceFromPeer tire les profils locaux d'un pair du groupe. Le dernier envoi remplace le précédent : la fusion reste
// idempotente (ADR 0014).
func (s *Server) syncSurfaceFromPeer(ctx context.Context, client *http.Client, p proxy.PeerInfo) {
	if s.surface == nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Endpoint+logapi.PathSurfaceExport, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var payload surface.Payload
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, 64<<20)).Decode(&payload); err != nil {
		return
	}
	s.surface.ApplyPeer(p.Name, payload)
}

func (s *Server) handleSurfaceExport(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, s.surface.Export())
}

// handleSurfaceList : GET /internal/v1/surface — un résumé par proxy en apprentissage ou ayant un profil.
func (s *Server) handleSurfaceList(w http.ResponseWriter, _ *http.Request) {
	out := logapi.SurfaceListResponse{Proxies: []surface.Summary{}}
	for _, rt := range s.table.All() {
		if rt.Type != router.RouteHTTP {
			continue
		}
		mode := surfaceMode(rt)
		if sum, ok := s.surface.Summary(rt.ID, mode); ok {
			sum.Host = rt.Host
			out.Proxies = append(out.Proxies, sum)
		} else if surface.Learning(mode) {
			out.Proxies = append(out.Proxies, surface.Summary{Route: rt.ID, Host: rt.Host, Mode: mode})
		}
	}
	writeJSON(w, out)
}

// surfaceRoute retrouve un proxy par identifiant ou par hôte.
func (s *Server) surfaceRoute(ref string) (*router.Route, bool) {
	if rt, ok := s.table.ByID(ref); ok {
		return rt, true
	}
	return s.table.ByHost(ref)
}

// handleSurfaceReport : GET /internal/v1/surface/report?route=… — rapport complet d'un proxy.
func (s *Server) handleSurfaceReport(w http.ResponseWriter, r *http.Request) {
	ref := r.URL.Query().Get("route")
	if ref == "" {
		http.Error(w, "route manquante", http.StatusBadRequest)
		return
	}
	id, mode := ref, surface.ModeOff
	if rt, ok := s.surfaceRoute(ref); ok {
		id, mode = rt.ID, surfaceMode(rt)
	}
	rep, ok := s.surface.Report(id, mode)
	if !ok {
		http.Error(w, "aucun profil pour ce proxy", http.StatusNotFound)
		return
	}
	writeJSON(w, rep)
}

// handleSurfaceProposals : GET /internal/v1/surface/proposals?route=… — réglages proposés à partir du profil. Les réglages
// que le proxy a déjà (ceux de ses snippets compris) ne sont jamais remplacés.
func (s *Server) handleSurfaceProposals(w http.ResponseWriter, r *http.Request) {
	ref := r.URL.Query().Get("route")
	if ref == "" {
		http.Error(w, "route manquante", http.StatusBadRequest)
		return
	}
	rt, ok := s.surfaceRoute(ref)
	if !ok {
		http.Error(w, "aucun profil pour ce proxy", http.StatusNotFound)
		return
	}
	own := rt
	rt = router.ResolveSnippets(rt, s.snippetStore)
	cur := surface.Current{
		Host: rt.Host, Aliases: rt.Aliases, MaxBodySize: rt.MaxBodySize, RateLimit: rt.RateLimit != nil,
		IPFilter: rt.IPFilter != nil && len(rt.IPFilter.CIDRs) > 0, GeoIP: rt.GeoIP != nil && len(rt.GeoIP.Countries) > 0, CORS: rt.CORS != nil,
	}
	// Le WAF : la configuration du proxy lui-même (c'est elle qu'une exclusion modifierait) ; celle d'un snippet ne se remplace pas ici.
	if own.WAF != nil {
		cur.WAF, _ = json.Marshal(own.WAF)
		for _, cr := range own.WAF.CustomRules {
			cur.CustomRuleIDs = append(cur.CustomRuleIDs, cr.ID)
		}
	}
	cur.WAFFromSnippet = own.WAF == nil && rt.WAF != nil
	var refs []surface.RateRef
	if s.behavior != nil {
		for _, ri := range s.behavior.References() {
			if ri.Route == rt.Host {
				refs = append(refs, surface.RateRef{Hour: ri.Hour, Median: ri.Median, Threshold: ri.Threshold, Ready: ri.Ready})
			}
		}
	}
	p, ok := s.surface.Proposals(rt.ID, cur, refs)
	if !ok {
		http.Error(w, "aucun profil pour ce proxy", http.StatusNotFound)
		return
	}
	writeJSON(w, p)
}

// handleSurfaceOpenAPI : GET /internal/v1/surface/openapi?route=… — la politique positive générée à partir du profil, sous la forme
// du réglage `openapi` du proxy, en mode detect. Rien n'est appliqué.
func (s *Server) handleSurfaceOpenAPI(w http.ResponseWriter, r *http.Request) {
	ref := r.URL.Query().Get("route")
	if ref == "" {
		http.Error(w, "route manquante", http.StatusBadRequest)
		return
	}
	rt, ok := s.surfaceRoute(ref)
	if !ok {
		http.Error(w, "aucun profil pour ce proxy", http.StatusNotFound)
		return
	}
	opt := surface.OpenAPIOptions{
		IncludeLowSupport: r.URL.Query().Get("include_low_support") == "1",
		Replaces:          rt.OpenAPI != nil && rt.OpenAPI.Enabled,
	}
	res, ok := s.surface.OpenAPI(rt.ID, opt)
	if !ok {
		http.Error(w, "aucun profil pour ce proxy", http.StatusNotFound)
		return
	}
	writeJSON(w, res)
}

// surfaceNoteViolation verse à la note commune d'Ephor une requête hors de la politique du proxy que le backend a refusée.
// Une violation qui réussit depuis une IP propre est probablement un chemin légitime que la politique ignore : elle ne pèse pas.
func (s *Server) surfaceNoteViolation(ip string, status int) {
	if s.threatEngine != nil && status >= 400 && status != http.StatusUnauthorized {
		s.threatEngine.NoteDecision(ip, behavior.SignalSurface, 3, time.Now().Add(10*time.Minute))
	}
}

// handleSurfaceForget : POST /internal/v1/surface/forget — la politique couvre désormais ces violations : leur compte ne dit plus
// rien. Les pairs du groupe reçoivent la même demande de l'Admin ; leurs copies locales des profils s'alignent à l'échange suivant.
func (s *Server) handleSurfaceForget(w http.ResponseWriter, r *http.Request) {
	var req logapi.SurfaceForgetRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<18)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Route == "" || len(req.Keys) == 0 || len(req.Keys) > 200 {
		http.Error(w, "requête invalide", http.StatusBadRequest)
		return
	}
	id := req.Route
	if rt, ok := s.surfaceRoute(req.Route); ok {
		id = rt.ID
	}
	n := s.surface.ForgetViolations(id, req.Keys)
	if n > 0 {
		s.saveSurfaceState()
	}
	writeJSON(w, logapi.SurfaceForgetResponse{Forgotten: n})
}

// handleSurfaceReset : POST /internal/v1/surface/reset — l'application a changé, l'apprentissage repart de zéro.
func (s *Server) handleSurfaceReset(w http.ResponseWriter, r *http.Request) {
	var req logapi.SurfaceResetRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Route == "" {
		http.Error(w, "requête invalide", http.StatusBadRequest)
		return
	}
	id := req.Route
	if rt, ok := s.surfaceRoute(req.Route); ok {
		id = rt.ID
	}
	reset := s.surface.Reset(id)
	if reset {
		s.saveSurfaceState()
	}
	writeJSON(w, logapi.SurfaceResetResponse{Reset: reset})
}

// surfaceStatusEvery : intervalle d'envoi des suggestions à l'Admin. Elles changent à l'échelle de la journée.
const surfaceStatusEvery = 5 * time.Minute

// surfaceSuggestionsPayload rassemble les ajouts suggérés pour chaque proxy en apprentissage. Un proxy sans suggestion n'y figure
// pas : l'Admin en déduit que ses suggestions précédentes sont réglées.
func (s *Server) surfaceSuggestionsPayload() edgews.SurfaceSuggestionsPayload {
	out := edgews.SurfaceSuggestionsPayload{Proxies: []edgews.SurfaceProxyPayload{}}
	if s.cfg != nil {
		out.NodeName = s.cfg.Identity.NodeName
	}
	if s.surface == nil {
		return out
	}
	for _, rt := range s.table.All() {
		if rt.Type != router.RouteHTTP || !surface.Learning(surfaceMode(rt)) {
			continue
		}
		sg := s.surface.Suggestions(rt.ID)
		if len(sg) == 0 {
			continue
		}
		p := edgews.SurfaceProxyPayload{Route: rt.ID, Host: rt.Host, Suggestions: make([]edgews.SurfaceSuggestionPayload, len(sg))}
		for i, x := range sg {
			p.Suggestions[i] = edgews.SurfaceSuggestionPayload{Key: x.Key, Method: x.Method, Path: x.Path, Confidence: x.Confidence}
		}
		out.Proxies = append(out.Proxies, p)
	}
	return out
}

// surfaceStatusLoop envoie à l'Admin l'état des suggestions : c'est lui qui en déduit lesquelles sont nouvelles et alerte.
func (s *Server) surfaceStatusLoop(ctx context.Context) {
	timer := time.NewTimer(time.Minute) // le premier état part vite : les profils restaurés peuvent déjà avoir des suggestions
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			timer.Reset(surfaceStatusEvery)
			if msg, err := edgews.NewMessage(0, edgews.TypeSurfaceSuggestions, s.surfaceSuggestionsPayload()); err == nil {
				s.wsHub.BroadcastToAdmins(msg)
			}
		}
	}
}
