// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	coreagent "github.com/vincamok/goproxify/internal/core/agent"
	"github.com/vincamok/goproxify/internal/core/metrics"
	"github.com/vincamok/goproxify/internal/core/router"
	coretokens "github.com/vincamok/goproxify/internal/core/tokens"
	corews "github.com/vincamok/goproxify/internal/core/ws"
	"github.com/vincamok/goproxify/internal/labels"
)

// --- Handlers Agent → Core -----------------------------------------------

type agentHeartbeatPayload struct {
	NodeName          string          `json:"node_name"`
	Role              string          `json:"role"`
	Version           string          `json:"version"`
	Endpoint          string          `json:"endpoint"`
	CPUPCT            float64         `json:"cpu_pct"`
	MemPCT            float64         `json:"mem_pct"`
	ContainerRuntimes []string        `json:"container_runtimes,omitempty"`
	AgentConfig       json.RawMessage `json:"agent_config,omitempty"`
}

func (s *Server) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	var hb agentHeartbeatPayload
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if hb.NodeName == "" {
		http.Error(w, "node_name requis", http.StatusBadRequest)
		return
	}

	// Purger les routes Docker si l'agent ne signale pas de runtime Docker/Podman.
	// On purge à chaque heartbeat sans runtime (pas seulement sur transition)
	// pour couvrir le cas d'un redémarrage du Core (nodeStore vide).
	if !hasRuntime(hb.ContainerRuntimes, "docker", "podman") {
		s.purgeDockerRoutesForAgent(hb.NodeName)
	}

	s.nodeStore.Upsert(coreagent.NodeInfo{
		NodeName:          hb.NodeName,
		Role:              hb.Role,
		Version:           hb.Version,
		Endpoint:          hb.Endpoint,
		CPUPCT:            hb.CPUPCT,
		MemPCT:            hb.MemPCT,
		ContainerRuntimes: hb.ContainerRuntimes,
		AgentConfig:       hb.AgentConfig,
	})
	w.WriteHeader(http.StatusNoContent)
}

func hasRuntime(runtimes []string, names ...string) bool {
	for _, r := range runtimes {
		for _, n := range names {
			if r == n {
				return true
			}
		}
	}
	return false
}

func (s *Server) purgeDockerRoutesForAgent(agentName string) {
	changed := false
	for _, rt := range s.table.All() {
		if rt.AgentName != agentName {
			continue
		}
		if strings.HasPrefix(rt.ID, "docker:") || strings.HasPrefix(rt.ID, "docker-host:") {
			if s.table.Delete(rt.ID) {
				changed = true
			}
		}
	}
	if changed {
		metrics.Core.RouteCount.Set(float64(s.table.Len()))
		s.log.Info("agent: routes Docker purgées (docker désactivé)", "agent", agentName)
	}
}

type agentContainerPayload struct {
	ID           string   `json:"id"`
	Host         string   `json:"host"`
	Aliases      []string `json:"aliases"`
	Paths        []string `json:"paths"`
	RouteType    string   `json:"route_type"`
	Backends     []string `json:"backends"`
	TLSEnabled   bool     `json:"tls_enabled"`
	Passthrough  bool     `json:"passthrough"`
	Source       string   `json:"source"`
	ContainerID  string   `json:"container_id"`
	AgentName    string   `json:"agent_name"`
	Role         string   `json:"role"`          // normal | canary | shadow
	CanaryWeight int      `json:"canary_weight"` // % trafic canary (défaut 10)

	// Sécurité (labels) — RawMessage pour accepter string legacy ou objet structuré.
	RateLimit      json.RawMessage `json:"rate_limit"`
	IPFilter       json.RawMessage `json:"ip_filter"`
	CORS           json.RawMessage `json:"cors"`
	GeoIP          json.RawMessage `json:"geo_ip"`
	SnippetIDs     []string        `json:"snippet_ids"`
	AuthProviderID string          `json:"auth_provider_id"`
	WAF            json.RawMessage `json:"waf"`
	Bot            json.RawMessage `json:"bot"`
	LimitConn      json.RawMessage `json:"limit_conn"`
	Backpressure   json.RawMessage `json:"backpressure"`
	JWT            json.RawMessage `json:"jwt"`
	MTLS           json.RawMessage `json:"mtls"`

	// Comportement HTTP
	PreserveHost *bool  `json:"preserve_host"`
	Websocket    *bool  `json:"websocket"`
	RequestID    *bool  `json:"request_id"`
	HTTPVersion  string `json:"http_version"`

	// Réécriture d'URL
	StripPrefix string `json:"strip_prefix"`
	PathRewrite string `json:"path_rewrite"`

	// Timeouts & limites
	ConnectTimeout  string `json:"connect_timeout"`
	ResponseTimeout string `json:"response_timeout"`
	SendTimeout     string `json:"send_timeout"`
	MaxBodySize     int64  `json:"max_body_size"`

	// Load balancing & résilience
	LBOverride     string          `json:"lb"`
	StickyCookie   string          `json:"sticky_cookie"`
	SlowStartSec   int             `json:"slow_start_sec"`
	Retry          json.RawMessage `json:"retry"`
	CircuitBreaker json.RawMessage `json:"circuit_breaker"`

	// En-têtes
	HeadersAdd    map[string]string `json:"headers_add"`
	HeadersRemove []string          `json:"headers_remove"`

	// Cache & logs
	Cache   json.RawMessage `json:"cache"`
	Logging json.RawMessage `json:"logging"`

	// Sentinel whitelist par route
	SentinelWhitelist []string `json:"sentinel_whitelist,omitempty"`

	// Relayed indique que ce payload a déjà été relayé par un Core pair (anti-boucle).
	Relayed bool `json:"relayed,omitempty"`
}

// agentRouteMatchesDelegation retourne vrai si host est couvert par le wildcard d'une délégation.
func agentRouteMatchesDelegation(pattern, host string) bool {
	if pattern == host {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		return strings.HasSuffix(host, pattern[1:])
	}
	return false
}


// payloadMatchesDelegation retourne vrai si le host ou l'un des aliases du payload
// est couvert par le wildcard de délégation donné.
func payloadMatchesDelegation(pattern string, p *agentContainerPayload) bool {
	if agentRouteMatchesDelegation(pattern, p.Host) {
		return true
	}
	for _, a := range p.Aliases {
		if agentRouteMatchesDelegation(pattern, a) {
			return true
		}
	}
	return false
}

// relayToDelegates relaie un payload de route agent aux Cores délégués dont le wildcard
// couvre le host ou l'un des aliases. Utilise le token admin partagé. Ne fait rien si Relayed=true.
func (s *Server) relayToDelegates(ctx context.Context, p *agentContainerPayload) {
	if p.Relayed {
		return
	}
	s.adminTokenMu.RLock()
	token := s.adminToken
	s.adminTokenMu.RUnlock()
	if token == "" {
		return
	}

	p.Relayed = true
	body, err := json.Marshal(p)
	if err != nil {
		return
	}

	for _, rt := range s.table.All() {
		if !strings.HasPrefix(rt.ID, "deleg-") {
			continue
		}
		if !payloadMatchesDelegation(rt.Host, p) {
			continue
		}
		base := rt.DelegateAPIEndpoint
		if base == "" {
			continue
		}
		// Utiliser le token du peer (Lucas Core) plutôt que le token admin local.
		peerToken := token
		for _, peer := range s.peers.All() {
			if peer.Endpoint == base {
				peerToken = peer.Token
				break
			}
		}
		go func(base, peerToken string, payload []byte) {
			reqURL := base + "/internal/v1/agent/containers"
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(payload))
			if err != nil {
				return
			}
			req.Header.Set("Authorization", "Bearer "+peerToken)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				s.log.Warn("core: relay route agent vers délégué", "delegate", base, "host", p.Host, "err", err)
				return
			}
			resp.Body.Close()
			s.log.Info("core: route agent relayée vers délégué", "delegate", base, "host", p.Host, "status", resp.StatusCode)
		}(base, peerToken, body)
	}
}

// relayDeleteToDelegates propage la suppression d'un conteneur aux Cores délégués.
func (s *Server) relayDeleteToDelegates(ctx context.Context, containerID, name string) {
	s.adminTokenMu.RLock()
	token := s.adminToken
	s.adminTokenMu.RUnlock()
	if token == "" {
		return
	}
	body, _ := json.Marshal(map[string]any{
		"container_id": containerID,
		"name":         name,
		"relayed":      true,
	})
	seen := map[string]bool{}
	for _, rt := range s.table.All() {
		if !strings.HasPrefix(rt.ID, "deleg-") {
			continue
		}
		base := rt.DelegateAPIEndpoint
		if base == "" || seen[base] {
			continue
		}
		seen[base] = true
		peerToken := token
		for _, peer := range s.peers.All() {
			if peer.Endpoint == base {
				peerToken = peer.Token
				break
			}
		}
		go func(base, peerToken string) {
			reqURL := base + "/internal/v1/agent/containers"
			req, err := http.NewRequestWithContext(ctx, http.MethodDelete, reqURL, bytes.NewReader(body))
			if err != nil {
				return
			}
			req.Header.Set("Authorization", "Bearer "+peerToken)
			req.Header.Set("Content-Type", "application/json")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				s.log.Warn("core: relay suppression route vers délégué", "delegate", base, "err", err)
				return
			}
			resp.Body.Close()
		}(base, peerToken)
	}
}

func (s *Server) handleAgentContainerStart(w http.ResponseWriter, r *http.Request) {
	var p agentContainerPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	host, extraPath := labels.ParseHostEntry(p.Host)
	p.Host = host
	if extraPath != "" {
		p.Paths = appendUniqueString(p.Paths, extraPath)
	}
	for i, a := range p.Aliases {
		h, path := labels.ParseHostEntry(a)
		p.Aliases[i] = h
		if path != "" {
			p.Paths = appendUniqueString(p.Paths, path)
		}
	}
	p.Aliases = filterEmptyStrings(p.Aliases)
	if p.Host == "" || len(p.Backends) == 0 {
		http.Error(w, "host et backends requis", http.StatusBadRequest)
		return
	}
	// Relay Core→Core : après traitement local, propager aux Cores délégués qui couvrent ce host.
	// context.Background() : r.Context() est annulé dès que le handler retourne.
	defer s.relayToDelegates(context.Background(), &p)
	// Purge les routes portainer qui seraient masquées par une délégation wildcard.
	defer s.purgeRoutesShadowedByPassthrough()
	role := strings.ToLower(strings.TrimSpace(p.Role))
	if role == "" {
		role = "normal"
	}
	weight := p.CanaryWeight
	if weight <= 0 {
		weight = 10
	}
	if weight > 100 {
		weight = 100
	}
	backendURL := p.Backends[0]

	isPortainer := p.Source == "portainer" || strings.HasPrefix(p.ID, "portainer:")
	var routeID string
	if isPortainer && p.ID != "" {
		routeID = p.ID
	} else {
		routeID = dockerHostRouteID(p.Host)
	}

	var existing *router.Route
	if !isPortainer && p.ContainerID != "" {
		if folded := s.foldDockerRoutesForContainer(p.ContainerID, p.Host); folded != nil {
			existing = folded
			routeID = folded.ID
		}
	}
	if existing == nil {
		if rt, ok := s.table.ByHost(p.Host); ok {
			if isPortainer && strings.HasPrefix(rt.ID, "portainer:") {
				existing = rt
				routeID = rt.ID
			} else if !isPortainer && isDockerDiscoveryRoute(rt) {
				existing = rt
				routeID = rt.ID
			}
			// Ne pas réutiliser une route docker-host comme base pour une route portainer
			// (ni l'inverse) : deux sources distinctes peuvent coexister pour le même host.
		}
	}

	applyMeta := func(rt *router.Route) {
		if rt.LB == "" || rt.LB == router.LBRoundRobin {
			rt.LB = router.LBAdaptive
		}
		if p.AgentName != "" {
			rt.AgentName = p.AgentName
		}
		if p.TLSEnabled {
			rt.TLSEnabled = true
		}
		if p.Passthrough {
			rt.TLSPassthrough = true
		}
		geoDB := ""
		if s.cfg != nil {
			geoDB = s.cfg.GeoIP.DBPath
		}
		applyDiscoverySecurity(rt, &p, geoDB)
		applyDiscoveryHostExtras(rt, &p)
		s.absorbDockerHostAliasRoutes(rt, rt.Aliases)
		if rt.ID != routeID {
			if existing != nil && existing.ID != routeID {
				s.table.Delete(existing.ID)
			}
			rt.ID = routeID
		}
		s.refreshSentinelWhitelists()
	}

	switch role {
	case "canary":
		rt := existing
		if rt == nil {
			rt = &router.Route{ID: routeID, Host: p.Host, LB: router.LBAdaptive}
		}
		// Hors pool LB : retirer ce conteneur s'il y était en normal
		rt.Backends = removeBackendByContainer(rt.Backends, p.ContainerID)
		rt.Canary = &router.CanaryConfig{
			Backend:     backendURL,
			Weight:      weight,
			ContainerID: p.ContainerID,
		}
		// Si ce conteneur était shadow, clear
		if rt.Shadow != nil && containerIDMatch(rt.Shadow.ContainerID, p.ContainerID) {
			rt.Shadow = nil
		}
		applyMeta(rt)
		s.table.Upsert(rt)
		metrics.Core.RouteCount.Set(float64(s.table.Len()))
		s.log.Info("agent: canary activé", "host", p.Host, "container", p.ContainerID, "weight", weight, "agent", p.AgentName)
		w.WriteHeader(http.StatusNoContent)
		return

	case "shadow":
		rt := existing
		if rt == nil {
			rt = &router.Route{ID: routeID, Host: p.Host, LB: router.LBAdaptive}
		}
		rt.Backends = removeBackendByContainer(rt.Backends, p.ContainerID)
		rt.Shadow = &router.ShadowConfig{
			Backend:     backendURL,
			ContainerID: p.ContainerID,
		}
		if rt.Canary != nil && containerIDMatch(rt.Canary.ContainerID, p.ContainerID) {
			rt.Canary = nil
		}
		applyMeta(rt)
		s.table.Upsert(rt)
		metrics.Core.RouteCount.Set(float64(s.table.Len()))
		s.log.Info("agent: shadow activé", "host", p.Host, "container", p.ContainerID, "agent", p.AgentName)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// role normal (défaut) : pool backends
	backends := make([]router.Backend, 0, len(p.Backends))
	for _, u := range p.Backends {
		backends = append(backends, router.Backend{
			URL:         u,
			ContainerID: p.ContainerID,
			AgentName:   p.AgentName,
		})
	}
	if existing != nil {
		merged := mergeDiscoveryBackends(existing.Backends, backends)
		existing.Backends = merged
		// Re-label : ce conteneur n'est plus canary/shadow
		if existing.Canary != nil && containerIDMatch(existing.Canary.ContainerID, p.ContainerID) {
			existing.Canary = nil
		}
		if existing.Shadow != nil && containerIDMatch(existing.Shadow.ContainerID, p.ContainerID) {
			existing.Shadow = nil
		}
		applyMeta(existing)
		s.table.Upsert(existing)
		metrics.Core.RouteCount.Set(float64(s.table.Len()))
		s.log.Info("agent: backend ajouté au pool", "host", p.Host, "container", p.ContainerID, "backends", len(merged), "agent", p.AgentName)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	route := &router.Route{
		ID:             routeID,
		Host:           p.Host,
		Aliases:        append([]string(nil), p.Aliases...),
		Backends:       backends,
		TLSEnabled:     p.TLSEnabled,
		TLSPassthrough: p.Passthrough,
		AgentName:      p.AgentName,
		LB:             router.LBAdaptive,
	}
	applyMeta(route)
	s.table.Upsert(route)
	metrics.Core.RouteCount.Set(float64(s.table.Len()))
	s.log.Info("agent: route label ajoutée", "host", p.Host, "container", p.ContainerID, "agent", p.AgentName)
	w.WriteHeader(http.StatusNoContent)
}

func dockerHostRouteID(host string) string {
	return "docker-host:" + host
}

func (s *Server) foldDockerRoutesForContainer(containerID, primaryHost string) *router.Route {
	if s == nil || s.table == nil || containerID == "" {
		return nil
	}
	var routes []*router.Route
	for _, rt := range s.table.All() {
		if !strings.HasPrefix(rt.ID, "docker-host:") {
			continue
		}
		if dockerRouteHasContainer(rt, containerID) {
			routes = append(routes, rt)
		}
	}
	if len(routes) == 0 {
		return nil
	}
	primary := routes[0]
	for _, rt := range routes {
		if strings.EqualFold(rt.Host, primaryHost) {
			primary = rt
			break
		}
	}
	for _, rt := range routes {
		if rt.ID == primary.ID {
			continue
		}
		primary.Backends = mergeDiscoveryBackends(primary.Backends, rt.Backends)
		if rt.Host != "" && !strings.EqualFold(rt.Host, primary.Host) {
			primary.Aliases = appendUniqueString(primary.Aliases, rt.Host)
		}
		for _, a := range rt.Aliases {
			if a != "" && !strings.EqualFold(a, primary.Host) {
				primary.Aliases = appendUniqueString(primary.Aliases, a)
			}
		}
		s.table.Delete(rt.ID)
	}
	return primary
}

func dockerRouteHasContainer(rt *router.Route, containerID string) bool {
	if rt == nil || containerID == "" {
		return false
	}
	for _, b := range rt.Backends {
		if containerIDMatch(b.ContainerID, containerID) {
			return true
		}
	}
	if rt.Canary != nil && containerIDMatch(rt.Canary.ContainerID, containerID) {
		return true
	}
	if rt.Shadow != nil && containerIDMatch(rt.Shadow.ContainerID, containerID) {
		return true
	}
	return false
}

func applyDiscoveryHostExtras(rt *router.Route, p *agentContainerPayload) {
	if rt == nil || p == nil {
		return
	}
	if p.Aliases != nil {
		aliases := make([]string, 0, len(p.Aliases))
		for _, a := range p.Aliases {
			if a == "" || strings.EqualFold(a, rt.Host) {
				continue
			}
			aliases = appendUniqueString(aliases, a)
		}
		rt.Aliases = aliases
	}
	if p.Host != "" && rt.Host != "" && !strings.EqualFold(p.Host, rt.Host) {
		rt.Aliases = appendUniqueString(rt.Aliases, p.Host)
	}
	if p.Paths != nil {
		rt.Locations = locationsFromLabelPaths(p.Paths)
	}

	// Comportement HTTP
	if p.PreserveHost != nil {
		rt.PreserveHost = p.PreserveHost
	}
	if p.Websocket != nil {
		rt.Websocket = p.Websocket
	}
	if p.RequestID != nil {
		rt.RequestID = p.RequestID
	}
	if p.HTTPVersion != "" {
		rt.HttpVersion = p.HTTPVersion
	}

	// Réécriture d'URL
	if p.StripPrefix != "" {
		rt.StripPrefix = p.StripPrefix
	}
	if p.PathRewrite != "" {
		rt.PathRewrite = p.PathRewrite
	}

	// Timeouts & limites
	if p.ConnectTimeout != "" {
		if d, err := time.ParseDuration(p.ConnectTimeout); err == nil {
			rt.ConnectTimeout = d
		}
	}
	if p.ResponseTimeout != "" {
		if d, err := time.ParseDuration(p.ResponseTimeout); err == nil {
			rt.ResponseTimeout = d
		}
	}
	if p.SendTimeout != "" {
		if d, err := time.ParseDuration(p.SendTimeout); err == nil {
			rt.SendTimeout = d
		}
	}
	if p.MaxBodySize > 0 {
		rt.MaxBodySize = p.MaxBodySize
	}

	// Load balancing & résilience
	if p.LBOverride != "" {
		rt.LB = router.LBAlgorithm(p.LBOverride)
	}
	if p.StickyCookie != "" {
		rt.StickyCookie = p.StickyCookie
	}
	if p.SlowStartSec > 0 {
		rt.SlowStartSec = p.SlowStartSec
	}
	if len(p.Retry) > 0 && string(p.Retry) != "null" {
		var rc router.RetryConfig
		if json.Unmarshal(p.Retry, &rc) == nil {
			rt.Retry = &rc
		}
	}
	if len(p.CircuitBreaker) > 0 && string(p.CircuitBreaker) != "null" {
		var cb router.CBConfig
		if json.Unmarshal(p.CircuitBreaker, &cb) == nil {
			rt.CircuitBreaker = &cb
		}
	}
	if len(p.LimitConn) > 0 && string(p.LimitConn) != "null" {
		var lc router.LimitConnConfig
		if json.Unmarshal(p.LimitConn, &lc) == nil {
			rt.LimitConn = &lc
		}
	}
	if len(p.Backpressure) > 0 && string(p.Backpressure) != "null" {
		var bp router.BackpressureConfig
		if json.Unmarshal(p.Backpressure, &bp) == nil {
			rt.Backpressure = &bp
		}
	}

	// En-têtes
	if len(p.HeadersAdd) > 0 {
		if rt.HeadersManipulation == nil {
			rt.HeadersManipulation = &router.HeadersManipulationConfig{}
		}
		if rt.HeadersManipulation.RequestSetHeader == nil {
			rt.HeadersManipulation.RequestSetHeader = map[string]string{}
		}
		for k, v := range p.HeadersAdd {
			rt.HeadersManipulation.RequestSetHeader[k] = v
		}
	}
	// headers.remove retire des en-têtes de la RÉPONSE (ex. X-Powered-By, Server), comme documenté.
	if len(p.HeadersRemove) > 0 {
		if rt.Transform == nil {
			rt.Transform = &router.RequestTransform{}
		}
		rt.Transform.RemoveResponseHeaders = p.HeadersRemove
	}

	// JWT & mTLS
	if len(p.JWT) > 0 && string(p.JWT) != "null" {
		var jc router.JWTConfig
		if json.Unmarshal(p.JWT, &jc) == nil {
			rt.JWT = &jc
		}
	}
	if len(p.MTLS) > 0 && string(p.MTLS) != "null" {
		var mc router.MTLSConfig
		if json.Unmarshal(p.MTLS, &mc) == nil {
			rt.MTLS = &mc
		}
	}

	// Cache
	if len(p.Cache) > 0 && string(p.Cache) != "null" {
		var cc router.CacheConfig
		if json.Unmarshal(p.Cache, &cc) == nil {
			rt.Cache = &cc
		}
	}

	// Logs
	if len(p.Logging) > 0 && string(p.Logging) != "null" {
		var lc router.RouteLoggingConfig
		if json.Unmarshal(p.Logging, &lc) == nil {
			rt.Logging = &lc
		}
	}
}

func locationsFromLabelPaths(paths []string) []router.Location {
	out := make([]router.Location, 0, len(paths))
	seen := map[string]struct{}{}
	for _, p := range paths {
		p = strings.TrimSpace(p)
		if p == "" || p == "/" {
			continue
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		p = strings.TrimRight(p, "/")
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, router.Location{Path: p, PathType: "prefix", StripPrefix: true})
	}
	return out
}

func (s *Server) absorbDockerHostAliasRoutes(primary *router.Route, aliases []string) {
	if s == nil || s.table == nil || primary == nil {
		return
	}
	for _, a := range aliases {
		if a == "" || strings.EqualFold(a, primary.Host) {
			continue
		}
		id := dockerHostRouteID(a)
		if id == primary.ID {
			continue
		}
		for _, rt := range s.table.All() {
			if rt.ID != id || !isDockerDiscoveryRoute(rt) {
				continue
			}
			primary.Backends = mergeDiscoveryBackends(primary.Backends, rt.Backends)
			s.table.Delete(rt.ID)
		}
	}
}

func appendUniqueString(list []string, v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return list
	}
	for _, e := range list {
		if strings.EqualFold(e, v) {
			return list
		}
	}
	return append(list, v)
}

func filterEmptyStrings(list []string) []string {
	out := list[:0]
	for _, v := range list {
		if strings.TrimSpace(v) != "" {
			out = append(out, v)
		}
	}
	return out
}

func isDockerDiscoveryRoute(r *router.Route) bool {
	if r == nil {
		return false
	}
	return strings.HasPrefix(r.ID, "docker:") || strings.HasPrefix(r.ID, "docker-host:")
}

func containerIDMatch(stored, incoming string) bool {
	if stored == "" || incoming == "" {
		return false
	}
	if stored == incoming {
		return true
	}
	short := incoming
	if len(short) > 12 {
		short = short[:12]
	}
	return strings.HasPrefix(stored, short) || strings.HasPrefix(incoming, stored)
}

func removeBackendByContainer(backends []router.Backend, containerID string) []router.Backend {
	if containerID == "" {
		return backends
	}
	out := make([]router.Backend, 0, len(backends))
	for _, b := range backends {
		if b.ContainerID != "" && containerIDMatch(b.ContainerID, containerID) {
			continue
		}
		out = append(out, b)
	}
	return out
}

func mergeDiscoveryBackends(existing, incoming []router.Backend) []router.Backend {
	out := append([]router.Backend(nil), existing...)
	for _, in := range incoming {
		replaced := false
		for i := range out {
			if in.ContainerID != "" && out[i].ContainerID == in.ContainerID {
				out[i] = in
				replaced = true
				break
			}
			if in.URL != "" && out[i].URL == in.URL {
				out[i] = in
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, in)
		}
	}
	return out
}

func (s *Server) handleAgentContainerStop(w http.ResponseWriter, r *http.Request) {
	var p struct {
		ContainerID string `json:"container_id"`
		Name        string `json:"name"`
		Relayed     bool   `json:"relayed,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	shortID := p.ContainerID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	changed := false
	for _, rt := range s.table.All() {
		if !isDockerDiscoveryRoute(rt) {
			continue
		}
		// Ancien schéma : une route par conteneur
		prefix := "docker:" + shortID
		if rt.ID == prefix || strings.HasPrefix(rt.ID, prefix+":") {
			if s.table.Delete(rt.ID) {
				changed = true
			}
			continue
		}
		// Pool par host : retirer backend et/ou clear canary/shadow
		if !strings.HasPrefix(rt.ID, "docker-host:") {
			continue
		}
		kept := make([]router.Backend, 0, len(rt.Backends))
		removedBackend := false
		for _, b := range rt.Backends {
			if b.ContainerID != "" && (b.ContainerID == p.ContainerID || strings.HasPrefix(b.ContainerID, shortID)) {
				removedBackend = true
				continue
			}
			kept = append(kept, b)
		}
		clearedCanary := false
		if rt.Canary != nil && containerIDMatch(rt.Canary.ContainerID, p.ContainerID) {
			rt.Canary = nil
			clearedCanary = true
		}
		clearedShadow := false
		if rt.Shadow != nil && containerIDMatch(rt.Shadow.ContainerID, p.ContainerID) {
			rt.Shadow = nil
			clearedShadow = true
		}
		if !removedBackend && !clearedCanary && !clearedShadow {
			continue
		}
		rt.Backends = kept
		if len(kept) == 0 && rt.Canary == nil && rt.Shadow == nil {
			if s.table.Delete(rt.ID) {
				changed = true
			}
			continue
		}
		s.table.Upsert(rt)
		changed = true
	}
	// Routes Portainer : portainer:{endpointID}:{containerID12}:{host}
	for _, rt := range s.table.All() {
		if !strings.HasPrefix(rt.ID, "portainer:") {
			continue
		}
		parts := strings.SplitN(rt.ID, ":", 4)
		if len(parts) >= 3 && parts[2] == shortID {
			if s.table.Delete(rt.ID) {
				changed = true
			}
		}
	}

	if changed {
		metrics.Core.RouteCount.Set(float64(s.table.Len()))
		s.log.Info("agent: routes/backends label retirés", "container", p.Name)
	}
	// Relay suppression portainer aux Cores délégués.
	if !p.Relayed {
		p.Relayed = true
		s.relayDeleteToDelegates(context.Background(), p.ContainerID, p.Name)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListAgentContainers retourne les routes injectées par les Agents (préfixe docker: ou k8s:).
func (s *Server) handleListAgentContainers(w http.ResponseWriter, r *http.Request) {
	type containerRoute struct {
		ID           string         `json:"id"`
		Host         string         `json:"host"`
		Aliases      []string       `json:"aliases,omitempty"`
		Backends     []string       `json:"backends"`
		ContainerIDs []string       `json:"container_ids,omitempty"`
		TLS          bool           `json:"tls"`
		Source       string         `json:"source"`
		AgentName    string         `json:"agent_name,omitempty"`
		Config       map[string]any `json:"config,omitempty"`
	}
	filterAgent := r.URL.Query().Get("agent")
	all := s.table.All()
	result := make([]containerRoute, 0)
	for _, rt := range all {
		src := ""
		if strings.HasPrefix(rt.ID, "docker:") || strings.HasPrefix(rt.ID, "docker-host:") {
			src = "docker"
		} else if strings.HasPrefix(rt.ID, "k8s:") {
			src = "k8s"
		} else if strings.HasPrefix(rt.ID, "portainer:") {
			src = "portainer"
		} else if strings.HasPrefix(rt.ID, "podman:") {
			src = "podman"
		} else {
			continue
		}
		if filterAgent != "" && rt.AgentName != filterAgent {
			continue
		}
		backends := make([]string, 0, len(rt.Backends))
		containerIDs := make([]string, 0, len(rt.Backends))
		seenCID := map[string]struct{}{}
		for _, b := range rt.Backends {
			backends = append(backends, b.URL)
			if b.ContainerID == "" {
				continue
			}
			if _, ok := seenCID[b.ContainerID]; ok {
				continue
			}
			seenCID[b.ContainerID] = struct{}{}
			containerIDs = append(containerIDs, b.ContainerID)
		}
		if rt.Canary != nil && rt.Canary.ContainerID != "" {
			if _, ok := seenCID[rt.Canary.ContainerID]; !ok {
				containerIDs = append(containerIDs, rt.Canary.ContainerID)
			}
		}
		if rt.Shadow != nil && rt.Shadow.ContainerID != "" {
			if _, ok := seenCID[rt.Shadow.ContainerID]; !ok {
				containerIDs = append(containerIDs, rt.Shadow.ContainerID)
			}
		}
		result = append(result, containerRoute{
			ID:           rt.ID,
			Host:         rt.Host,
			Aliases:      append([]string(nil), rt.Aliases...),
			Backends:     backends,
			ContainerIDs: containerIDs,
			TLS:          rt.TLSEnabled || rt.TLSPassthrough,
			Source:       src,
			AgentName:    rt.AgentName,
			Config:       discoveryRouteConfig(rt),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result) //nolint:errcheck
}

// discoveryRouteConfig expose les champs utiles aux badges UI Trafic (même forme que config proxy).
// Le badge LB Adaptatif n'est exposé que lorsqu'il y a réellement un pool multi-backends.
func discoveryRouteConfig(rt *router.Route) map[string]any {
	if rt == nil {
		return nil
	}
	cfg := map[string]any{
		"tls_enabled":     rt.TLSEnabled,
		"tls_passthrough": rt.TLSPassthrough,
	}
	if len(rt.Backends) >= 2 {
		lb := rt.LB
		if lb == "" || lb == router.LBRoundRobin {
			lb = router.LBAdaptive
		}
		cfg["lb"] = lb
	}
	if rt.RateLimit != nil {
		cfg["rate_limit"] = rt.RateLimit
	}
	if rt.IPFilter != nil {
		cfg["ip_filter"] = rt.IPFilter
	}
	if rt.GeoIP != nil {
		cfg["geo_ip"] = rt.GeoIP
	}
	if rt.CORS != nil {
		cfg["cors"] = rt.CORS
	}
	if rt.WAF != nil {
		cfg["waf"] = rt.WAF
	}
	if rt.Bot != nil {
		cfg["bot"] = rt.Bot
	}
	if rt.JWT != nil {
		cfg["jwt"] = rt.JWT
	}
	if rt.MTLS != nil {
		cfg["mtls"] = rt.MTLS
	}
	if rt.SSO != nil {
		cfg["sso"] = rt.SSO
	}
	if rt.AuthProviderID != "" {
		cfg["auth_provider_id"] = rt.AuthProviderID
	}
	if len(rt.SnippetIDs) > 0 {
		cfg["snippet_ids"] = rt.SnippetIDs
	}
	if rt.CircuitBreaker != nil {
		cfg["circuit_breaker"] = rt.CircuitBreaker
	}
	if rt.Retry != nil {
		cfg["retry"] = rt.Retry
	}
	if rt.StickyCookie != "" {
		cfg["sticky_cookie"] = rt.StickyCookie
	}
	if rt.SlowStartSec > 0 {
		cfg["slow_start_sec"] = rt.SlowStartSec
	}
	if rt.LimitConn != nil {
		cfg["limit_conn"] = rt.LimitConn
	}
	if rt.Backpressure != nil {
		cfg["backpressure"] = rt.Backpressure
	}
	if rt.Websocket != nil {
		cfg["websocket"] = *rt.Websocket
	}
	if rt.HttpVersion != "" {
		cfg["http_version"] = rt.HttpVersion
	}
	if rt.RequestID != nil {
		cfg["request_id"] = *rt.RequestID
	}
	if rt.HeadersManipulation != nil {
		cfg["headers_manipulation"] = rt.HeadersManipulation
	}
	if rt.Canary != nil {
		cfg["canary"] = rt.Canary
	}
	if rt.Shadow != nil {
		cfg["shadow"] = rt.Shadow
	}
	if len(rt.Locations) > 0 {
		cfg["locations"] = rt.Locations
	}
	if rt.Logging != nil {
		cfg["logging"] = rt.Logging
	}
	return cfg
}

func (s *Server) handleAgentEvent(w http.ResponseWriter, r *http.Request) {
	var e struct {
		NodeName    string `json:"node_name"`
		ContainerID string `json:"container_id"`
		EventType   string `json:"event_type"`
		Detail      string `json:"detail"`
	}
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ev := s.nodeStore.RecordEvent(coreagent.NodeEvent{
		NodeName:    e.NodeName,
		ContainerID: e.ContainerID,
		EventType:   e.EventType,
		Detail:      e.Detail,
	})
	// Relayer vers Admin pour persistance SQLite (historique UI)
	if payload, err := json.Marshal(ev); err == nil {
		s.wsHub.BroadcastToAdmins(corews.Message{Type: corews.TypeAgentEvent, Payload: payload})
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleAgentLogs(w http.ResponseWriter, r *http.Request) {
	// Relais transparent vers Admin (Prism / Logs) — pas de stockage local.
	var batch struct {
		ContainerID   string `json:"container_id"`
		ContainerName string `json:"container_name"`
		Entries       []struct {
			T    time.Time `json:"t"`
			Line string    `json:"line"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, "JSON invalide", http.StatusBadRequest)
		return
	}
	if len(batch.Entries) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	payload := make([]corews.LogEntryPayload, 0, len(batch.Entries))
	for _, e := range batch.Entries {
		ts := e.T
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		payload = append(payload, corews.LogEntryPayload{
			Ts:        ts.Format(time.RFC3339Nano),
			Level:     "info",
			Component: "agent",
			NodeName:  s.cfg.Identity.NodeName,
			Domain:    batch.ContainerName,
			Message:   e.Line,
		})
	}
	msg, err := corews.NewMessage(0, corews.TypeAgentLog, payload)
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	s.wsHub.BroadcastToAdmins(msg)
	w.WriteHeader(http.StatusNoContent)
}

// handleCorePair émet un token Agent local sans passer par l'Admin.
// Protégé uniquement par GPX_PAIRING_SECRET (identique à Admin).
// Permet aux Agents sur des hôtes distants de s'appairer avec leur Core local.
func (s *Server) handleCorePair(w http.ResponseWriter, r *http.Request) {
	configuredSecret := os.Getenv("GPX_PAIRING_SECRET")
	var req struct {
		Secret   string `json:"secret"`
		NodeName string `json:"node_name"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if configuredSecret == "" {
		http.Error(w, "pairing non configuré", http.StatusServiceUnavailable)
		return
	}
	if len(configuredSecret) != len(req.Secret) ||
		subtle.ConstantTimeCompare([]byte(configuredSecret), []byte(req.Secret)) != 1 {
		http.Error(w, "secret invalide", http.StatusForbidden)
		return
	}
	nodeName := req.NodeName
	if nodeName == "" {
		nodeName = "agent"
	}
	token, _, err := s.tokenStore.Create(nodeName, coretokens.RoleAgent, 0)
	if err != nil {
		s.log.Error("core: création token appairage agent", "err", err)
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	// L'Agent a prouvé son identité via GPX_PAIRING_SECRET : pré-approuver pour que
	// la prochaine connexion WS avec ce token soit acceptée sans intervention humaine.
	if err := s.wsHub.ApproveAgent(nodeName); err != nil {
		s.log.Warn("core: pré-approbation WS échouée", "node", nodeName, "err", err)
	}
	s.log.Info("core: appairage agent accepté", "node", nodeName)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"token": token}) //nolint:errcheck
}

// --- Endpoints lecture nœuds (Admin → Core) ------------------------------

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.nodeStore.All()) //nolint:errcheck
}

func (s *Server) handleListNodeEvents(w http.ResponseWriter, r *http.Request) {
	limit := 200
	nodeFilter := r.URL.Query().Get("node")
	w.Header().Set("Content-Type", "application/json")
	evs := s.nodeStore.Events(limit)
	if nodeFilter != "" {
		filtered := make([]coreagent.NodeEvent, 0, len(evs))
		for _, e := range evs {
			if e.NodeName == nodeFilter {
				filtered = append(filtered, e)
			}
		}
		evs = filtered
	}
	json.NewEncoder(w).Encode(evs) //nolint:errcheck
}

// agentOfflineLoop marque les Agents inactifs depuis plus de 90 s comme "offline".
// handleAgentRescanRelay relaie une commande rescan d'Admin vers l'Agent.
// Admin → Core (ce handler) → Agent (internal API).
// Le relay via Core est nécessaire car Admin est cross-machine et ne peut
// pas résoudre les endpoints Docker internes des agents.
func (s *Server) handleAgentRescanRelay(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	if s.wsHub.IsAgentConnected(name) {
		body, _ := json.Marshal(map[string]string{"action": "rescan"})
		msg, err := corews.NewMessage(0, corews.TypeRescan, json.RawMessage(body))
		if err != nil {
			http.Error(w, "erreur interne", http.StatusInternalServerError)
			return
		}
		if err := s.wsHub.SendToAgentByName(name, msg); err != nil {
			s.log.Warn("rescan relay: WS échoué", "agent", name, "err", err)
			http.Error(w, "agent injoignable", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	all := s.nodeStore.All()
	s.log.Info("rescan relay: recherche agent", "name", name, "nodestore_count", len(all))
	var agentEndpoint string
	for _, n := range all {
		s.log.Info("rescan relay: nœud connu", "node_name", n.NodeName, "endpoint", n.Endpoint, "status", n.Status)
		if n.NodeName == name && n.Endpoint != "" {
			agentEndpoint = n.Endpoint
			break
		}
	}
	if agentEndpoint == "" {
		s.log.Warn("rescan relay: agent introuvable dans nodestore", "name", name)
		http.Error(w, "agent introuvable ou endpoint inconnu", http.StatusNotFound)
		return
	}
	s.log.Info("rescan relay: forward vers agent", "name", name, "endpoint", agentEndpoint)

	body, _ := json.Marshal(map[string]string{"action": "rescan"})
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		agentEndpoint+"/internal/v1/command", bytes.NewReader(body))
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	setAgentInternalAuth(req)

	resp, err := agentRelayHTTP.Do(req)
	if err != nil {
		s.log.Warn("rescan relay: agent injoignable", "agent", name, "endpoint", agentEndpoint, "err", err)
		http.Error(w, "agent injoignable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
}

// handleAgentCommandRelay relaie une commande JSON arbitraire vers l'Agent.
func (s *Server) handleAgentCommandRelay(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "erreur lecture body", http.StatusBadRequest)
		return
	}

	// Priorité WS : l'agent connecté n'a pas besoin d'endpoint HTTP exposé.
	if s.wsHub.IsAgentConnected(name) {
		msgType := corews.TypeCommand
		var cmd map[string]string
		if json.Unmarshal(body, &cmd) == nil && cmd["action"] == "rescan" {
			msgType = corews.TypeRescan
		}
		msg, err := corews.NewMessage(0, msgType, json.RawMessage(body))
		if err != nil {
			http.Error(w, "erreur interne", http.StatusInternalServerError)
			return
		}
		if err := s.wsHub.SendToAgentByName(name, msg); err != nil {
			s.log.Warn("command relay: WS échoué", "agent", name, "err", err)
			http.Error(w, "agent injoignable", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	n, ok := s.nodeStore.Get(name)
	if !ok || n.Endpoint == "" {
		http.Error(w, "agent introuvable ou endpoint inconnu", http.StatusNotFound)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		n.Endpoint+"/internal/v1/command", bytes.NewReader(body))
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	setAgentInternalAuth(req)
	resp, err := agentRelayHTTP.Do(req)
	if err != nil {
		s.log.Warn("command relay: agent injoignable", "agent", name, "endpoint", n.Endpoint, "err", err)
		http.Error(w, "agent injoignable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
}

// setAgentInternalAuth pose le Bearer partagé (GPX_PAIRING_SECRET) pour l'API Agent :8001.
func setAgentInternalAuth(req *http.Request) {
	if secret := os.Getenv("GPX_PAIRING_SECRET"); secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
}

func (s *Server) agentOfflineLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.nodeStore.MarkOffline(90 * time.Second)
		}
	}
}

