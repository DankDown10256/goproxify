// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/httpx"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vincamok/goproxify/internal/edge/plugins"
	"context"
	"encoding/json"
	"fmt"
	"github.com/vincamok/goproxify/internal/edge/tracing"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	edgecrowdsec "github.com/vincamok/goproxify/internal/edge/crowdsec"
	"github.com/vincamok/goproxify/internal/edge/errorpages"
	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/portal"
	"github.com/vincamok/goproxify/internal/edge/router"
	edgere "github.com/vincamok/goproxify/internal/edge/rulesengine"
	"github.com/vincamok/goproxify/internal/edge/threat"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
	edgetokens "github.com/vincamok/goproxify/internal/edge/tokens"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// --- API interne :8000 ---------------------------------------------------

func (s *Server) startInternalAPI() error {
	if s.cfg.Network.InternalAPIPort == 0 {
		s.cfg.Network.InternalAPIPort = 8000
	}
	addr := fmt.Sprintf("%s:%d", s.cfg.Network.BindAddress, s.cfg.Network.InternalAPIPort)
	mux := http.NewServeMux()

	// WebSocket — plan de contrôle (pas soumis à authMiddleware)
	mux.HandleFunc("/ws/admin", s.wsHub.ServeAdmin)
	mux.HandleFunc("/ws/agent", s.wsHub.ServeAgent)

	mux.HandleFunc("POST /internal/v1/routes", s.handlePushRoutes)
	mux.HandleFunc("DELETE /internal/v1/routes/{id}", s.handleDeleteRoute)
	mux.HandleFunc("GET /internal/v1/proxies", s.handleListFileProxies)
	mux.HandleFunc("POST /internal/v1/proxies/revisions", s.handleCreateProxyRevision)
	mux.HandleFunc("GET /internal/v1/proxies/{id}", s.handleGetFileProxy)
	mux.HandleFunc("DELETE /internal/v1/proxies/{id}", s.handleDeleteFileProxy)
	mux.HandleFunc("POST /internal/v1/proxies/{id}/cache/purge", s.handlePurgeProxyCache)
	mux.HandleFunc("GET /internal/v1/proxies/{id}/revisions", s.handleListProxyRevisions)
	mux.HandleFunc("POST /internal/v1/proxies/{id}/revisions/{rev}/dry-run", s.handleDryRunProxyRevision)
	mux.HandleFunc("POST /internal/v1/proxies/{id}/revisions/{rev}/promote", s.handlePromoteProxyRevision)
	mux.HandleFunc("POST /internal/v1/proxies/{id}/revisions/{rev}/reject", s.handleRejectProxyRevision)
	mux.HandleFunc("POST /internal/v1/delegations", s.handlePushDelegations)
	mux.HandleFunc("POST /internal/v1/certs", s.handlePushCerts)
	mux.HandleFunc("POST /internal/v1/snippets", s.handlePushSnippets)
	mux.HandleFunc("POST /internal/v1/error-pages", s.handlePushErrorPages)
	mux.HandleFunc("POST /internal/v1/plugins", s.handlePushPlugins)
	mux.HandleFunc("POST /internal/v1/auth-providers", s.handlePushAuthProviders)
	mux.HandleFunc("POST /internal/v1/ip-profiles", s.handlePushIPProfiles)
	mux.HandleFunc("POST /internal/v1/bans", s.handlePushBans)
	mux.HandleFunc("POST /internal/v1/bans/gossip", s.handleBansGossip)
	mux.HandleFunc("GET /internal/v1/bans", s.handleListBans)
	mux.HandleFunc("GET "+logapi.PathRejections, s.handleRejections)
	mux.HandleFunc("GET "+logapi.PathSeasonal, s.handleSeasonal)
	mux.HandleFunc("GET /internal/v1/backup/export", s.handleBackupExport)
	mux.HandleFunc("POST /internal/v1/backup/restore", s.handleBackupRestore)
	mux.HandleFunc("GET /internal/v1/bans/history", s.handleListBanHistory)
	mux.HandleFunc("DELETE /internal/v1/bans/{id}", s.handleDeleteBan)
	mux.HandleFunc("POST /internal/v1/threat-config", s.handlePushThreatConfig)
	mux.HandleFunc("POST /internal/v1/server-config", s.handlePushServerConfig)
	mux.HandleFunc("POST /internal/v1/threat-lists/sync", s.handleHAThreatSync)
	mux.HandleFunc("GET /internal/v1/threat-lists/export", s.handleHAThreatExport)
	mux.HandleFunc("POST /internal/v1/waf/behavior/sync", s.handleHAWAFBehaviorSync)
	mux.HandleFunc("GET /internal/v1/waf/behavior/export", s.handleHAWAFBehaviorExport)
	mux.HandleFunc("GET "+logapi.PathSurfaceExport, s.handleSurfaceExport)
	mux.HandleFunc("GET "+logapi.PathInventoryExport, s.handleInventoryExport)
	mux.HandleFunc("GET /internal/v1/waf/behavior/profiles", s.handleWAFBehaviorProfiles)
	mux.HandleFunc("DELETE /internal/v1/waf/behavior/profiles/{ip}", s.handleWAFBehaviorDeleteProfile)
	mux.HandleFunc("POST /internal/v1/settings", s.handlePushSettings)
	mux.HandleFunc("POST /internal/v1/portal", s.handlePushPortal)
	mux.HandleFunc("GET /internal/v1/portal/recordings", s.handlePortalRecordingsList)
	mux.HandleFunc("GET /internal/v1/portal/sessions/{id}/watch", s.handlePortalSessionWatch)
	mux.HandleFunc("GET /internal/v1/portal/recordings/{id}", s.handlePortalRecordingGet)
	mux.HandleFunc("DELETE /internal/v1/portal/recordings/{id}", s.handlePortalRecordingDelete)
	mux.HandleFunc("GET /internal/v1/portal/replica", s.handlePortalReplicaExport)
	mux.HandleFunc("POST /internal/v1/portal/replica", s.handlePortalReplicaImport)
	mux.HandleFunc("GET /internal/v1/agents/replica", s.handleAgentReplicaExport)
	mux.HandleFunc("POST /internal/v1/agents/replica", s.handleAgentReplicaImport)
	mux.HandleFunc("GET "+agentNodesReplicaPath, s.handleAgentNodesReplicaExport)
	mux.HandleFunc("GET "+proxyReplicaPath, s.handleProxyReplicaExport)
	mux.HandleFunc("GET "+pushedReplicaPath, s.handlePushedReplicaExport)
	mux.HandleFunc("GET "+groupCardPath, s.handleGroupCard)
	mux.HandleFunc("POST "+groupRuleFiredPath, s.handleGroupRuleFired)
	mux.HandleFunc("GET "+agentStateReplicaPath, s.handleAgentStateReplicaExport)
	mux.HandleFunc("POST "+agentStateReplicaPath, s.handleAgentStateReplicaImport)
	mux.HandleFunc("GET "+echReplicaPath, s.handleECHReplicaExport)
	mux.HandleFunc("POST "+echReplicaPath, s.handleECHReplicaImport)
	mux.HandleFunc("POST /internal/v1/gateway/peers", s.handlePushGatewayPeers)
	mux.HandleFunc("POST /internal/v1/gateway/tunnel", s.handleGatewayTunnel)
	mux.HandleFunc("GET /internal/v1/lb/scores", s.handleLBScores)
	mux.HandleFunc("GET /internal/v1/ratelimit/export", s.handleQuotaExport)
	mux.HandleFunc("GET /internal/v1/ratelimit/rates", s.handleRateExport)
	mux.HandleFunc("GET /internal/v1/health", s.handleInternalHealth)
	mux.HandleFunc("GET /internal/v1/backends/health", s.handleBackendsHealth)
	mux.HandleFunc("GET /internal/v1/metrics/summary", s.handleMetricsSummary)
	mux.Handle("GET /internal/v1/metrics", promhttp.Handler())
	// Chemin par défaut d'un scrape Prometheus ; protégé par le jeton comme le reste de l'API interne.
	mux.Handle("GET /metrics", promhttp.Handler())

	// Endpoints Agent → passerelle
	mux.HandleFunc("POST /internal/v1/agent/heartbeat", s.handleAgentHeartbeat)
	mux.HandleFunc("POST /internal/v1/agent/containers", s.handleAgentContainerStart)
	mux.HandleFunc("DELETE /internal/v1/agent/containers", s.handleAgentContainerStop)
	mux.HandleFunc("PUT /internal/v1/agent/state", s.handleAgentState)
	mux.HandleFunc("POST /internal/v1/agent/events", s.handleAgentEvent)
	mux.HandleFunc("POST /internal/v1/agent/logs", s.handleAgentLogs)

	// Recherche dans la base de logs de la passerelle (appelée par l'Admin, ADR 0012).
	s.registerLogRoutes(mux)

	// Relay Admin → Agent (Admin appelle passerelle, Passerelle relaie à l'Agent)
	mux.HandleFunc("POST /internal/v1/agent/{name}/rescan", s.handleAgentRescanRelay)
	mux.HandleFunc("POST /internal/v1/agent/{name}/command", s.handleAgentCommandRelay)

	// Endpoints passerelle → Admin (lecture de l'état des nœuds et conteneurs)
	mux.HandleFunc("GET /internal/v1/nodes", s.handleListNodes)
	mux.HandleFunc("GET /internal/v1/node-events", s.handleListNodeEvents)
	mux.HandleFunc("GET /internal/v1/agent/containers", s.handleListAgentContainers)

	// Appairage local Agent → passerelle (protégé par GPX_PAIRING_SECRET, fail-closed)
	mux.HandleFunc("POST /internal/v1/pair", s.handleEdgePair)

	s.intSrv = httpx.Harden(&http.Server{Addr: addr, Handler: limitInternalBodies(s.authMiddleware(mux))})
	go func() {
		if err := s.intSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.Error("internal api", "err", err)
		}
	}()
	return nil
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ces chemins ont leur propre authentification — ils bypassent le bearer token.
		// /ws/admin  : HMAC-SHA256 validé dans ServeAdmin (ValidateAdminHMAC)
		// /ws/agent  : join token ou agent_hmac validés dans ServeAgent
		// /internal/v1/pair : protégé par GPX_PAIRING_SECRET
		switch r.URL.Path {
		case "/ws/admin", "/ws/agent", "/internal/v1/pair":
			next.ServeHTTP(w, r)
			return
		}
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer == "" {
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}
		role, ok, err := s.tokenStore.RoleOf(bearer)
		if err != nil || !ok {
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}
		if role == edgetokens.RoleAgent && !agentTokenMayCall(r.Method, r.URL.Path) {
			http.Error(w, "403 Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handlePushDelegations reçoit les routes synthétiques de délégation inter-passerelle.
// Contrairement à handlePushRoutes (qui remplace tout), les délégations sont
// fusionnées : les routes normales restent intactes, seules les routes "deleg-*" sont mises à jour.
func (s *Server) handlePushDelegations(w http.ResponseWriter, r *http.Request) {
	var routes []*router.Route
	if err := json.NewDecoder(r.Body).Decode(&routes); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.applyDelegationRoutes(routes)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) applyDelegationRoutes(routes []*router.Route) {
	// Supprimer les anciennes routes de délégation, puis upsert les nouvelles
	for _, existing := range s.table.All() {
		if strings.HasPrefix(existing.ID, "deleg-") {
			s.table.Delete(existing.ID)
		}
	}
	for _, route := range routes {
		if route == nil {
			continue
		}
		// Délégation : respecter TLSPassthrough du payload (terminate vs passthrough).
		// TLSSkipVerify n'est plus forcé ici — uniquement si le payload Admin l'indique.
		if strings.HasPrefix(route.ID, "deleg-") {
			route.TLSEnabled = true
			if !route.TLSPassthrough {
				// Terminate : proxy HTTP(S) — SNI backend géré via hostSNITransport.
				if route.PreserveHost == nil {
					t := true
					route.PreserveHost = &t
				}
			}
			s.log.Info("délégation appliquée",
				"id", route.ID, "host", route.Host,
				"tls_passthrough", route.TLSPassthrough,
				"backend", backendURL(route),
			)
			s.upsertImplicitRoute(route)
			continue
		}
		s.table.Upsert(route)
	}
	// Purge les proxies exacts locaux qui masqueraient un passthrough (délégation).
	removed := s.purgeRoutesShadowedByPassthrough()
	s.saveCache()
	s.log.Info("délégations mises à jour", "count", len(routes), "purged_conflicts", removed)
}

func backendURL(r *router.Route) string {
	if r == nil || len(r.Backends) == 0 {
		return ""
	}
	return r.Backends[0].URL
}

// purgeRoutesShadowedByPassthrough retire les routes non-passthrough dont le host
// est couvert par une délégation wildcard (deleg-* *.domaine).
func (s *Server) purgeRoutesShadowedByPassthrough() int {
	var patterns []string
	for _, r := range s.table.All() {
		// Critère principal : ID deleg-* (fiable même si le bool a été perdu en transit).
		if strings.HasPrefix(r.ID, "deleg-") && strings.HasPrefix(r.Host, "*.") {
			patterns = append(patterns, r.Host)
			continue
		}
		if r.TLSPassthrough && strings.HasPrefix(r.Host, "*.") {
			patterns = append(patterns, r.Host)
		}
	}
	if len(patterns) == 0 {
		return 0
	}
	removed := 0
	for _, r := range s.table.All() {
		if r.TLSPassthrough || strings.HasPrefix(r.ID, "deleg-") {
			continue
		}
		shadowed := false
		for _, p := range patterns {
			if router.HostCoveredByPattern(r.Host, p) {
				shadowed = true
				break
			}
			for _, a := range r.Aliases {
				if router.HostCoveredByPattern(a, p) {
					shadowed = true
					break
				}
			}
			if shadowed {
				break
			}
		}
		if shadowed {
			s.table.Delete(r.ID)
			removed++
			s.log.Info("route locale purgée (masquée par délégation passthrough)",
				"id", r.ID, "host", r.Host)
		}
	}
	return removed
}

func (s *Server) handlePushRoutes(w http.ResponseWriter, r *http.Request) {
	var routes []*router.Route
	if err := json.NewDecoder(r.Body).Decode(&routes); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Préserver agents + proxies fichiers (source de vérité sur disque).
	routes = s.mergePushPreservingFileProxies(routes)
	if err := s.table.Replace(routes); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.ensurePortalPublicRoute()
	purged := s.purgeRoutesShadowedByPassthrough()
	metrics.Edge.RouteCount.Set(float64(s.table.Len()))
	s.syncHealthChecks()
	s.saveCache()
	s.log.Info("routes remplacées", "count", len(routes), "purged_conflicts", purged)
	w.WriteHeader(http.StatusNoContent)
}

func isAgentRoute(id string) bool {
	return strings.HasPrefix(id, portalPublicRouteID) ||
		router.IsDiscoveredID(id) ||
		strings.HasPrefix(id, "deleg-")
}

func (s *Server) handlePushCerts(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Name    string `json:"name"`
		CertPEM []byte `json:"cert_pem"`
		KeyPEM  []byte `json:"key_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.certStore.StorePEM(payload.Name, payload.CertPEM, payload.KeyPEM); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	s.writeCertToDisk(payload.Name, payload.CertPEM, payload.KeyPEM)
	metrics.Edge.CertCount.Set(float64(s.certStore.Len()))
	metrics.UpdateCertExpiries(s.certStore.CertExpiries())
	s.saveCache()
	s.log.Info("certificat mis à jour", "name", payload.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.table.Delete(id) {
		metrics.Edge.RouteCount.Set(float64(s.table.Len()))
		s.saveCache()
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePushSnippets(w http.ResponseWriter, r *http.Request) {
	var snippets []*router.Snippet
	if err := json.NewDecoder(r.Body).Decode(&snippets); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.snippetStore.Replace(snippets)
	s.saveCache()
	s.log.Info("snippets mis à jour", "count", len(snippets))
	w.WriteHeader(http.StatusNoContent)
}

// handlePushPlugins aligne les plugins sur la liste complète envoyée (même effet que le message WebSocket
// push_plugins) : installe les nouveaux ou modifiés, retire les absents.
func (s *Server) handlePushPlugins(w http.ResponseWriter, r *http.Request) {
	var pkgs []plugins.Package
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<20)).Decode(&pkgs); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.applyPlugins(pkgs)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePushAuthProviders(w http.ResponseWriter, r *http.Request) {
	var providers []*router.AuthProvider
	if err := json.NewDecoder(r.Body).Decode(&providers); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.providerStore.Replace(providers)
	s.saveCache()
	s.log.Info("fournisseurs auth mis à jour", "count", len(providers))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePushIPProfiles(w http.ResponseWriter, r *http.Request) {
	var profiles []*router.IPProfile
	if err := json.NewDecoder(r.Body).Decode(&profiles); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.applyIPProfiles(profiles)
	s.log.Info("profils IP mis à jour", "count", len(profiles))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePushThreatConfig(w http.ResponseWriter, r *http.Request) {
	var cfg threat.Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.applyThreatConfig(cfg)
	s.log.Info("threat: config mise à jour", "enabled", cfg.Enabled)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePushServerConfig(w http.ResponseWriter, r *http.Request) {
	var body pushedServerConfig
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.applyServerConfig(body)
	s.log.Info("server-config mis à jour (redémarrage requis pour appliquer les timeouts)")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleHAThreatSync(w http.ResponseWriter, r *http.Request) {
	var p threat.HAPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.threatEngine != nil {
		s.threatEngine.ApplyHAPayload(p)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleHAThreatExport(w http.ResponseWriter, r *http.Request) {
	if s.threatEngine == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	p := s.threatEngine.BuildHAPayload()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p) //nolint:errcheck
}

func (s *Server) handleWAFBehaviorProfiles(w http.ResponseWriter, r *http.Request) {
	if s.wafEngine == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("{}")) //nolint:errcheck
		return
	}
	profiles := s.wafEngine.BehaviorProfiles()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profiles) //nolint:errcheck
}

func (s *Server) handleWAFBehaviorDeleteProfile(w http.ResponseWriter, r *http.Request) {
	if s.wafEngine == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	ip := r.PathValue("ip")
	if ip == "" {
		http.Error(w, "ip requis", http.StatusBadRequest)
		return
	}
	s.wafEngine.DeleteBehaviorProfile(ip)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleHAWAFBehaviorExport(w http.ResponseWriter, r *http.Request) {
	if s.wafEngine == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	p := s.wafEngine.BehaviorStore().BuildHAPayload()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(p) //nolint:errcheck
}

func (s *Server) handleHAWAFBehaviorSync(w http.ResponseWriter, r *http.Request) {
	if s.wafEngine == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var p behavior.HAPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.wafEngine.BehaviorStore().ApplyHAPayload(p)
	w.WriteHeader(http.StatusNoContent)
}

// threatBanCallback retourne la fonction appelée par Ephor (et le WAF) quand ils bannissent une IP.
// Comme pour les autres bans automatiques, le ban est persisté localement : il s'applique et survit à un redémarrage sans
// l'Admin, qui est seulement notifié.
func (s *Server) threatBanCallback() threat.BanCallback {
	return func(ip, reason string, expires time.Time, signals []router.BanSignal) {
		// Un scanner qui ouvre des centaines de connexions avant que le premier ban soit actif rappelait ce
		// callback à chaque requête : base locale, pairs, rechargement des bans et Admin, autant de fois.
		if ok, _ := s.blockLog.Allow("threatban|" + ip); !ok {
			return
		}
		b := &router.RuntimeBan{
			ID:        "threat-" + ip,
			IP:        ip,
			Reason:    reason,
			Source:    "threat",
			ExpiresAt: &expires,
			Signals:   signals,
			UserAgent: s.lastUA.Get(ip),
		}
		s.addBanEvent(ip, "threat")
		s.gossipBanToPeers(b)
		if s.bansDB != nil {
			if err := s.bansDB.UpsertRuntimeBan(b); err != nil {
				s.log.Warn(threat.Name+": persistance ban DB échouée", "err", err)
			}
		}
		s.reloadBanStore()
		s.log.Info(threat.Name+": IP bannie", "ip", ip, "reason", reason)

		// Notifier Admin pour persister le ban dans security_bans.
		payload := edgews.ThreatBanPayload{
			IP:        ip,
			Reason:    reason,
			ExpiresAt: expires.UTC().Format(time.RFC3339),
			NodeName:  s.cfg.Identity.NodeName,
			Signals:   signals,
			UserAgent: b.UserAgent,
		}
		if msg, err := edgews.NewMessage(0, edgews.TypeThreatBan, payload); err == nil {
			s.wsHub.BroadcastToAdmins(msg)
		}
	}
}

// onCrowdSecBansChanged applique la liste complète des bans CrowdSec dans le banStore.
// Remplace tous les bans crowdsec existants en DB, conserve les autres sources.
func (s *Server) onCrowdSecBansChanged(csBans []edgecrowdsec.Ban) {
	if s.bansDB != nil {
		if err := s.bansDB.DeleteBansBySource("crowdsec"); err != nil {
			s.log.Warn("crowdsec: suppression bans DB échouée", "err", err)
		}
		for _, b := range csBans {
			b := b
			s.addBanEvent(b.IP, "crowdsec")
			if err := s.bansDB.UpsertBan(b.ID, b.IP, "", b.Reason, "crowdsec", b.ExpiresAt); err != nil {
				s.log.Warn("crowdsec: persistance ban DB échouée", "err", err)
			}
		}
	}
	s.reloadBanStore()
	s.log.Info("crowdsec: bans appliqués", "count", len(csBans))
}

// onCrowdSecDecisions notifie l'Admin des nouvelles/supprimées décisions CrowdSec.
func (s *Server) onCrowdSecDecisions(added, deleted []edgecrowdsec.Decision) {
	payload := edgews.CrowdSecDecisionsPayload{
		NodeName: s.cfg.Identity.NodeName,
	}
	for _, d := range added {
		if s.threatEngine != nil && d.Scope == "Ip" && strings.EqualFold(d.Type, "ban") {
			until := time.Time{}
			if dur, err := time.ParseDuration(d.Duration); err == nil && dur > 0 {
				until = time.Now().Add(dur)
			}
			s.threatEngine.NoteDecision(d.Value, behavior.SignalCrowdSec, 5, until)
		}
		payload.Added = append(payload.Added, edgews.CrowdSecDecision{
			Value: d.Value, Scenario: d.Scenario, Origin: d.Origin,
			Type: d.Type, Duration: d.Duration, Scope: d.Scope,
		})
	}
	for _, d := range deleted {
		payload.Deleted = append(payload.Deleted, edgews.CrowdSecDecision{
			Value: d.Value, Scenario: d.Scenario, Origin: d.Origin,
			Type: d.Type, Duration: d.Duration, Scope: d.Scope,
		})
	}
	if msg, err := edgews.NewMessage(0, edgews.TypeCrowdSecDecisions, payload); err == nil {
		s.wsHub.BroadcastToAdmins(msg)
	}
}

// --- BanStore helpers --------------------------------------------------------

// reloadBanStore reconstruit le BanStore en mémoire depuis la DB.
func (s *Server) reloadBanStore() {
	s.bansMu.Lock()
	defer s.bansMu.Unlock()
	var dbBans []*router.RuntimeBan
	if s.bansDB != nil {
		rows, err := s.bansDB.ActiveBans()
		if err != nil {
			s.log.Warn("bansdb: lecture bans actifs échouée", "err", err)
		} else {
			for _, r := range rows {
				r := r
				rb := &router.RuntimeBan{
					ID:        r.ID,
					IP:        r.IP,
					Reason:    r.Reason,
					Source:    r.Source,
					ExpiresAt: r.ExpiresAt,
					Signals:   r.Signals,
					UserAgent: r.UserAgent,
				}
				if s.autoBanWhitelisted(rb) {
					continue
				}
				dbBans = append(dbBans, rb)
			}
		}
	}
	s.banStore.Replace(dbBans)
}

// autoBanWhitelisted : la liste blanche d'Ephor prime aussi sur les bans que ce moteur et les plugins
// ont déjà posés — ajouter une IP à la liste blanche la débloque sans attendre l'expiration.
func (s *Server) autoBanWhitelisted(b *router.RuntimeBan) bool {
	switch b.Source {
	case "threat":
		return s.threatEngine != nil && s.threatEngine.WhitelistedIP(b.IP)
	}
	if strings.HasPrefix(b.Source, edgews.PluginBanSourcePrefix) {
		return s.profileStore.IsWhitelisted(b.IP) || (s.threatEngine != nil && s.threatEngine.WhitelistedIP(b.IP))
	}
	return false
}

// applyUnbans lève, quelle que soit leur source (Ephor local, plugin, règle, pair HA, Admin),
// les bans des IPs débannies depuis l'Admin. Un déban à l'instant remet aussi à zéro les compteurs
// des moteurs pour que l'IP ne soit pas rebannie sur ses erreurs passées.
func (s *Server) applyUnbans(list []edgews.UnbanEntry) {
	now := time.Now()
	for _, u := range list {
		if u.IP == "" {
			continue
		}
		at := now
		if u.At != nil && u.At.Before(now) {
			at = *u.At
		}
		if s.bansDB != nil {
			if err := s.bansDB.Unban(u.IP, at); err != nil {
				s.log.Warn("bansdb: déban échoué", "ip", u.IP, "err", err)
			}
		}
		if u.At != nil {
			continue
		}
		if s.threatEngine != nil {
			s.threatEngine.ResetIP(u.IP)
		}
	}
	s.reloadBanStore()
}

// --- Moteur de règles automatiques (Passerelle) ------------------------------------

// addBanEvent enregistre un ban dans l'historique DB (pour CondBanSpike / CondBanRepeat).
func (s *Server) addBanEvent(ip, source string) {
	if s.bansDB == nil {
		return
	}
	if err := s.bansDB.RecordBanEvent(ip, source); err != nil {
		s.log.Warn("bansdb: enregistrement événement ban échoué", "err", err)
	}
}

// priorThreatBans retourne le nombre de bans Ephor déjà posés sur l'IP depuis `since`, pour que
// Ephor allonge les bans des récidivistes.
func (s *Server) priorThreatBans(ip string, since time.Time) int {
	if s.bansDB == nil {
		return 0
	}
	n, err := s.bansDB.BanCountForIP(ip, "threat", since)
	if err != nil {
		s.log.Warn("bansdb: BanCountForIP échoué", "err", err)
		return 0
	}
	return n
}

// recentBanCount retourne le nombre de bans depuis `since` (source="" = toutes).
func (s *Server) recentBanCount(since time.Time, source string) int {
	if s.bansDB == nil {
		return 0
	}
	n, err := s.bansDB.RecentBanCount(since, source)
	if err != nil {
		s.log.Warn("bansdb: recentBanCount échoué", "err", err)
		return 0
	}
	return n
}

// repeatBanIP retourne l'IP bannie ≥ minCount fois depuis `since`.
func (s *Server) repeatBanIP(since time.Time, minCount int) (string, int) {
	if s.bansDB == nil {
		return "", 0
	}
	ip, n, err := s.bansDB.RepeatBanIP(since, minCount)
	if err != nil {
		s.log.Warn("bansdb: repeatBanIP échoué", "err", err)
		return "", 0
	}
	return ip, n
}

// recordProxyEvent est branché sur accessLog.SetProxyTap pour alimenter CondProxyErrorRate.
func (s *Server) recordProxyEvent(domain string, status int) {
	if domain == "" || s.bansDB == nil {
		return
	}
	if err := s.bansDB.RecordProxyEvent(domain, status >= 500); err != nil {
		s.log.Warn("bansdb: recordProxyEvent échoué", "err", err)
	}
}

// proxyErrorRate retourne le pire taux d'erreurs HTTP parmi tous les domaines.
func (s *Server) proxyErrorRate(since time.Time) (rate float64, host string) {
	if s.bansDB == nil {
		return 0, ""
	}
	rate, host, err := s.bansDB.ProxyErrorRate(since, 10)
	if err != nil {
		s.log.Warn("bansdb: proxyErrorRate échoué", "err", err)
		return 0, ""
	}
	return rate, host
}

// addRuleBan ajoute un ban déclenché par une règle automatique dans le banStore.
func (s *Server) addRuleBan(ip, reason string, duration time.Duration) {
	var expires *time.Time
	if duration > 0 {
		t := time.Now().Add(duration)
		expires = &t
	}
	id := "rule:" + ip
	rb := &router.RuntimeBan{
		ID:        id,
		IP:        ip,
		Reason:    reason,
		Source:    "rules_engine",
		ExpiresAt: expires,
		UserAgent: s.lastUA.Get(ip),
	}
	s.addBanEvent(ip, "rules_engine")
	if s.bansDB != nil {
		if err := s.bansDB.UpsertRuntimeBan(rb); err != nil {
			s.log.Warn("rulesengine: persistance ban DB échouée", "err", err)
		}
	}
	s.reloadBanStore()
	s.log.Info("rulesengine: IP bannie", "ip", ip, "reason", reason)
}

// onRuleFired est appelé par le moteur de règles après chaque déclenchement.
// Il notifie l'Admin via WS, qui le journalise dans les exécutions du flux.
func (s *Server) onRuleFired(log edgere.ExecLog) {
	payload := edgews.RuleFiredPayload{
		NodeName:    s.cfg.Identity.NodeName,
		RuleID:      log.RuleID,
		RuleName:    log.RuleName,
		ActionType:  log.ActionType,
		CondResult:  log.CondResult,
		ActionTaken: log.ActionTaken,
		Silenced:    log.Silenced,
		Detail:      log.Detail,
		Error:       log.Error,
		FiredAt:     log.FiredAt.UTC().Format(time.RFC3339),
	}
	// Une notification vue par plusieurs membres d'un groupe ne remonte qu'une fois : l'exécutant du groupe la remonte.
	if isNotifyFiring(payload) && s.forwardRuleFired(payload) {
		return
	}
	s.reportRuleFired(payload)
}

// onRuleNotify est le callback EmitNotify du moteur de règles. Le déclenchement remonte déjà à l'Admin par
// onRuleFired (action notify) ; c'est l'Admin qui achemine la notification vers les canaux, avec le message
// du flux. Un second message ici dupliquait le déclenchement dans le journal.
func (s *Server) onRuleNotify(ruleID, severity, title, message string, _ map[string]any) {
	s.log.Info("rulesengine: notification", "rule", ruleID, "severity", severity, "title", title, "message", message)
}

func (s *Server) handlePushBans(w http.ResponseWriter, r *http.Request) {
	var list []*router.RuntimeBan
	if err := json.NewDecoder(r.Body).Decode(&list); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.applyBans(list)
	s.log.Info("bans IP mis à jour", "count", len(list))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleListBans(w http.ResponseWriter, r *http.Request) {
	if s.bansDB == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]")) //nolint:errcheck
		return
	}
	rows, err := s.bansDB.ActiveBans()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rows) //nolint:errcheck
}

func (s *Server) handleListBanHistory(w http.ResponseWriter, r *http.Request) {
	if s.bansDB == nil {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]")) //nolint:errcheck
		return
	}
	since := time.Now().AddDate(0, 0, -30)
	if q := r.URL.Query().Get("since"); q != "" {
		if t, err := time.Parse(time.RFC3339, q); err == nil {
			since = t
		}
	}
	rows, err := s.bansDB.BanHistorySince(since)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rows) //nolint:errcheck
}

func (s *Server) handleDeleteBan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		http.Error(w, "id requis", http.StatusBadRequest)
		return
	}
	if s.bansDB != nil {
		if err := s.bansDB.DeleteBan(id); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	s.reloadBanStore()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleInternalHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"status":         "ok",
		"routes":         s.table.Len(),
		"certs":          s.certStore.Len(),
		"snippets":       s.snippetStore.Len(),
		"auth_providers": s.providerStore.Len(),
	})
}

// handleBackendsHealth expose l'état runtime des backends (quarantaine / health checks).
func (s *Server) handleBackendsHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	backends := map[string]string{}
	if s.health != nil {
		backends = s.health.Snapshot()
	}
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"backends": backends,
	})
}

// pushedSettings est le payload runtime poussé par Admin (HTTP ou WS).
type pushedSettings struct {
	TracingEndpoint string `json:"tracing_endpoint"`
	LogLevel        string `json:"log_level"`
	LogFormat       string `json:"log_format"`
	AdminPublicURL  string `json:"admin_public_url"`
	IPAnonymize     *bool  `json:"ip_anonymize,omitempty"`
	IPPseudonymize  *bool  `json:"ip_pseudonymize,omitempty"`
}

// merge reporte sur p les champs renseignés de next : l'Admin pousse aussi des réglages
// isolés (ex. ip_anonymize seul), qui ne doivent pas effacer les autres de la copie locale.
func (p pushedSettings) merge(next pushedSettings) pushedSettings {
	for _, f := range []struct {
		dst *string
		src string
	}{
		{&p.TracingEndpoint, next.TracingEndpoint},
		{&p.LogLevel, next.LogLevel},
		{&p.LogFormat, next.LogFormat},
		{&p.AdminPublicURL, next.AdminPublicURL},
	} {
		if f.src != "" {
			*f.dst = f.src
		}
	}
	if next.IPAnonymize != nil {
		p.IPAnonymize = next.IPAnonymize
	}
	if next.IPPseudonymize != nil {
		p.IPPseudonymize = next.IPPseudonymize
	}
	return p
}

// handlePushSettings reçoit les paramètres runtime poussés par Admin.
// La config locale (cfg.Engine.*) a toujours la priorité sur chaque champ.
func (s *Server) handlePushSettings(w http.ResponseWriter, r *http.Request) {
	var payload pushedSettings
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.receivePushedSettings(payload)
	w.WriteHeader(http.StatusNoContent)
}

// applyPushedSettings applique les settings Admin (local wins sur engine.*).
func (s *Server) applyPushedSettings(payload pushedSettings) {
	// Tracing endpoint — local wins
	if s.cfg.Engine.TracingEndpoint == "" && payload.TracingEndpoint != "" {
		s.mu.Lock()
		s.pushedTracing = payload.TracingEndpoint
		s.mu.Unlock()
		s.log.Info("settings: tracing endpoint reçu depuis Admin", "endpoint", payload.TracingEndpoint)
		s.reconfigureTracing(payload.TracingEndpoint)
	}

	// Log level + format — rechargement à chaud, local wins
	level := payload.LogLevel
	format := payload.LogFormat
	if s.cfg.Engine.LogLevel != "" {
		level = s.cfg.Engine.LogLevel
	}
	if s.cfg.Engine.LogFormat != "" {
		format = s.cfg.Engine.LogFormat
	}
	if level != "" || format != "" {
		s.log.Reload(level, format, s.cfg.Engine.SystemLogPath)
		s.log.Info("settings: logger rechargé depuis Admin", "level", level, "format", format)
	}

	// Protection des IP, appliquée d'un bloc : l'anonymisation de edge.json ne peut pas être levée
	// par l'Admin, et l'emporte dans le logger sur la pseudonymisation (IP réelle jamais envoyée).
	if payload.IPAnonymize != nil || payload.IPPseudonymize != nil {
		anon, pseudo := s.accessLog.IPProtection()
		if payload.IPAnonymize != nil && !s.cfg.Engine.IPAnonymize {
			anon = *payload.IPAnonymize
		}
		if payload.IPPseudonymize != nil {
			pseudo = *payload.IPPseudonymize
		}
		s.accessLog.SetIPProtection(anon, pseudo)
		s.log.Info("settings: protection IP access logs", "anonymize", anon, "pseudonymize", pseudo)
	}

	// URL publique Admin — pour les liens des pages d'erreur (sauf override env local).
	if os.Getenv("GPX_ADMIN_PUBLIC_URL") == "" && payload.AdminPublicURL != "" {
		prev := errorpages.GetAdminBaseURL()
		errorpages.SetAdminBaseURL(payload.AdminPublicURL)
		if prev != errorpages.GetAdminBaseURL() {
			s.log.Info("settings: URL publique Admin reçue", "url", errorpages.GetAdminBaseURL())
		}
	}
}

// portalPushPayload est le body Admin → passerelle pour le portail d'accès.
type portalPushPayload struct {
	Enabled              bool                   `json:"enabled"`
	SSHPort              int                    `json:"ssh_port"`
	HTTPPort             int                    `json:"http_port"`
	PublicHost           string                 `json:"public_host"`
	AuthProviderID       string                 `json:"auth_provider_id"`
	DBPath               string                 `json:"db_path"`
	AllowPersonalTargets bool                   `json:"allow_personal_targets"`
	Require2FA           bool                   `json:"require_2fa"`
	SessionTTLSec        int                    `json:"session_ttl_sec"`
	SessionMode          string                 `json:"session_mode"`
	Theme                string                 `json:"theme"`
	Views                []portal.View          `json:"views"`
	Catalog              []portal.CatalogTarget `json:"catalog"`
	Users                []portal.SyncedUser    `json:"users"`
	Grants               []portal.AccessGrant   `json:"grants"`
	Policy               portal.Policy          `json:"policy"`

	// Haute disponibilité : voir portal.Config.
	HAGroup       string   `json:"ha_group"`
	HAMembers     []string `json:"ha_members"`
	HASessionMode string   `json:"ha_session_mode"`
	HAStandby     bool     `json:"ha_standby"`
	HAKey         string   `json:"ha_key"`
}

func (s *Server) handlePushPortal(w http.ResponseWriter, r *http.Request) {
	var payload portalPushPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.applyPortalPush(payload)
	w.WriteHeader(http.StatusNoContent)
}

// applyPortalPush garde une copie locale chiffrée de la config poussée par l'Admin (le portail
// redémarre ainsi sans l'Admin) puis l'applique.
func (s *Server) applyPortalPush(payload portalPushPayload) {
	if s.portal == nil {
		return
	}
	if s.cache != nil {
		if err := s.cache.SaveFile(portalConfigPath(), payload); err != nil {
			s.log.Warn("portal: persistance config échouée", "err", err)
		}
	}
	s.applyPortalPayload(payload)
}

func (s *Server) applyPortalPayload(payload portalPushPayload) {
	// La composition du groupe HA arrive avec cette config : les Agents en sont informés.
	defer func() { go s.wsHub.BroadcastEdgeEndpoints() }()
	cfg := portal.Config{
		Enabled:              payload.Enabled,
		SSHPort:              payload.SSHPort,
		HTTPPort:             payload.HTTPPort,
		PublicHost:           payload.PublicHost,
		AuthProviderID:       payload.AuthProviderID,
		DBPath:               payload.DBPath,
		AllowPersonalTargets: payload.AllowPersonalTargets,
		Require2FA:           payload.Require2FA,
		SessionTTLSec:        payload.SessionTTLSec,
		SessionMode:          payload.SessionMode,
		Theme:                payload.Theme,
		Views:                payload.Views,
		Policy:               payload.Policy,
		HAGroup:              payload.HAGroup,
		HAMembers:            payload.HAMembers,
		HAKey:                payload.HAKey,
		HASharedSess:         payload.HAGroup != "" && payload.HASessionMode == "shared",
		HAStandby:            payload.HAStandby,
	}
	if err := s.portal.ApplyConfig(cfg); err != nil {
		s.log.Error("portal: apply config", "err", err)
		return
	}
	if payload.Enabled || payload.HAStandby {
		if payload.Catalog != nil {
			if err := s.portal.SetCatalog(payload.Catalog); err != nil {
				s.log.Warn("portal: catalog", "err", err)
			}
		}
		if payload.Grants != nil {
			s.portal.SetGrants(payload.Grants)
		}
		if payload.Users != nil {
			if err := s.portal.SyncUsers(payload.Users); err != nil {
				s.log.Warn("portal: users", "err", err)
			}
		}
	}
	s.ensurePortalPublicRoute()
}

// portalPublicRouteID identifie la route HTTP auto-injectée pour le portail.
const portalPublicRouteID = "gpx-portal-public"

// Client HTTP pour les relais passerelle→Agent (évite DefaultClient sans timeout — revue P1 #7).
var agentRelayHTTP = &http.Client{Timeout: 30 * time.Second}

// portalRoutes : les routes publiques du portail que cette passerelle publie (ID → hôte) et leurs backends.
// Une passerelle qui l'héberge le sert en local. Un membre en attente d'un groupe HA ne l'héberge pas (rien n'écoute
// chez lui) : il renvoie l'hôte vers les autres membres du groupe, dont celui qui l'héberge répond, les autres refusent
// la connexion et sont écartés par le contrôle de santé. Sans pair connu, pas de route.
func (s *Server) portalRoutes() (hosts map[string]string, backends []router.Backend) {
	hosts = map[string]string{}
	if s.portal == nil {
		return hosts, nil
	}
	cfg := s.portal.Config()
	if !cfg.Enabled && !cfg.HAStandby {
		return hosts, nil
	}
	cfg.Defaults()
	if cfg.Enabled {
		backends = []router.Backend{{URL: fmt.Sprintf("http://127.0.0.1:%d", cfg.HTTPPort), Weight: 1}}
	} else {
		backends = s.portalMemberBackends(cfg)
		if len(backends) == 0 {
			return hosts, nil
		}
	}
	if h := strings.TrimSpace(strings.ToLower(cfg.PublicHost)); h != "" {
		hosts[portalPublicRouteID] = h
		for _, vh := range cfg.ViewHosts() {
			hosts[portalPublicRouteID+":"+vh] = vh
		}
	}
	return hosts, backends
}

// portalMemberBackends : le port HTTP du portail chez les autres membres du groupe HA, d'après les adresses de leurs
// passerelles (poussées par l'Admin, copie locale chiffrée).
func (s *Server) portalMemberBackends(cfg portal.Config) []router.Backend {
	member := map[string]bool{}
	for _, m := range cfg.HAMembers {
		member[m] = true
	}
	var out []router.Backend
	for _, p := range s.peers.All() {
		if !member[p.Name] {
			continue
		}
		u, err := url.Parse(p.Endpoint)
		if err != nil || u.Hostname() == "" {
			continue
		}
		out = append(out, router.Backend{
			URL:    "http://" + net.JoinHostPort(u.Hostname(), strconv.Itoa(cfg.HTTPPort)),
			Weight: 1,
		})
	}
	return out
}

// ensurePortalPublicRoute publie PublicHost vers le portail (TLS sur l'entrée), ainsi que les hôtes dédiés des vues.
// Rejoué après chaque Replace de routes pour survivre aux full-sync Admin.
func (s *Server) ensurePortalPublicRoute() {
	if s.portal == nil || s.table == nil {
		return
	}
	wanted, backends := s.portalRoutes()
	for _, r := range s.table.All() {
		if strings.HasPrefix(r.ID, portalPublicRouteID) {
			if _, keep := wanted[r.ID]; !keep && s.table.Delete(r.ID) {
				s.implicitSkeleton.Delete(r.ID)
				s.log.Info("portal: route publique retirée", "host", r.Host)
			}
		}
	}
	preserve := true
	for id, host := range wanted {
		s.upsertImplicitRoute(&router.Route{
			ID:           id,
			Host:         host,
			Type:         router.RouteHTTP,
			TLSEnabled:   true,
			PreserveHost: &preserve,
			Backends:     backends,
		})
		s.log.Info("portal: route HTTPS publique", "host", host, "backends", len(backends), "backend", backends[0].URL)
	}
}

// handleMetricsSummary retourne un résumé JSON des métriques Prometheus clés.
// Utilisé par l'UI admin pour la page edge-metrics (pas de parsing text/prometheus côté client).
func (s *Server) handleMetricsSummary(w http.ResponseWriter, _ *http.Request) {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		http.Error(w, "gather error", http.StatusInternalServerError)
		return
	}

	// Index name → MetricFamily pour lookup O(1)
	idx := make(map[string]*dto.MetricFamily, len(mfs))
	for _, mf := range mfs {
		idx[mf.GetName()] = mf
	}

	getGauge := func(name string, labels map[string]string) float64 {
		mf, ok := idx[name]
		if !ok {
			return 0
		}
		for _, m := range mf.GetMetric() {
			if matchLabels(m.GetLabel(), labels) {
				return m.GetGauge().GetValue()
			}
		}
		return 0
	}

	sumCounter := func(name string, filterLabel, filterVal string) float64 {
		mf, ok := idx[name]
		if !ok {
			return 0
		}
		var total float64
		for _, m := range mf.GetMetric() {
			if filterLabel == "" || labelVal(m.GetLabel(), filterLabel) == filterVal {
				total += m.GetCounter().GetValue()
			}
		}
		return total
	}

	// Histogramme p50/p95/p99 agrégé sur tous les hosts/backends
	quantile := func(name string, q float64) float64 {
		mf, ok := idx[name]
		if !ok {
			return 0
		}
		var sumCount, sumSum float64
		buckets := map[float64]float64{}
		for _, m := range mf.GetMetric() {
			h := m.GetHistogram()
			sumSum += h.GetSampleSum()
			sumCount += float64(h.GetSampleCount())
			for _, b := range h.GetBucket() {
				buckets[b.GetUpperBound()] += float64(b.GetCumulativeCount())
			}
		}
		return bucketQuantile(buckets, sumCount, sumSum, q)
	}

	// Backends uniques avec leur taux d'erreur
	type backendStat struct {
		Backend   string  `json:"backend"`
		Requests  float64 `json:"requests"`
		Errors    float64 `json:"errors"`
		ErrorRate float64 `json:"error_rate"`
		P95ms     float64 `json:"p95_ms"`
	}
	backendMap := map[string]*backendStat{}
	if mf, ok := idx["gpx_backend_requests_total"]; ok {
		for _, m := range mf.GetMetric() {
			b := labelVal(m.GetLabel(), "backend")
			if b == "" {
				continue
			}
			if _, exists := backendMap[b]; !exists {
				backendMap[b] = &backendStat{Backend: b}
			}
			backendMap[b].Requests += m.GetCounter().GetValue()
			if st := labelVal(m.GetLabel(), "status"); len(st) > 0 && st[0] == '5' {
				backendMap[b].Errors += m.GetCounter().GetValue()
			}
		}
	}
	if mf, ok := idx["gpx_backend_duration_seconds"]; ok {
		p95ByBackend := map[string]struct{ sum, count float64 }{}
		for _, m := range mf.GetMetric() {
			b := labelVal(m.GetLabel(), "backend")
			if b == "" {
				continue
			}
			h := m.GetHistogram()
			e := p95ByBackend[b]
			e.sum += h.GetSampleSum()
			e.count += float64(h.GetSampleCount())
			p95ByBackend[b] = e
		}
		for b, e := range p95ByBackend {
			if bs, ok := backendMap[b]; ok && e.count > 0 {
				bs.P95ms = (e.sum / e.count) * 1000
			}
		}
	}
	backends := make([]backendStat, 0, len(backendMap))
	for _, bs := range backendMap {
		if bs.Requests > 0 {
			bs.ErrorRate = bs.Errors / bs.Requests * 100
		}
		backends = append(backends, *bs)
	}

	// Proxies breakdown par host
	type latencyBucket struct {
		Le    float64 `json:"le"`
		Count float64 `json:"count"`
	}
	type proxyStat struct {
		Host         string  `json:"host"`
		Requests     float64 `json:"requests"`
		Errors       float64 `json:"errors"`
		ErrorRate    float64 `json:"error_rate"`
		P95ms        float64 `json:"p95_ms"`
		ActiveReqs   float64 `json:"active_requests"`
		BytesIn      float64 `json:"bytes_in"`
		BytesOut     float64 `json:"bytes_out"`
		BlockedTotal float64 `json:"blocked_total"`
		// Données brutes de l'histogramme de latence : permettent à l'Admin de calculer
		// un p95 sur une fenêtre (différence entre deux relevés).
		DurationSumS   float64         `json:"duration_sum_s"`
		DurationCount  float64         `json:"duration_count"`
		LatencyBuckets []latencyBucket `json:"latency_buckets,omitempty"`
	}
	proxyMap := map[string]*proxyStat{}
	ensureProxy := func(host string) *proxyStat {
		if ps, ok := proxyMap[host]; ok {
			return ps
		}
		ps := &proxyStat{Host: host}
		proxyMap[host] = ps
		return ps
	}
	if mf, ok := idx["gpx_edge_requests_total"]; ok {
		for _, m := range mf.GetMetric() {
			host := labelVal(m.GetLabel(), "host")
			if host == "" {
				continue
			}
			ps := ensureProxy(host)
			ps.Requests += m.GetCounter().GetValue()
			if st := labelVal(m.GetLabel(), "status"); len(st) > 0 && st[0] == '5' {
				ps.Errors += m.GetCounter().GetValue()
			}
		}
	}
	if mf, ok := idx["gpx_edge_active_requests"]; ok {
		for _, m := range mf.GetMetric() {
			host := labelVal(m.GetLabel(), "host")
			if host == "" {
				continue
			}
			ensureProxy(host).ActiveReqs = m.GetGauge().GetValue()
		}
	}
	if mf, ok := idx["gpx_edge_request_duration_seconds"]; ok {
		type hstat struct {
			sum, count float64
			buckets    map[float64]float64
		}
		durByHost := map[string]*hstat{}
		for _, m := range mf.GetMetric() {
			host := labelVal(m.GetLabel(), "host")
			if host == "" {
				continue
			}
			h := m.GetHistogram()
			e := durByHost[host]
			if e == nil {
				e = &hstat{buckets: map[float64]float64{}}
				durByHost[host] = e
			}
			e.sum += h.GetSampleSum()
			e.count += float64(h.GetSampleCount())
			for _, b := range h.GetBucket() {
				e.buckets[b.GetUpperBound()] += float64(b.GetCumulativeCount())
			}
		}
		for host, e := range durByHost {
			if e.count == 0 {
				continue
			}
			ps := ensureProxy(host)
			ps.P95ms = bucketQuantile(e.buckets, e.count, e.sum, 0.95) * 1000
			ps.DurationSumS = e.sum
			ps.DurationCount = e.count
			for _, bound := range sortedBounds(e.buckets) {
				ps.LatencyBuckets = append(ps.LatencyBuckets, latencyBucket{Le: bound, Count: e.buckets[bound]})
			}
		}
	}
	if mf, ok := idx["gpx_edge_bytes_received_by_host_total"]; ok {
		for _, m := range mf.GetMetric() {
			host := labelVal(m.GetLabel(), "host")
			if host == "" {
				continue
			}
			ensureProxy(host).BytesIn = m.GetCounter().GetValue()
		}
	}
	if mf, ok := idx["gpx_edge_bytes_sent_by_host_total"]; ok {
		for _, m := range mf.GetMetric() {
			host := labelVal(m.GetLabel(), "host")
			if host == "" {
				continue
			}
			ensureProxy(host).BytesOut = m.GetCounter().GetValue()
		}
	}
	if mf, ok := idx["gpx_pipeline_blocked_total"]; ok {
		for _, m := range mf.GetMetric() {
			host := labelVal(m.GetLabel(), "host")
			if host == "" {
				continue
			}
			ensureProxy(host).BlockedTotal += m.GetCounter().GetValue()
		}
	}
	proxies := make([]proxyStat, 0, len(proxyMap))
	for _, ps := range proxyMap {
		if ps.Requests > 0 {
			ps.ErrorRate = ps.Errors / ps.Requests * 100
		}
		proxies = append(proxies, *ps)
	}

	// Certs expiry (secondes restantes)
	type certStat struct {
		Domain  string  `json:"domain"`
		ExpSecs float64 `json:"exp_secs"`
	}
	var certs []certStat
	if mf, ok := idx["gpx_tls_cert_expiry_seconds"]; ok {
		for _, m := range mf.GetMetric() {
			domain := labelVal(m.GetLabel(), "domain")
			certs = append(certs, certStat{Domain: domain, ExpSecs: m.GetGauge().GetValue()})
		}
	}

	// Pipeline blocks par stage
	type pipelineStat struct {
		Stage string  `json:"stage"`
		Count float64 `json:"count"`
	}
	stageMap := map[string]float64{}
	if mf, ok := idx["gpx_pipeline_blocked_total"]; ok {
		for _, m := range mf.GetMetric() {
			stage := labelVal(m.GetLabel(), "stage")
			stageMap[stage] += m.GetCounter().GetValue()
		}
	}
	var pipeline []pipelineStat
	for stage, count := range stageMap {
		pipeline = append(pipeline, pipelineStat{Stage: stage, Count: count})
	}

	// Sections lues par les pages Infrastructure, Portail, Sécurité et Domaines/TLS.
	var peerSum, peerCount float64
	if mf, ok := idx["gpx_peer_sync_duration_seconds"]; ok {
		for _, m := range mf.GetMetric() {
			peerSum += m.GetHistogram().GetSampleSum()
			peerCount += float64(m.GetHistogram().GetSampleCount())
		}
	}
	type tlsHostStat struct {
		Host              string  `json:"host"`
		HandshakeP95ms    float64 `json:"handshake_p95_ms"`
		ActiveConnections float64 `json:"active_connections"`
	}
	tlsByHost := map[string]*tlsHostStat{}
	tlsHost := func(host string) *tlsHostStat {
		if ts, ok := tlsByHost[host]; ok {
			return ts
		}
		ts := &tlsHostStat{Host: host}
		tlsByHost[host] = ts
		return ts
	}
	if mf, ok := idx["gpx_tls_handshake_seconds"]; ok {
		for _, m := range mf.GetMetric() {
			host := labelVal(m.GetLabel(), "host")
			h := m.GetHistogram()
			if host == "" || h.GetSampleCount() == 0 {
				continue
			}
			b := map[float64]float64{}
			for _, bk := range h.GetBucket() {
				b[bk.GetUpperBound()] += float64(bk.GetCumulativeCount())
			}
			tlsHost(host).HandshakeP95ms = bucketQuantile(b, float64(h.GetSampleCount()), h.GetSampleSum(), 0.95) * 1000
		}
	}
	if mf, ok := idx["gpx_tls_active_connections"]; ok {
		for _, m := range mf.GetMetric() {
			if host := labelVal(m.GetLabel(), "host"); host != "" {
				tlsHost(host).ActiveConnections = m.GetGauge().GetValue()
			}
		}
	}
	tlsHosts := make([]tlsHostStat, 0, len(tlsByHost))
	for _, ts := range tlsByHost {
		tlsHosts = append(tlsHosts, *ts)
	}

	summary := map[string]any{
		"active_requests":     getGauge("gpx_edge_active_requests", nil),
		"routes_total":        getGauge("gpx_edge_routes_total", nil),
		"requests_total":      sumCounter("gpx_edge_requests_total", "", ""),
		"errors_total":        sumCounter("gpx_edge_requests_total", "status", "5xx"),
		"p50_ms":              quantile("gpx_edge_request_duration_seconds", 0.5) * 1000,
		"p95_ms":              quantile("gpx_edge_request_duration_seconds", 0.95) * 1000,
		"p99_ms":              quantile("gpx_edge_request_duration_seconds", 0.99) * 1000,
		"backend_ttfb_p95_ms": quantile("gpx_backend_ttfb_seconds", 0.95) * 1000,
		"bytes_in":            sumCounter("gpx_edge_bytes_received_total", "", ""),
		"bytes_out":           sumCounter("gpx_edge_bytes_sent_total", "", ""),
		"backends":            backends,
		"certs":               certs,
		"pipeline":            pipeline,
		"proxies":             proxies,
		"ws": map[string]any{
			"admin_connections": getGauge("goproxify_ws_connections_active", map[string]string{"role": "admin"}),
			"agent_connections": getGauge("goproxify_ws_connections_active", map[string]string{"role": "agent"}),
		},
		"peers": map[string]any{"sync_sum_s": peerSum, "sync_count": peerCount},
		"portal": map[string]any{"sessions": map[string]any{
			"one_shot": getGauge("gpx_portal_sessions_active", map[string]string{"type": "one_shot"}),
			"multi":    getGauge("gpx_portal_sessions_active", map[string]string{"type": "multi"}),
		}},
		"waf":       map[string]any{"profiles_active": getGauge("gpx_waf_profiles_active", nil)},
		"tls_hosts": tlsHosts,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary) //nolint:errcheck
}

func matchLabels(pairs []*dto.LabelPair, want map[string]string) bool {
	if len(want) == 0 {
		return true
	}
	m := make(map[string]string, len(pairs))
	for _, p := range pairs {
		m[p.GetName()] = p.GetValue()
	}
	for k, v := range want {
		if m[k] != v {
			return false
		}
	}
	return true
}

func labelVal(pairs []*dto.LabelPair, name string) string {
	for _, p := range pairs {
		if p.GetName() == name {
			return p.GetValue()
		}
	}
	return ""
}

func sortedBounds(m map[float64]float64) []float64 {
	keys := make([]float64, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	// tri insertion simple (< 20 éléments)
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// reconfigureTracing bascule l'export OTLP à chaud vers l'endpoint poussé par Admin
// et vide l'ancien exporteur en arrière-plan.
func (s *Server) reconfigureTracing(endpoint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if endpoint == s.activeTracing {
		return
	}
	shutdown, err := tracing.Init(endpoint, s.cfg.Engine.TracingSampleRatio)
	if err != nil {
		s.log.Warn("settings: tracing endpoint invalide, export inchangé", "endpoint", endpoint, "err", err)
		return
	}
	old := s.tracingShutdown
	s.tracingShutdown = shutdown
	s.activeTracing = endpoint
	if old != nil {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			old(ctx) //nolint:errcheck
		}()
	}
}

// bucketQuantile estime le quantile q (en secondes) d'un histogramme Prometheus à
// buckets cumulatifs ; retombe sur la moyenne si la cible dépasse le dernier bucket.
func bucketQuantile(buckets map[float64]float64, count, sum, q float64) float64 {
	if count == 0 {
		return 0
	}
	target := q * count
	var prevBound, prevCount float64
	for _, bound := range sortedBounds(buckets) {
		c := buckets[bound]
		if c >= target {
			if c == prevCount {
				return bound
			}
			return prevBound + (bound-prevBound)*(target-prevCount)/(c-prevCount)
		}
		prevBound, prevCount = bound, c
	}
	return sum / count
}

// applyEraseIPs retire d'une passerelle les traces d'IPs que l'Admin a effacées : lignes d'accès de la base
// de logs locale (en clair ou pseudonymisées) et historique des bans. L'ordre arrive aussi à chaque
// connexion tant qu'il est conservé, d'où l'absence de journal par IP (elle ne doit pas y réapparaître).
func (s *Server) applyEraseIPs(list []edgews.EraseEntry) {
	var lines int64
	var bans int64
	for _, e := range list {
		if e.IP == "" {
			continue
		}
		l, b, err := s.eraseIP(e.IP)
		if err != nil {
			s.log.Warn("rgpd: effacement d'une IP échoué", "err", err)
		}
		lines += l
		bans += b
	}
	s.persistEphorState()
	if lines > 0 || bans > 0 {
		s.log.Info("rgpd: IP effacées de la passerelle", "access_log_lines", lines, "ban_rows", bans)
	}
}

// registerLogRoutes déclare les routes de la base de logs, appelées par l'Admin. Les tests de recherche montent les
// mêmes routes : une route oubliée ici le serait aussi chez eux.
func (s *Server) registerLogRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET "+logapi.PathSearch, s.handleLogSearch)
	mux.HandleFunc("GET "+logapi.PathHistogram, s.handleLogHistogram)
	mux.HandleFunc("GET "+logapi.PathFacets, s.handleLogFacets)
	mux.HandleFunc("POST "+logapi.PathReveal, s.handleLogReveal)
	mux.HandleFunc("POST "+logapi.PathTop, s.handleLogTop)
	mux.HandleFunc("GET "+logapi.PathUniqueIPs, s.handleLogUniqueIPs)
	mux.HandleFunc("POST "+logapi.PathEphorSim, s.handleEphorSimulate)
	mux.HandleFunc("GET "+logapi.PathEphorReferences, s.handleEphorReferences)
	mux.HandleFunc("GET "+logapi.PathSurface, s.handleSurfaceList)
	mux.HandleFunc("GET "+logapi.PathInventory, s.handleInventory)
	mux.HandleFunc("GET "+logapi.PathSurfaceReport, s.handleSurfaceReport)
	mux.HandleFunc("GET "+logapi.PathSurfaceProposals, s.handleSurfaceProposals)
	mux.HandleFunc("GET "+logapi.PathSurfaceOpenAPI, s.handleSurfaceOpenAPI)
	mux.HandleFunc("POST "+logapi.PathSurfaceReset, s.handleSurfaceReset)
	mux.HandleFunc("POST "+logapi.PathSurfaceForget, s.handleSurfaceForget)
	mux.HandleFunc("POST "+logapi.PathErase, s.handleLogErase)
}

// enableStrict est l'action « mode strict » des automatisations d'une passerelle : elle durcit Ephor pour dur (threat.Engine.Harden).
func (s *Server) enableStrict(dur time.Duration) error {
	if s.threatEngine == nil {
		return fmt.Errorf("Ephor n'est pas démarré")
	}
	return s.threatEngine.Harden(dur)
}
