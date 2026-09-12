// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/core/errorpages"
	"github.com/vincamok/goproxify/internal/core/metrics"
	"github.com/vincamok/goproxify/internal/core/portal"
	"github.com/vincamok/goproxify/internal/core/router"
	"github.com/vincamok/goproxify/internal/core/threat"
	"github.com/vincamok/goproxify/internal/core/waf/behavior"
	corews "github.com/vincamok/goproxify/internal/core/ws"
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
	mux.HandleFunc("GET /internal/v1/proxies/{id}/revisions", s.handleListProxyRevisions)
	mux.HandleFunc("POST /internal/v1/proxies/{id}/revisions/{rev}/dry-run", s.handleDryRunProxyRevision)
	mux.HandleFunc("POST /internal/v1/proxies/{id}/revisions/{rev}/promote", s.handlePromoteProxyRevision)
	mux.HandleFunc("POST /internal/v1/proxies/{id}/revisions/{rev}/reject", s.handleRejectProxyRevision)
	mux.HandleFunc("POST /internal/v1/delegations", s.handlePushDelegations)
	mux.HandleFunc("POST /internal/v1/certs", s.handlePushCerts)
	mux.HandleFunc("POST /internal/v1/snippets", s.handlePushSnippets)
	mux.HandleFunc("POST /internal/v1/error-pages", s.handlePushErrorPages)
	mux.HandleFunc("POST /internal/v1/auth-providers", s.handlePushAuthProviders)
	mux.HandleFunc("POST /internal/v1/ip-profiles", s.handlePushIPProfiles)
	mux.HandleFunc("POST /internal/v1/bans", s.handlePushBans)
	mux.HandleFunc("POST /internal/v1/threat-config", s.handlePushThreatConfig)
	mux.HandleFunc("POST /internal/v1/threat-lists/sync", s.handleHAThreatSync)
	mux.HandleFunc("GET /internal/v1/threat-lists/export", s.handleHAThreatExport)
	mux.HandleFunc("POST /internal/v1/waf/behavior/sync", s.handleHAWAFBehaviorSync)
	mux.HandleFunc("GET /internal/v1/waf/behavior/export", s.handleHAWAFBehaviorExport)
	mux.HandleFunc("GET /internal/v1/waf/behavior/profiles", s.handleWAFBehaviorProfiles)
	mux.HandleFunc("DELETE /internal/v1/waf/behavior/profiles/{ip}", s.handleWAFBehaviorDeleteProfile)
	mux.HandleFunc("POST /internal/v1/settings", s.handlePushSettings)
	mux.HandleFunc("POST /internal/v1/portal", s.handlePushPortal)
	mux.HandleFunc("POST /internal/v1/cluster/peers", s.handlePushClusterPeers)
	mux.HandleFunc("POST /internal/v1/gateway/peers", s.handlePushGatewayPeers)
	mux.HandleFunc("POST /internal/v1/gateway/tunnel", s.handleGatewayTunnel)
	mux.HandleFunc("GET /internal/v1/lb/scores", s.handleLBScores)
	mux.HandleFunc("GET /internal/v1/health", s.handleInternalHealth)
	mux.HandleFunc("GET /internal/v1/backends/health", s.handleBackendsHealth)

	// Endpoints Agent → Core
	mux.HandleFunc("POST /internal/v1/agent/heartbeat", s.handleAgentHeartbeat)
	mux.HandleFunc("POST /internal/v1/agent/containers", s.handleAgentContainerStart)
	mux.HandleFunc("DELETE /internal/v1/agent/containers", s.handleAgentContainerStop)
	mux.HandleFunc("POST /internal/v1/agent/events", s.handleAgentEvent)
	mux.HandleFunc("POST /internal/v1/agent/logs", s.handleAgentLogs)

	// Relay Admin → Agent (Admin appelle Core, Core relaie à l'Agent)
	mux.HandleFunc("POST /internal/v1/agent/{name}/rescan", s.handleAgentRescanRelay)
	mux.HandleFunc("POST /internal/v1/agent/{name}/command", s.handleAgentCommandRelay)

	// Endpoints Core → Admin (lecture de l'état des nœuds et conteneurs)
	mux.HandleFunc("GET /internal/v1/nodes", s.handleListNodes)
	mux.HandleFunc("GET /internal/v1/node-events", s.handleListNodeEvents)
	mux.HandleFunc("GET /internal/v1/agent/containers", s.handleListAgentContainers)

	// Appairage local Agent → Core (protégé par GPX_PAIRING_SECRET, fail-closed)
	mux.HandleFunc("POST /internal/v1/pair", s.handleCorePair)

	s.intSrv = &http.Server{Addr: addr, Handler: s.authMiddleware(mux)}
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
		ok, err := s.tokenStore.Validate(bearer)
		if err != nil || !ok {
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handlePushDelegations reçoit les routes synthétiques de délégation inter-Core.
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
	metrics.Core.RouteCount.Set(float64(s.table.Len()))
	s.health.StartChecks(backendURLsFromRoutes(routes), 30*time.Second)
	s.saveCache()
	s.log.Info("routes remplacées", "count", len(routes), "purged_conflicts", purged)
	w.WriteHeader(http.StatusNoContent)
}

func isAgentRoute(id string) bool {
	return id == portalPublicRouteID ||
		strings.HasPrefix(id, "docker:") ||
		strings.HasPrefix(id, "docker-host:") ||
		strings.HasPrefix(id, "k8s:") ||
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
	metrics.Core.CertCount.Set(float64(s.certStore.Len()))
	s.saveCache()
	s.log.Info("certificat mis à jour", "name", payload.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.table.Delete(id) {
		metrics.Core.RouteCount.Set(float64(s.table.Len()))
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
	if s.threatEngine != nil {
		s.threatEngine.UpdateConfig(cfg)
	}
	s.log.Info("threat: config mise à jour", "enabled", cfg.Enabled)
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

// threatBanCallback retourne la fonction appelée par le moteur quand il détecte une menace.
// Elle ajoute le ban au BanStore local pour un effet immédiat et notifie Admin via WS.
func (s *Server) threatBanCallback() threat.BanCallback {
	return func(ip, reason string, expires time.Time) {
		b := &router.RuntimeBan{
			ID:        "threat-" + ip,
			IP:        ip,
			Reason:    reason,
			Source:    "threat",
			ExpiresAt: &expires,
		}
		s.mu.Lock()
		s.pendingThreatBans = append(s.pendingThreatBans, b)
		s.mu.Unlock()
		s.flushThreatBans()

		// Notifier Admin pour persister le ban dans security_bans.
		payload := corews.ThreatBanPayload{
			IP:        ip,
			Reason:    reason,
			ExpiresAt: expires.UTC().Format(time.RFC3339),
			NodeName:  s.cfg.Identity.NodeName,
		}
		if msg, err := corews.NewMessage(0, corews.TypeThreatBan, payload); err == nil {
			s.wsHub.BroadcastToAdmins(msg)
		}
	}
}

// flushThreatBans fusionne les bans threat dans le BanStore actif.
func (s *Server) flushThreatBans() {
	s.mu.Lock()
	toAdd := s.pendingThreatBans
	s.pendingThreatBans = nil
	s.mu.Unlock()
	if len(toAdd) == 0 {
		return
	}
	// Reconstruire la liste complète (BanStore ne supporte que Replace).
	// Les bans threat ont une durée limitée — ils s'effaceront à expiration.
	s.bansMu.Lock()
	defer s.bansMu.Unlock()
	merged := append(s.lastBanList, toAdd...)
	s.lastBanList = merged
	s.banStore.Replace(merged)
	s.log.Info("threat: ban(s) appliqués", "count", len(toAdd))
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
	AccessLogPath   string `json:"access_log_path"`
	AdminPublicURL  string `json:"admin_public_url"`
}

// handlePushSettings reçoit les paramètres runtime poussés par Admin.
// La config locale (cfg.Engine.*) a toujours la priorité sur chaque champ.
func (s *Server) handlePushSettings(w http.ResponseWriter, r *http.Request) {
	var payload pushedSettings
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.applyPushedSettings(payload)
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

	// Access log path — rechargement à chaud, local wins
	if s.cfg.Engine.AccessLogPath == "" && payload.AccessLogPath != "" {
		s.accessLog.Reopen(payload.AccessLogPath)
		s.log.Info("settings: access log redirigé depuis Admin", "path", payload.AccessLogPath)
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

// portalPushPayload est le body Admin → Core pour le portail d'accès.
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
	Catalog              []portal.CatalogTarget `json:"catalog"`
	Users                []portal.SyncedUser    `json:"users"`
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

func (s *Server) applyPortalPush(payload portalPushPayload) {
	if s.portal == nil {
		return
	}
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
	}
	if err := s.portal.ApplyConfig(cfg); err != nil {
		s.log.Error("portal: apply config", "err", err)
		return
	}
	if payload.Enabled {
		if payload.Catalog != nil {
			if err := s.portal.SetCatalog(payload.Catalog); err != nil {
				s.log.Warn("portal: catalog", "err", err)
			}
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

// Client HTTP pour les relais Core→Agent (évite DefaultClient sans timeout — revue P1 #7).
var agentRelayHTTP = &http.Client{Timeout: 30 * time.Second}

// ensurePortalPublicRoute publie PublicHost → http://127.0.0.1:HTTPPort (TLS sur l'entrée).
// Rejoué après chaque Replace de routes pour survivre aux full-sync Admin.
func (s *Server) ensurePortalPublicRoute() {
	if s.portal == nil || s.table == nil {
		return
	}
	cfg := s.portal.Config()
	if !cfg.Enabled || strings.TrimSpace(cfg.PublicHost) == "" {
		if s.table.Delete(portalPublicRouteID) {
			s.log.Info("portal: route publique retirée")
		}
		return
	}
	cfg.Defaults()
	host := strings.TrimSpace(strings.ToLower(cfg.PublicHost))
	backend := fmt.Sprintf("http://127.0.0.1:%d", cfg.HTTPPort)
	s.table.Upsert(&router.Route{
		ID:         portalPublicRouteID,
		Host:       host,
		Type:       router.RouteHTTP,
		TLSEnabled: true,
		Backends:   []router.Backend{{URL: backend, Weight: 1}},
	})
	s.log.Info("portal: route HTTPS publique", "host", host, "backend", backend)
}

// handlePushClusterPeers reçoit la topologie Raft poussée par Admin.
// Si le Core a déjà une config Peers locale non vide, elle est ignorée (local wins).
func (s *Server) handlePushClusterPeers(w http.ResponseWriter, r *http.Request) {
	if len(s.cfg.Cluster.Peers) > 0 {
		// Config locale définie : Admin ne peut pas l'écraser.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var peers map[string]string
	if err := json.NewDecoder(r.Body).Decode(&peers); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.clusterGroup != nil && len(peers) > 0 {
		s.clusterGroup.UpdatePeers(peers)
		s.log.Info("cluster: topologie reçue depuis Admin", "peers", len(peers))
	}
	w.WriteHeader(http.StatusNoContent)
}

