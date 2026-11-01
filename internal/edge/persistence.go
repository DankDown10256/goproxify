// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"os"
	"time"

	"github.com/vincamok/goproxify/internal/agent/telemetry"
	"github.com/vincamok/goproxify/internal/buildinfo"
	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	"github.com/vincamok/goproxify/internal/edge/ipprofiles"
	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/middleware"
	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/portal"
	edgere "github.com/vincamok/goproxify/internal/edge/rulesengine"
	"github.com/vincamok/goproxify/internal/edge/threat"
	"github.com/vincamok/goproxify/internal/edge/waf"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
	"github.com/vincamok/goproxify/internal/edge/tunnel"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// --- Cache & reconnexion -------------------------------------------------

// applyIPProfiles met à jour le store en mémoire et persiste sur le volume passerelle.
func (s *Server) applyIPProfiles(profiles []*router.IPProfile) {
	s.profileStore.Replace(profiles)
	if err := ipprofiles.Save(ipprofiles.Dir(), profiles); err != nil {
		s.log.Warn("edge: persistance profils IP échouée", "err", err)
		return
	}
	s.log.Debug("edge: profils IP persistés", "count", len(profiles), "dir", ipprofiles.Dir())
}

func (s *Server) loadIPProfilesFromDisk() {
	profiles, err := ipprofiles.Load(ipprofiles.Dir())
	if err != nil {
		s.log.Warn("edge: lecture profils IP disque échouée", "err", err)
		return
	}
	if profiles == nil {
		return
	}
	s.profileStore.Replace(profiles)
	s.log.Info("edge: profils IP chargés depuis le disque",
		"count", len(profiles),
		"dir", ipprofiles.Dir(),
	)
}

// applyBans persiste la liste Admin (source "admin") en DB et reconstruit le BanStore.
func (s *Server) applyBans(list []*router.RuntimeBan) {
	if s.bansDB != nil {
		// Remplacer tous les bans source "admin" en DB.
		if err := s.bansDB.DeleteBansBySource("admin"); err != nil {
			s.log.Warn("edge: suppression bans admin DB échouée", "err", err)
		}
		for _, b := range list {
			if b == nil || b.IP == "" {
				continue
			}
			src := b.Source
			if src == "" {
				src = "admin"
			}
			rb := *b
			rb.Source = src
			if err := s.bansDB.UpsertRuntimeBan(&rb); err != nil {
				s.log.Warn("edge: persistance ban admin DB échouée", "err", err)
			}
		}
	}
	s.reloadBanStore()
	s.log.Debug("edge: bans admin appliqués", "count", len(list))
}

func (s *Server) loadBansFromDisk() {
	if s.bansDB == nil {
		return
	}
	s.reloadBanStore()
	s.log.Info("edge: bans chargés depuis la DB", "count", s.banStore.Len())
}

// threatConfigPath est la copie locale chiffrée de la configuration Ephor poussée par l'Admin.
func threatConfigPath() string {
	if p := os.Getenv("GPX_THREAT_CONFIG_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/threat-config.gpx"
}

// applyThreatConfig persiste la configuration Ephor reçue de l'Admin puis l'applique. La copie est
// écrite même si le moteur n'existe pas encore : il la relira à son démarrage.
func (s *Server) applyThreatConfig(cfg threat.Config) {
	if err := s.cache.SaveFile(threatConfigPath(), cfg); err != nil {
		s.log.Warn(threat.Name+": persistance config échouée", "err", err)
	}
	if s.threatEngine == nil {
		return
	}
	s.threatEngine.UpdateConfig(cfg)
	s.applyChallenge(cfg)
	// UpdateConfig remplace la liste blanche : y remettre les entrées ephor_whitelist des routes.
	s.refreshEphorWhitelists()
}

// applyChallenge monte le défi gradué d'Ephor (ADR 0020, étape 1.b) quand la configuration le demande, ou le retire.
func (s *Server) applyChallenge(cfg threat.Config) {
	if !cfg.Enabled || !cfg.Challenge.Active() {
		s.gwChallenge.Store(nil)
		return
	}
	ch := cfg.Challenge
	ttl := ""
	if ch.TTL.Duration > 0 {
		ttl = ch.TTL.String()
	}
	s.gwChallenge.Store(middleware.NewGatewayChallenge(middleware.GatewayChallengeConfig{
		Difficulty: ch.Difficulty, TTL: ttl, ExemptPaths: ch.ExemptPaths, Secret: ch.Secret,
	}))
}

// loadThreatConfigFromDisk rend Ephor opérationnel sans l'Admin après un redémarrage.
func (s *Server) loadThreatConfigFromDisk() {
	var cfg threat.Config
	ok, err := s.cache.LoadFile(threatConfigPath(), &cfg)
	if err != nil {
		s.log.Warn(threat.Name+": config locale illisible — en attente de l'Admin", "err", err)
		return
	}
	if !ok {
		return
	}
	s.threatEngine.UpdateConfig(cfg)
	s.applyChallenge(cfg)
	s.refreshEphorWhitelists()
	s.log.Info(threat.Name+": config chargée depuis le disque", "enabled", cfg.Enabled)
}

// threatStatePath est la copie locale chiffrée des scores et fenêtres d'erreurs d'Ephor.
func threatStatePath() string {
	if p := os.Getenv("GPX_THREAT_STATE_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/threat-state.gpx"
}

// loadThreatStateFromDisk restaure les scores d'Ephor au démarrage, sans l'Admin : un redémarrage ne remet plus à zéro
// les IP en cours de suspicion.
func (s *Server) loadThreatStateFromDisk() {
	var st threat.State
	ok, err := s.cache.LoadFile(threatStatePath(), &st)
	if err != nil {
		s.log.Warn(threat.Name+": état local illisible — compteurs repartis de zéro", "err", err)
		return
	}
	if !ok {
		return
	}
	s.threatEngine.RestoreState(st)
	s.log.Info(threat.Name+": compteurs restaurés depuis le disque", "scores", len(st.Scores), "erreurs", len(st.Errors), "rate", len(st.RateTriggers))
}

// behaviorStatePath est la copie locale chiffrée du magasin comportemental (notes, historique propre, références apprises).
func behaviorStatePath() string {
	if p := os.Getenv("GPX_BEHAVIOR_STATE_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/behavior-state.gpx"
}

func (s *Server) loadBehaviorStateFromDisk() {
	if s.behavior == nil {
		return
	}
	var st behavior.State
	ok, err := s.cache.LoadFile(behaviorStatePath(), &st)
	if err != nil {
		s.log.Warn(threat.Name+": état comportemental local illisible — il repart de zéro", "err", err)
		return
	}
	if !ok {
		return
	}
	s.behavior.ImportState(st)
	s.log.Info(threat.Name+": état comportemental restauré", "notes", len(st.Profiles.Entries), "historiques", len(st.Trust), "routes", len(st.Refs))
}

func (s *Server) saveBehaviorState() {
	if s.behavior == nil {
		return
	}
	if err := s.cache.SaveFile(behaviorStatePath(), s.behavior.ExportState()); err != nil {
		s.log.Warn(threat.Name+": sauvegarde de l'état comportemental échouée", "err", err)
	}
}

// persistEphorState réécrit les copies locales d'Ephor sans attendre le prochain tour de sauvegarde : après un ordre
// d'effacement, un redémarrage dans l'intervalle ne doit pas ramener le score ni l'historique de l'IP effacée.
func (s *Server) persistEphorState() {
	s.saveThreatState()
	s.saveBehaviorState()
}

func (s *Server) saveThreatState() {
	if s.threatEngine == nil {
		return
	}
	if err := s.cache.SaveFile(threatStatePath(), s.threatEngine.SnapshotState()); err != nil {
		s.log.Warn(threat.Name+": sauvegarde de l'état échouée", "err", err)
	}
}

// wafConfigPath est la copie locale chiffrée de l'interrupteur du WAF poussé par l'Admin.
func wafConfigPath() string {
	if p := os.Getenv("GPX_WAF_CONFIG_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/waf-config.gpx"
}

// applyWAFConfig persiste l'interrupteur du WAF reçu de l'Admin puis l'applique à chaud.
func (s *Server) applyWAFConfig(cfg waf.EngineConfig) {
	if err := s.cache.SaveFile(wafConfigPath(), cfg); err != nil {
		s.log.Warn("waf: persistance config échouée", "err", err)
	}
	s.wafEngine.SetEnabled(cfg.Enabled)
}

// loadWAFConfigFromDisk rend à la passerelle son dernier réglage du WAF sans l'Admin. Sans copie ou avec
// une copie illisible, le WAF reste actif : une panne de lecture n'éteint pas une protection.
func (s *Server) loadWAFConfigFromDisk() {
	cfg := waf.DefaultEngineConfig()
	ok, err := s.cache.LoadFile(wafConfigPath(), &cfg)
	if err != nil {
		s.log.Warn("waf: config locale illisible — WAF actif en attente de l'Admin", "err", err)
		s.wafEngine.SetEnabled(true)
		return
	}
	if !ok {
		return
	}
	s.wafEngine.SetEnabled(cfg.Enabled)
	s.log.Info("waf: config chargée depuis le disque", "enabled", cfg.Enabled)
}

// portalConfigPath est la copie locale chiffrée de la config du portail Access poussée par l'Admin
// (réglages, vues, politique, accès temporaires, clé de groupe HA).
func portalConfigPath() string {
	if p := os.Getenv("GPX_PORTAL_CONFIG_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/portal-config.gpx"
}

// loadPortalConfigFromDisk relance le portail sur sa dernière config connue, sans l'Admin.
func (s *Server) loadPortalConfigFromDisk() {
	var payload portalPushPayload
	ok, err := s.cache.LoadFile(portalConfigPath(), &payload)
	if err != nil {
		s.log.Warn("portal: config locale illisible — en attente de l'Admin", "err", err)
		return
	}
	if !ok {
		return
	}
	s.applyPortalPayload(payload)
	s.log.Info("portal: config chargée depuis le disque", "enabled", payload.Enabled, "vues", len(payload.Views))
}

// autoRulesPath est la copie locale chiffrée des règles automatiques poussées par l'Admin.
func autoRulesPath() string {
	if p := os.Getenv("GPX_AUTO_RULES_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/auto-rules.gpx"
}

// applyAutoRules persiste les règles reçues de l'Admin puis les applique. La copie est écrite même
// si le moteur n'existe pas encore : il la relira à sa création.
func (s *Server) applyAutoRules(rules []edgere.Rule) {
	if err := s.cache.SaveFile(autoRulesPath(), rules); err != nil {
		s.log.Warn("rulesengine: persistance des règles échouée", "err", err)
	}
	if s.rulesEngine != nil {
		s.rulesEngine.ReplaceRules(rules)
	}
}

// loadAutoRulesFromDisk remet en service les dernières règles connues sans l'Admin.
func (s *Server) loadAutoRulesFromDisk() {
	var rules []edgere.Rule
	ok, err := s.cache.LoadFile(autoRulesPath(), &rules)
	if err != nil {
		s.log.Warn("rulesengine: copie locale illisible — en attente de l'Admin", "err", err)
		return
	}
	if !ok {
		return
	}
	s.rulesEngine.ReplaceRules(rules)
	s.log.Info("rulesengine: règles chargées depuis le disque", "count", len(rules))
}

// tunnelConfigPath est la copie locale chiffrée de la liste des pairs du tunnel L4 poussée par l'Admin.
func tunnelConfigPath() string {
	if p := os.Getenv("GPX_TUNNEL_CONFIG_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/tunnel-config.gpx"
}

// applyTunnelConfig persiste la liste des pairs du tunnel reçue de l'Admin puis l'applique.
func (s *Server) applyTunnelConfig(payload edgews.TunnelConfigPayload) {
	if err := s.cache.SaveFile(tunnelConfigPath(), payload); err != nil {
		s.log.Warn("tunnel: persistance des pairs échouée", "err", err)
	}
	s.setTunnelPeers(payload)
}

func (s *Server) setTunnelPeers(payload edgews.TunnelConfigPayload) {
	if s.tunnelManager == nil {
		return
	}
	peers := make([]tunnel.PeerConfig, 0, len(payload.Peers))
	for _, p := range payload.Peers {
		peers = append(peers, tunnel.PeerConfig{Name: p.Name, Addr: p.Addr})
	}
	s.tunnelManager.SetPeers(peers)
}

// loadTunnelConfigFromDisk rétablit les pairs du tunnel L4 sans l'Admin.
func (s *Server) loadTunnelConfigFromDisk() {
	var payload edgews.TunnelConfigPayload
	ok, err := s.cache.LoadFile(tunnelConfigPath(), &payload)
	if err != nil {
		s.log.Warn("tunnel: copie locale illisible — en attente de l'Admin", "err", err)
		return
	}
	if !ok {
		return
	}
	s.setTunnelPeers(payload)
	s.log.Info("tunnel: pairs chargés depuis le disque", "count", len(payload.Peers))
}

// pushedServerConfig est la configuration serveur HTTP poussée par l'Admin (0 = non défini).
type pushedServerConfig struct {
	ReadHeaderSeconds int `json:"read_header_seconds"`
	ReadSeconds       int `json:"read_seconds"`
	WriteSeconds      int `json:"write_seconds"`
	IdleSeconds       int `json:"idle_seconds"`
}

// merge reporte sur p les valeurs définies de o.
func (p pushedServerConfig) merge(o pushedServerConfig) pushedServerConfig {
	if o.ReadHeaderSeconds > 0 {
		p.ReadHeaderSeconds = o.ReadHeaderSeconds
	}
	if o.ReadSeconds > 0 {
		p.ReadSeconds = o.ReadSeconds
	}
	if o.WriteSeconds > 0 {
		p.WriteSeconds = o.WriteSeconds
	}
	if o.IdleSeconds > 0 {
		p.IdleSeconds = o.IdleSeconds
	}
	return p
}

// serverConfigPath est la copie locale chiffrée de la configuration serveur poussée par l'Admin.
// edge.json n'est pas réécrit : sa sérialisation ne relit pas ses propres clés.
func serverConfigPath() string {
	if p := os.Getenv("GPX_SERVER_CONFIG_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/server-config.gpx"
}

// applyServerConfig persiste puis applique les timeouts reçus de l'Admin ; ils prennent effet au
// prochain démarrage du serveur HTTP.
func (s *Server) applyServerConfig(p pushedServerConfig) {
	s.serverCfgMu.Lock()
	s.serverCfg = s.serverCfg.merge(p)
	err := s.cache.SaveFile(serverConfigPath(), s.serverCfg)
	s.serverCfgMu.Unlock()
	if err != nil {
		s.log.Warn("server-config: persistance échouée", "err", err)
	}
	s.setServerTimeouts(p)
}

func (s *Server) setServerTimeouts(p pushedServerConfig) {
	t := &s.cfg.Timeouts
	t.ReadHeaderSeconds = pickPositive(p.ReadHeaderSeconds, t.ReadHeaderSeconds)
	t.ReadSeconds = pickPositive(p.ReadSeconds, t.ReadSeconds)
	t.WriteSeconds = pickPositive(p.WriteSeconds, t.WriteSeconds)
	t.IdleSeconds = pickPositive(p.IdleSeconds, t.IdleSeconds)
}

func pickPositive(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

// loadServerConfigFromDisk réapplique les derniers timeouts reçus de l'Admin ; à appeler avant la
// création des serveurs HTTP.
func (s *Server) loadServerConfigFromDisk() {
	var p pushedServerConfig
	ok, err := s.cache.LoadFile(serverConfigPath(), &p)
	if err != nil {
		s.log.Warn("server-config: copie locale illisible — en attente de l'Admin", "err", err)
		return
	}
	if !ok {
		return
	}
	s.serverCfgMu.Lock()
	s.serverCfg = p
	s.serverCfgMu.Unlock()
	s.setServerTimeouts(p)
	s.log.Info("server-config: timeouts chargés depuis le disque")
}

// portalTemplatesPath est la copie locale chiffrée des modèles de pages du portail Access.
func portalTemplatesPath() string {
	if p := os.Getenv("GPX_PORTAL_TEMPLATES_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/portal-templates.gpx"
}

// applyPortalTemplates persiste les modèles de pages reçus de l'Admin puis les applique.
func (s *Server) applyPortalTemplates(tpls []portal.PageTemplate) {
	if err := s.cache.SaveFile(portalTemplatesPath(), tpls); err != nil {
		s.log.Warn("portal: persistance des modèles échouée", "err", err)
	}
	s.portal.ReplacePageTemplates(tpls)
}

// loadPortalTemplatesFromDisk rend au portail ses pages personnalisées sans l'Admin.
func (s *Server) loadPortalTemplatesFromDisk() {
	var tpls []portal.PageTemplate
	ok, err := s.cache.LoadFile(portalTemplatesPath(), &tpls)
	if err != nil {
		s.log.Warn("portal: modèles locaux illisibles — en attente de l'Admin", "err", err)
		return
	}
	if !ok {
		return
	}
	s.portal.ReplacePageTemplates(tpls)
	s.log.Info("portal: modèles chargés depuis le disque", "count", len(tpls))
}

// settingsPath est la copie locale chiffrée des réglages runtime poussés par l'Admin
// (protection des IP des access logs, journalisation, tracing, URL publique).
func settingsPath() string {
	if p := os.Getenv("GPX_EDGE_SETTINGS_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/edge-settings.gpx"
}

// receivePushedSettings persiste puis applique des réglages reçus de l'Admin. Sans copie
// locale, une passerelle redémarrée pendant une coupure de l'Admin écrirait les IP complètes
// dans son access log malgré l'anonymisation demandée.
func (s *Server) receivePushedSettings(p pushedSettings) {
	s.pushedMu.Lock()
	s.pushed = s.pushed.merge(p)
	err := s.cache.SaveFile(settingsPath(), s.pushed)
	s.pushedMu.Unlock()
	if err != nil {
		s.log.Warn("settings: persistance des réglages Admin échouée", "err", err)
	}
	s.applyPushedSettings(p)
}

// loadPushedSettingsFromDisk réapplique au démarrage les derniers réglages reçus de l'Admin.
func (s *Server) loadPushedSettingsFromDisk() {
	var p pushedSettings
	ok, err := s.cache.LoadFile(settingsPath(), &p)
	if err != nil {
		s.log.Warn("settings: copie locale illisible — en attente de l'Admin", "err", err)
		return
	}
	if !ok {
		return
	}
	s.pushedMu.Lock()
	s.pushed = p
	s.pushedMu.Unlock()
	s.applyPushedSettings(p)
	s.log.Info("settings: réglages Admin chargés depuis le disque")
}

func (s *Server) saveCache() {
	// Invalider immédiatement les chaînes dispatch ; le flush disque est debouncé.
	s.invalidateDispatchCache()
	s.saveCacheMu.Lock()
	defer s.saveCacheMu.Unlock()
	if s.saveCacheTimer != nil {
		s.saveCacheTimer.Stop()
	}
	s.saveCacheTimer = time.AfterFunc(500*time.Millisecond, s.saveCacheNow)
}

func (s *Server) saveCacheNow() {
	snap := &edgecache.Snapshot{
		SavedAt:       time.Now(),
		Routes:        s.table.All(),
		Certs:         s.certStore.AllPEMs(),
		Snippets:      s.snippetStore.All(),
		AuthProviders: s.providerStore.All(),
		ECHKeys:       s.ech.Keys(),
		ECHVersion:    s.ech.Version(),
	}
	if err := s.cache.Save(snap); err != nil {
		s.log.Warn("edge: sauvegarde cache échouée", "err", err)
		return
	}
	s.log.Debug("edge: cache local sauvegardé",
		"routes", len(snap.Routes),
		"certs", len(snap.Certs),
	)
}

// bansDBPurgeLoop purge toutes les heures les bans expirés et l'historique > 30 jours.
func (s *Server) bansDBPurgeLoop(ctx context.Context) {
	if s.bansDB == nil {
		return
	}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.bansDB.PurgeExpiredBans()
			_ = s.bansDB.PurgeBanHistory(time.Now().AddDate(0, 0, -30))
			_ = s.bansDB.PurgeUnbans(time.Now().AddDate(0, 0, -30))
			_ = s.bansDB.PurgeProxyErrors(time.Now().Add(-48 * time.Hour))
		}
	}
}

func (s *Server) autosaveLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.saveCacheNow()
			s.saveThreatState()
			s.saveBehaviorState()
			s.saveSurfaceState()
			s.saveAppsState()
		}
	}
}

// wsHeartbeatLoop envoie un heartbeat passerelle → Admin toutes les 30 s via WebSocket.
func (s *Server) wsHeartbeatLoop(ctx context.Context) {
	send := func() {
		var cpuPct, memPct float64
		if prev, err := telemetry.ReadCPUStat(); err == nil {
			time.Sleep(200 * time.Millisecond)
			if cur, err := telemetry.ReadCPUStat(); err == nil {
				cpuPct = telemetry.CPUUsagePct(prev, cur)
			}
		}
		if mem, err := telemetry.ReadMemStat(); err == nil {
			memPct = mem.UsagePct()
		}
		msg, _ := edgews.NewMessage(0, edgews.TypeEdgeHeartbeat, edgews.EdgeHeartbeatPayload{
			NodeName: s.cfg.Identity.NodeName,
			Role:     "edge",
			Version:  buildinfo.Edge,
			CPUPct:   cpuPct,
			MemPct:   memPct,
		})
		s.wsHub.BroadcastToAdmins(msg)
	}

	send()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			send()
		}
	}
}


// sendPortalLive envoie à l'Admin l'instantané des connexions pontées en cours du portail.
func (s *Server) sendPortalLive() {
	if s.portal == nil {
		return
	}
	msg, err := edgews.NewMessage(0, edgews.TypePortalLive, map[string]any{
		"node_name": s.cfg.Identity.NodeName,
		"sessions":  s.portal.LiveSessions(),
	})
	if err != nil {
		return
	}
	s.wsHub.BroadcastToAdmins(msg)
}

// portalLiveLoop renvoie l'instantané toutes les 30 s pour qu'un Admin redémarré retrouve l'état.
func (s *Server) portalLiveLoop(ctx context.Context) {
	tk := time.NewTicker(30 * time.Second)
	defer tk.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
			if s.portal != nil && len(s.portal.LiveSessions()) > 0 {
				s.sendPortalLive()
			}
		}
	}
}

// ocspLoop agrafe aux certificats une réponse OCSP obtenue auprès de l'AC (sans l'Admin).
func (s *Server) ocspLoop(ctx context.Context) {
	st := edgetls.NewOCSPStapler(s.certStore, s.log.Logger())
	st.OnUpdate = func(status map[string]edgetls.OCSPStatus) {
		for name, ss := range status {
			secs := time.Until(ss.NextUpdate).Seconds()
			if secs < 0 {
				secs = 0
			}
			metrics.OCSPStapleSeconds.WithLabelValues(name).Set(secs)
			revoked := 0.0
			if ss.Revoked {
				revoked = 1
			}
			metrics.OCSPRevoked.WithLabelValues(name).Set(revoked)
		}
	}
	st.Run(ctx)
}

// trafficWindow est la fenêtre du débit récent envoyé à l'Admin ; trafficEvery, son rythme (celui de la sonde de la
// carte de topologie).
const (
	trafficWindow = 60 * time.Second
	trafficEvery  = 5 * time.Second
)

// trafficLoop envoie à l'Admin le débit de la dernière minute : la carte de topologie ne peut plus le tirer des lignes
// d'accès, que l'Admin ne reçoit plus.
func (s *Server) trafficLoop(ctx context.Context) {
	if s.logStore == nil {
		return
	}
	ticker := time.NewTicker(trafficEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			qctx, cancel := context.WithTimeout(ctx, trafficEvery)
			total, blocked, errs, err := s.logStore.RecentCounts(qctx, time.Now().Add(-trafficWindow))
			cancel()
			if err != nil {
				continue
			}
			msg, err := edgews.NewMessage(0, edgews.TypeEdgeTraffic, edgews.EdgeTrafficPayload{
				NodeName: s.cfg.Identity.NodeName, WindowSec: int(trafficWindow.Seconds()), Requests: total, Blocked: blocked, Errors: errs,
			})
			if err == nil {
				s.wsHub.BroadcastToAdmins(msg)
			}
		}
	}
}
