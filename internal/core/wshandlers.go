// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"encoding/json"
	"os"
	"time"

	coreagent "github.com/vincamok/goproxify/internal/core/agent"
	"github.com/vincamok/goproxify/internal/core/errorpages"
	corecrowdsec "github.com/vincamok/goproxify/internal/core/crowdsec"
	coref2b "github.com/vincamok/goproxify/internal/core/fail2ban"
	"github.com/vincamok/goproxify/internal/core/metrics"
	"github.com/vincamok/goproxify/internal/core/portal"
	"github.com/vincamok/goproxify/internal/core/router"
	"github.com/vincamok/goproxify/internal/core/threat"
	coretokens "github.com/vincamok/goproxify/internal/core/tokens"
	corews "github.com/vincamok/goproxify/internal/core/ws"
)

// --- Handlers WebSocket plan de contrôle ------------------------------------

// handleWSAdminMessage traite les messages reçus d'un Admin via WS.
// Les types de messages correspondent aux mêmes payloads que les endpoints HTTP.
func (s *Server) handleWSAdminMessage(connID string, msg corews.Message) error {
	switch msg.Type {
	case corews.TypePushRoutes:
		var routes []*router.Route
		if err := json.Unmarshal(msg.Payload, &routes); err != nil {
			metrics.Config.ReloadTotal.WithLabelValues("routes", "error").Inc()
			return err
		}
		reloadStart := time.Now()
		// Un push vide (mode fichiers) ne doit pas effacer proxies/*.json ni les agents.
		routes = s.mergePushPreservingFileProxies(routes)
		if err := s.table.Replace(routes); err != nil {
			metrics.Config.ReloadTotal.WithLabelValues("routes", "error").Inc()
			return err
		}
		s.ensurePortalPublicRoute()
		purged := s.purgeRoutesShadowedByPassthrough()
		metrics.Core.RouteCount.Set(float64(s.table.Len()))
		metrics.Config.ReloadTotal.WithLabelValues("routes", "success").Inc()
		metrics.Config.ReloadDuration.Observe(time.Since(reloadStart).Seconds())
		s.saveCache()
		s.log.Info("ws/admin: routes mises à jour", "count", len(routes), "purged_conflicts", purged)

	case corews.TypeDeleteRoute:
		var p struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return err
		}
		s.table.Delete(p.ID)
		s.saveCache()
		s.log.Info("ws/admin: route supprimée", "id", p.ID)

	case corews.TypePushCert:
		var cert struct {
			Name    string `json:"name"`
			CertPEM []byte `json:"cert_pem"`
			KeyPEM  []byte `json:"key_pem"`
		}
		if err := json.Unmarshal(msg.Payload, &cert); err != nil {
			metrics.Config.ReloadTotal.WithLabelValues("cert", "error").Inc()
			return err
		}
		reloadCertStart := time.Now()
		if err := s.certStore.StorePEM(cert.Name, cert.CertPEM, cert.KeyPEM); err != nil {
			metrics.Config.ReloadTotal.WithLabelValues("cert", "error").Inc()
			return err
		}
		s.writeCertToDisk(cert.Name, cert.CertPEM, cert.KeyPEM)
		metrics.Core.CertCount.Set(float64(s.certStore.Len()))
		metrics.UpdateCertExpiries(s.certStore.CertExpiries())
		metrics.Config.ReloadTotal.WithLabelValues("cert", "success").Inc()
		metrics.Config.ReloadDuration.Observe(time.Since(reloadCertStart).Seconds())
		s.saveCache()
		s.log.Info("ws/admin: certificat poussé", "name", cert.Name)

	case corews.TypePushDelegations:
		var routes []*router.Route
		if err := json.Unmarshal(msg.Payload, &routes); err != nil {
			return err
		}
		s.applyDelegationRoutes(routes)

	case corews.TypePushSnippets:
		var snippets []*router.Snippet
		if err := json.Unmarshal(msg.Payload, &snippets); err != nil {
			return err
		}
		s.snippetStore.Replace(snippets)
		s.saveCache()
		for _, sn := range snippets {
			if sn.Type == router.SnippetWAF {
				if ack, err := corews.NewMessage(0, corews.TypeWAFReloaded, map[string]string{
					"node_name": s.cfg.Identity.NodeName,
					"status":    "ok",
				}); err == nil {
					s.wsHub.BroadcastToAdmins(ack)
				}
				break
			}
		}

	case corews.TypePushAuthProviders:
		var providers []*router.AuthProvider
		if err := json.Unmarshal(msg.Payload, &providers); err != nil {
			return err
		}
		s.providerStore.Replace(providers)
		s.saveCache()

	case corews.TypePushIPProfiles:
		var profiles []*router.IPProfile
		if err := json.Unmarshal(msg.Payload, &profiles); err != nil {
			return err
		}
		s.applyIPProfiles(profiles)

	case corews.TypePushBans:
		var list []*router.RuntimeBan
		if err := json.Unmarshal(msg.Payload, &list); err != nil {
			return err
		}
		s.applyBans(list)
		s.log.Info("ws/admin: bans mis à jour", "count", len(list))

	case corews.TypePushCrowdSecConfig:
		var cfg corecrowdsec.Config
		if err := json.Unmarshal(msg.Payload, &cfg); err != nil {
			return err
		}
		if s.crowdSecBouncer != nil {
			s.crowdSecBouncer.UpdateConfig(cfg)
			if err := corecrowdsec.SaveConfig("", cfg); err != nil {
				s.log.Warn("crowdsec: persistance config échouée", "err", err)
			}
			go s.crowdSecBouncer.SyncNow(context.Background())
		}
		s.log.Info("crowdsec: config mise à jour", "enabled", cfg.Enabled)

	case corews.TypePushF2BConfig:
		var cfg coref2b.Config
		if err := json.Unmarshal(msg.Payload, &cfg); err != nil {
			return err
		}
		if s.f2bEngine != nil {
			s.f2bEngine.UpdateConfig(cfg)
			if err := coref2b.SaveConfig("", cfg); err != nil {
				s.log.Warn("f2b: persistance config échouée", "err", err)
			}
		}
		s.log.Info("fail2ban: config mise à jour", "enabled", cfg.Enabled)

	case corews.TypePushThreatConfig:
		var cfg threat.Config
		if err := json.Unmarshal(msg.Payload, &cfg); err != nil {
			return err
		}
		if s.threatEngine != nil {
			s.threatEngine.UpdateConfig(cfg)
		}
		s.log.Info(threat.Name+": config mise à jour", "enabled", cfg.Enabled)

	case corews.TypePushServerConfig:
		var body struct {
			ReadHeaderSeconds int `json:"read_header_seconds"`
			ReadSeconds       int `json:"read_seconds"`
			WriteSeconds      int `json:"write_seconds"`
			IdleSeconds       int `json:"idle_seconds"`
		}
		if err := json.Unmarshal(msg.Payload, &body); err != nil {
			return err
		}
		if body.ReadHeaderSeconds > 0 {
			s.cfg.Timeouts.ReadHeaderSeconds = body.ReadHeaderSeconds
		}
		if body.ReadSeconds > 0 {
			s.cfg.Timeouts.ReadSeconds = body.ReadSeconds
		}
		if body.WriteSeconds > 0 {
			s.cfg.Timeouts.WriteSeconds = body.WriteSeconds
		}
		if body.IdleSeconds > 0 {
			s.cfg.Timeouts.IdleSeconds = body.IdleSeconds
		}
		if s.cfgPath != "" {
			if data, err := json.MarshalIndent(s.cfg, "", "  "); err == nil {
				_ = os.WriteFile(s.cfgPath, data, 0o640)
			}
		}
		s.log.Info("ws/admin: server-config mis à jour (redémarrage requis)")

	case corews.TypePushSettings:
		var payload pushedSettings
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			return err
		}
		s.applyPushedSettings(payload)

	case corews.TypePushPortal:
		var payload portalPushPayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			return err
		}
		s.applyPortalPush(payload)

	case corews.TypePushErrorPages:
		var tpls []errorpages.Template
		if err := json.Unmarshal(msg.Payload, &tpls); err != nil {
			return err
		}
		if err := errorpages.DefaultStore().ReplaceAll(tpls); err != nil {
			s.log.Warn("ws/admin: error pages", "err", err)
			return err
		}
		s.log.Info("ws/admin: pages d'erreur mises à jour", "count", len(tpls))

	case corews.TypePushPortalTemplates:
		var tpls []portal.PageTemplate
		if err := json.Unmarshal(msg.Payload, &tpls); err != nil {
			return err
		}
		s.portal.ReplacePageTemplates(tpls)
		s.log.Info("ws/admin: templates Access mis à jour", "count", len(tpls))

	case corews.TypeFullSync:
		reloadFullStart := time.Now()
		// full_sync contient routes + certs + snippets + providers dans un seul payload
		var fsync struct {
			Routes    []*router.Route        `json:"routes"`
			Snippets  []*router.Snippet      `json:"snippets"`
			Providers []*router.AuthProvider `json:"providers"`
			Profiles  []*router.IPProfile    `json:"ip_profiles"`
			Bans      []*router.RuntimeBan   `json:"bans"`
		}
		if err := json.Unmarshal(msg.Payload, &fsync); err != nil {
			return err
		}
		if fsync.Routes != nil {
			routes := s.mergePushPreservingFileProxies(fsync.Routes)
			_ = s.table.Replace(routes)
			s.ensurePortalPublicRoute()
			purged := s.purgeRoutesShadowedByPassthrough()
			metrics.Core.RouteCount.Set(float64(s.table.Len()))
			s.log.Info("ws/admin: full_sync routes", "count", len(routes), "purged_conflicts", purged)
		} else {
			// Mode fichiers : ne pas Replace([]) — réinjecter proxies/*.json par-dessus la table.
			s.loadProductionProxies()
		}
		if fsync.Snippets != nil {
			s.snippetStore.Replace(fsync.Snippets)
		}
		if fsync.Providers != nil {
			s.providerStore.Replace(fsync.Providers)
		}
		if fsync.Profiles != nil {
			s.applyIPProfiles(fsync.Profiles)
		}
		if fsync.Bans != nil {
			s.applyBans(fsync.Bans)
		}
		metrics.Config.ReloadTotal.WithLabelValues("full_sync", "success").Inc()
		metrics.Config.ReloadDuration.Observe(time.Since(reloadFullStart).Seconds())
		s.saveCache()
		s.log.Info("ws/admin: full_sync appliqué",
			"routes", len(fsync.Routes),
			"snippets", len(fsync.Snippets),
			"providers", len(fsync.Providers),
			"ip_profiles", len(fsync.Profiles),
			"bans", len(fsync.Bans),
		)

	case corews.TypeApproveAgent:
		var p corews.ApproveAgentPayload
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return err
		}
		return s.wsHub.ApproveAgent(p.AgentID)

	case corews.TypeRevokeAgent:
		var p corews.RevokeAgentPayload
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return err
		}
		return s.wsHub.RevokeAgent(p.AgentID)

	case corews.TypeAdminToken:
		var p corews.AdminTokenPayload
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return err
		}
		if p.Token != "" {
			if err := s.tokenStore.EnsureToken("admin-ws", p.Token, coretokens.RoleAdmin); err != nil {
				s.log.Warn("ws/admin: enregistrement token Admin échoué", "err", err)
			} else {
				s.log.Debug("ws/admin: token Admin enregistré dans le store")
			}
			s.adminTokenMu.Lock()
			s.adminToken = p.Token
			s.adminTokenMu.Unlock()
		}

	case corews.TypePushGatewayPeers:
		return s.applyGatewayPeersWS(msg.Payload)

	default:
		s.log.Debug("ws/admin: message inconnu ignoré", "type", msg.Type)
	}
	return nil
}

// handleWSAgentMessage traite les messages reçus d'un Agent via WS.
func (s *Server) handleWSAgentMessage(connID string, msg corews.Message) error {
	switch msg.Type {
	case corews.TypeAgentHeartbeat:
		var hb agentHeartbeatPayload
		if err := json.Unmarshal(msg.Payload, &hb); err != nil {
			return err
		}
		if hb.NodeName == "" {
			hb.NodeName = connID
		}
		if !hasRuntime(hb.ContainerRuntimes, "docker", "podman") {
			s.purgeDockerRoutesForAgent(hb.NodeName)
		}
		s.nodeStore.Upsert(coreagent.NodeInfo{
			NodeName:          hb.NodeName,
			Role:              "agent",
			Version:           hb.Version,
			Endpoint:          hb.Endpoint,
			CPUPCT:            hb.CPUPCT,
			MemPCT:            hb.MemPCT,
			ContainerRuntimes: hb.ContainerRuntimes,
			AgentConfig:       hb.AgentConfig,
		})
		if s.metrics != nil {
			s.metrics.UpdateHost(hb.Endpoint, hb.CPUPCT, hb.MemPCT)
		}

	case corews.TypeAgentContainers:
		// Même traitement que POST /internal/v1/agent/containers
		s.log.Debug("ws/agent: containers reçus", "agent", connID)

	case corews.TypeAgentMetrics:
		var mp corews.AgentMetricsPayload
		if err := json.Unmarshal(msg.Payload, &mp); err != nil {
			return err
		}
		if s.metrics != nil {
			s.metrics.UpdateFromMetrics(mp)
		}
		s.log.Debug("ws/agent: métriques reçues", "agent", connID, "containers", len(mp.Containers))

	case corews.TypeAgentEvent:
		var ev coreagent.NodeEvent
		if err := json.Unmarshal(msg.Payload, &ev); err == nil {
			if ev.NodeName == "" {
				ev.NodeName = connID
			}
			recorded := s.nodeStore.RecordEvent(ev)
			if payload, err := json.Marshal(recorded); err == nil {
				s.wsHub.BroadcastToAdmins(corews.Message{Type: corews.TypeAgentEvent, Payload: payload})
			}
		}

	case corews.TypeAgentLog:
		// Relayer les logs vers l'Admin via WS
		relayMsg := corews.Message{Type: corews.TypeAgentLog, Payload: msg.Payload}
		s.wsHub.BroadcastToAdmins(relayMsg)

	case corews.TypeShellData, corews.TypeShellReady, corews.TypeShellClose, corews.TypeShellError:
		if s.portal != nil {
			if b := s.portal.ShellBroker(); b != nil {
				b.HandleAgentMessage(msg.Type, msg.Payload)
			}
		}

	default:
		s.log.Debug("ws/agent: message inconnu ignoré", "type", msg.Type)
	}
	return nil
}
