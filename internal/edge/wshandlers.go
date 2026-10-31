// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"encoding/json"
	"github.com/vincamok/goproxify/internal/edge/plugins"
	"time"

	edgeagent "github.com/vincamok/goproxify/internal/edge/agent"
	edgecrowdsec "github.com/vincamok/goproxify/internal/edge/crowdsec"
	"github.com/vincamok/goproxify/internal/edge/errorpages"
	edgef2b "github.com/vincamok/goproxify/internal/edge/fail2ban"
	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/portal"
	"github.com/vincamok/goproxify/internal/edge/router"
	edgere "github.com/vincamok/goproxify/internal/edge/rulesengine"
	"github.com/vincamok/goproxify/internal/edge/siem"
	"github.com/vincamok/goproxify/internal/edge/threat"
	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
	edgetokens "github.com/vincamok/goproxify/internal/edge/tokens"
	"github.com/vincamok/goproxify/internal/edge/waf"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// --- Handlers WebSocket plan de contrôle ------------------------------------

// applyAdminMessage applique un message de l'Admin, ou le même document rattrapé auprès d'un pair du groupe HA.
// Les types de messages correspondent aux mêmes payloads que les endpoints HTTP.
func (s *Server) applyAdminMessage(connID string, msg edgews.Message) error {
	switch msg.Type {
	case edgews.TypePushRoutes:
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
		metrics.Edge.RouteCount.Set(float64(s.table.Len()))
		metrics.Config.ReloadTotal.WithLabelValues("routes", "success").Inc()
		metrics.Config.ReloadDuration.Observe(time.Since(reloadStart).Seconds())
		s.saveCache()
		s.log.Info("ws/admin: routes mises à jour", "count", len(routes), "purged_conflicts", purged)

	case edgews.TypeDeleteRoute:
		var p struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return err
		}
		s.table.Delete(p.ID)
		s.saveCache()
		s.log.Info("ws/admin: route supprimée", "id", p.ID)

	case edgews.TypePushCert:
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
		metrics.Edge.CertCount.Set(float64(s.certStore.Len()))
		metrics.UpdateCertExpiries(s.certStore.CertExpiries())
		metrics.Config.ReloadTotal.WithLabelValues("cert", "success").Inc()
		metrics.Config.ReloadDuration.Observe(time.Since(reloadCertStart).Seconds())
		s.saveCache()
		s.log.Info("ws/admin: certificat poussé", "name", cert.Name)

	case edgews.TypeACMEChallenge:
		var ch edgetls.ACMEChallenge
		if err := json.Unmarshal(msg.Payload, &ch); err != nil {
			return err
		}
		if err := s.certStore.Challenges.Apply(ch); err != nil {
			return err
		}
		s.log.Info("ws/admin: challenge ACME", "type", ch.Type, "domain", ch.Domain, "clear", ch.Clear)

	case edgews.TypePushECHKeys:
		var set edgetls.ECHKeySet
		if err := json.Unmarshal(msg.Payload, &set); err != nil {
			return err
		}
		if err := s.ech.SetStamped(set.Keys); err != nil {
			return err
		}
		s.saveCache()
		go s.pushECHReplica(context.Background())
		s.log.Info("ws/admin: clés ECH mises à jour", "count", len(set.Keys))

	case edgews.TypePushDelegations:
		var routes []*router.Route
		if err := json.Unmarshal(msg.Payload, &routes); err != nil {
			return err
		}
		s.applyDelegationRoutes(routes)

	case edgews.TypeASNOffer:
		var p edgews.ASNOfferPayload
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return err
		}
		s.handleASNOffer(p)

	case edgews.TypePushASN:
		var c edgews.ASNChunkPayload
		if err := json.Unmarshal(msg.Payload, &c); err != nil {
			return err
		}
		s.applyASNChunk(c)

	case edgews.TypePushPlugins:
		var pkgs []plugins.Package
		if err := json.Unmarshal(msg.Payload, &pkgs); err != nil {
			return err
		}
		s.applyPlugins(pkgs)

	case edgews.TypePushSnippets:
		var snippets []*router.Snippet
		if err := json.Unmarshal(msg.Payload, &snippets); err != nil {
			return err
		}
		s.snippetStore.Replace(snippets)
		s.saveCache()
		for _, sn := range snippets {
			if sn.Type == router.SnippetWAF {
				if ack, err := edgews.NewMessage(0, edgews.TypeWAFReloaded, map[string]string{
					"node_name": s.cfg.Identity.NodeName,
					"status":    "ok",
				}); err == nil {
					s.wsHub.BroadcastToAdmins(ack)
				}
				break
			}
		}

	case edgews.TypePushAuthProviders:
		var providers []*router.AuthProvider
		if err := json.Unmarshal(msg.Payload, &providers); err != nil {
			return err
		}
		s.providerStore.Replace(providers)
		s.saveCache()

	case edgews.TypePushIPProfiles:
		var profiles []*router.IPProfile
		if err := json.Unmarshal(msg.Payload, &profiles); err != nil {
			return err
		}
		s.applyIPProfiles(profiles)

	case edgews.TypePushBans:
		var list []*router.RuntimeBan
		if err := json.Unmarshal(msg.Payload, &list); err != nil {
			return err
		}
		s.applyBans(list)
		s.log.Info("ws/admin: bans mis à jour", "count", len(list))

	case edgews.TypeUnbanIPs:
		var list []edgews.UnbanEntry
		if err := json.Unmarshal(msg.Payload, &list); err != nil {
			return err
		}
		s.applyUnbans(list)
		s.log.Info("ws/admin: débans appliqués", "count", len(list))

	case edgews.TypePushCrowdSecConfig:
		var cfg edgecrowdsec.Config
		if err := json.Unmarshal(msg.Payload, &cfg); err != nil {
			return err
		}
		if s.crowdSecBouncer != nil {
			s.crowdSecBouncer.UpdateConfig(cfg)
			if err := s.saveCrowdSecConfig(cfg); err != nil {
				s.log.Warn("crowdsec: persistance config échouée", "err", err)
			}
			go s.crowdSecBouncer.SyncNow(context.Background())
		}
		s.log.Info("crowdsec: config mise à jour", "enabled", cfg.Enabled)

	case edgews.TypePushF2BConfig:
		var cfg edgef2b.Config
		if err := json.Unmarshal(msg.Payload, &cfg); err != nil {
			return err
		}
		if s.f2bEngine != nil {
			s.f2bEngine.UpdateConfig(cfg)
			if err := s.saveF2BConfig(cfg); err != nil {
				s.log.Warn("f2b: persistance config échouée", "err", err)
			}
			s.reloadBanStore()
		}
		s.log.Info("fail2ban: config mise à jour", "enabled", cfg.Enabled)

	case edgews.TypePushLogRetention:
		var p edgews.LogRetentionPayload
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return err
		}
		return s.applyLogRetention(p)

	case edgews.TypePushSIEMConfig:
		var cfg siem.Config
		if err := json.Unmarshal(msg.Payload, &cfg); err != nil {
			return err
		}
		return s.applySIEMConfig(cfg)

	case edgews.TypePushThreatConfig:
		var cfg threat.Config
		if err := json.Unmarshal(msg.Payload, &cfg); err != nil {
			return err
		}
		s.applyThreatConfig(cfg)
		s.log.Info(threat.Name+": config mise à jour", "enabled", cfg.Enabled)

	case edgews.TypePushWAFConfig:
		var cfg waf.EngineConfig
		if err := json.Unmarshal(msg.Payload, &cfg); err != nil {
			return err
		}
		s.applyWAFConfig(cfg)
		s.log.Info("waf: config mise à jour", "enabled", cfg.Enabled)

	case edgews.TypePushServerConfig:
		var body pushedServerConfig
		if err := json.Unmarshal(msg.Payload, &body); err != nil {
			return err
		}
		s.applyServerConfig(body)
		s.log.Info("ws/admin: server-config mis à jour (redémarrage requis)")

	case edgews.TypePushSettings:
		var payload pushedSettings
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			return err
		}
		s.receivePushedSettings(payload)

	case edgews.TypePushPortal:
		var payload portalPushPayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			return err
		}
		s.applyPortalPush(payload)

	case edgews.TypeKillPortalSession:
		var p struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return err
		}
		if s.portal != nil && s.portal.KillLive(p.ID) {
			s.log.Info("ws/admin: connexion portail terminée", "id", p.ID)
		}

	case edgews.TypePushErrorPages:
		var tpls []errorpages.Template
		if err := json.Unmarshal(msg.Payload, &tpls); err != nil {
			return err
		}
		if err := errorpages.DefaultStore().ReplaceAll(tpls); err != nil {
			s.log.Warn("ws/admin: error pages", "err", err)
			return err
		}
		s.log.Info("ws/admin: pages d'erreur mises à jour", "count", len(tpls))

	case edgews.TypePushGroupCard:
		var card edgews.GroupCard
		if err := json.Unmarshal(msg.Payload, &card); err != nil {
			return err
		}
		return s.applyGroupCard(card)

	case edgews.TypePushPortalTemplates:
		var tpls []portal.PageTemplate
		if err := json.Unmarshal(msg.Payload, &tpls); err != nil {
			return err
		}
		s.applyPortalTemplates(tpls)
		s.log.Info("ws/admin: templates Access mis à jour", "count", len(tpls))

	case edgews.TypeFullSync:
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
			metrics.Edge.RouteCount.Set(float64(s.table.Len()))
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

	case edgews.TypeApproveAgent:
		var p edgews.ApproveAgentPayload
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return err
		}
		return s.wsHub.ApproveAgent(p.AgentID)

	case edgews.TypeRevokeAgent:
		var p edgews.RevokeAgentPayload
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return err
		}
		return s.wsHub.RevokeAgent(p.AgentID)

	case edgews.TypeAdminToken:
		var p edgews.AdminTokenPayload
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return err
		}
		if p.Token != "" {
			if err := s.tokenStore.EnsureToken(adminWSTokenName, p.Token, edgetokens.RoleAdmin); err != nil {
				s.log.Warn("ws/admin: enregistrement token Admin échoué", "err", err)
			} else {
				s.log.Debug("ws/admin: token Admin enregistré dans le store")
			}
			s.adminTokenMu.Lock()
			s.adminToken = p.Token
			s.adminTokenMu.Unlock()
		}

	case edgews.TypeRevokeStaleAdminTokens:
		var p edgews.AdminTokenPayload
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return err
		}
		return s.revokeStaleAdminTokens(p.Token)

	case edgews.TypePushGatewayPeers:
		return s.applyGatewayPeersWS(msg.Payload)

	case edgews.TypePushDisabledRoutes:
		return s.applyDisabledRoutes(msg.Payload)

	case edgews.TypePushAutoRules:
		var rules []edgere.Rule
		if err := json.Unmarshal(msg.Payload, &rules); err != nil {
			return err
		}
		s.applyAutoRules(rules)
		s.log.Info("ws/admin: règles automatiques mises à jour", "count", len(rules))

	case edgews.TypePushTunnelConfig:
		var payload edgews.TunnelConfigPayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			return err
		}
		s.applyTunnelConfig(payload)
		s.log.Info("ws/admin: tunnel peers mis à jour", "count", len(payload.Peers))

	case edgews.TypeLogResume:
		return s.handleLogResume(connID, msg.Payload)

	case edgews.TypeLogAck:
		return s.handleLogAck(msg.Payload)

	case edgews.TypeLogLive:
		return s.handleLogLive(connID, msg.Payload)

	default:
		s.log.Debug("ws/admin: message inconnu ignoré", "type", msg.Type)
	}
	return nil
}

// handleWSAgentMessage traite les messages reçus d'un Agent via WS.
func (s *Server) handleWSAgentMessage(connID string, msg edgews.Message) error {
	switch msg.Type {
	case edgews.TypeAgentHeartbeat:
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
		s.nodeStore.Upsert(edgeagent.NodeInfo{
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

	case edgews.TypeAgentContainers:
		// Même traitement que POST /internal/v1/agent/containers
		s.log.Debug("ws/agent: containers reçus", "agent", connID)

	case edgews.TypeAgentMetrics:
		var mp edgews.AgentMetricsPayload
		if err := json.Unmarshal(msg.Payload, &mp); err != nil {
			return err
		}
		if s.metrics != nil {
			s.metrics.UpdateFromMetrics(mp)
		}
		s.log.Debug("ws/agent: métriques reçues", "agent", connID, "containers", len(mp.Containers))

	case edgews.TypeAgentEvent:
		var ev edgeagent.NodeEvent
		if err := json.Unmarshal(msg.Payload, &ev); err == nil {
			if ev.NodeName == "" {
				ev.NodeName = connID
			}
			recorded := s.nodeStore.RecordEvent(ev)
			if payload, err := json.Marshal(recorded); err == nil {
				s.wsHub.BroadcastToAdmins(edgews.Message{Type: edgews.TypeAgentEvent, Payload: payload})
			}
		}

	case edgews.TypeAgentLog:
		// Relayer les logs vers l'Admin via WS
		relayMsg := edgews.Message{Type: edgews.TypeAgentLog, Payload: msg.Payload}
		s.wsHub.BroadcastToAdmins(relayMsg)

	case edgews.TypeShellData, edgews.TypeShellReady, edgews.TypeShellClose, edgews.TypeShellError:
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
