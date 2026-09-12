// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"context"
	"encoding/json"
	"time"

	"github.com/vincamok/goproxify/internal/agent/telemetry"
	"github.com/vincamok/goproxify/internal/buildinfo"
	corecache "github.com/vincamok/goproxify/internal/core/cache"
	"github.com/vincamok/goproxify/internal/core/bans"
	"github.com/vincamok/goproxify/internal/core/cluster"
	"github.com/vincamok/goproxify/internal/core/ipprofiles"
	"github.com/vincamok/goproxify/internal/core/metrics"
	"github.com/vincamok/goproxify/internal/core/raft"
	"github.com/vincamok/goproxify/internal/core/router"
	corews "github.com/vincamok/goproxify/internal/core/ws"
)

// --- Cache & reconnexion -------------------------------------------------

// applyIPProfiles met à jour le store en mémoire et persiste sur le volume Core.
func (s *Server) applyIPProfiles(profiles []*router.IPProfile) {
	s.profileStore.Replace(profiles)
	if err := ipprofiles.Save(ipprofiles.Dir(), profiles); err != nil {
		s.log.Warn("core: persistance profils IP échouée", "err", err)
		return
	}
	s.log.Debug("core: profils IP persistés", "count", len(profiles), "dir", ipprofiles.Dir())
}

func (s *Server) loadIPProfilesFromDisk() {
	profiles, err := ipprofiles.Load(ipprofiles.Dir())
	if err != nil {
		s.log.Warn("core: lecture profils IP disque échouée", "err", err)
		return
	}
	if profiles == nil {
		return
	}
	s.profileStore.Replace(profiles)
	s.log.Info("core: profils IP chargés depuis le disque",
		"count", len(profiles),
		"dir", ipprofiles.Dir(),
	)
}

// applyBans met à jour le store en mémoire et persiste sur le volume Core.
func (s *Server) applyBans(list []*router.RuntimeBan) {
	// Conserver la liste Admin pour pouvoir y fusionner les bans threat.
	s.bansMu.Lock()
	s.lastBanList = list
	merged := append(list, s.pendingThreatBans...)
	s.bansMu.Unlock()

	s.banStore.Replace(merged)
	if err := bans.Save(bans.Dir(), list); err != nil {
		s.log.Warn("core: persistance bans échouée", "err", err)
		return
	}
	s.log.Debug("core: bans persistés", "count", len(list), "dir", bans.Dir())
}

func (s *Server) loadBansFromDisk() {
	list, err := bans.Load(bans.Dir())
	if err != nil {
		s.log.Warn("core: lecture bans disque échouée", "err", err)
		return
	}
	if list == nil {
		return
	}
	s.banStore.Replace(list)
	s.log.Info("core: bans chargés depuis le disque",
		"count", len(list),
		"dir", bans.Dir(),
	)
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
	snap := &corecache.Snapshot{
		SavedAt:       time.Now(),
		Routes:        s.table.All(),
		Certs:         s.certStore.AllPEMs(),
		Snippets:      s.snippetStore.All(),
		AuthProviders: s.providerStore.All(),
	}
	if err := s.cache.Save(snap); err != nil {
		s.log.Warn("core: sauvegarde cache échouée", "err", err)
		return
	}
	s.log.Debug("core: cache local sauvegardé",
		"routes", len(snap.Routes),
		"certs", len(snap.Certs),
	)
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
			if err := s.wafEngine.SaveSnapshot("/etc/goproxify/waf-behavior.json"); err != nil {
				s.log.Warn("waf: autosave snapshot échoué", "err", err)
			}
		}
	}
}

func (s *Server) applyClusterCommand(entry raft.LogEntry) {
	cmd, err := cluster.DecodeCommand(entry)
	if err != nil {
		s.log.Warn("cluster: commande invalide", "err", err)
		return
	}
	switch cmd.Type {
	case cluster.CmdPushRoutes:
		var payload cluster.RoutesPayload
		if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
			s.log.Warn("cluster: décode routes", "err", err)
			return
		}
		var routes []*router.Route
		for _, raw := range payload.Routes {
			var r router.Route
			if err := json.Unmarshal(raw, &r); err == nil {
				routes = append(routes, &r)
			}
		}
		s.table.Replace(routes) //nolint:errcheck
		metrics.Core.RouteCount.Set(float64(s.table.Len()))
		s.saveCache()
		s.log.Info("cluster: routes appliquées", "count", len(routes))

	case cluster.CmdPushCert:
		var payload cluster.CertPayload
		if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
			s.log.Warn("cluster: décode cert", "err", err)
			return
		}
		if err := s.certStore.StorePEM(payload.Name, payload.CertPEM, payload.KeyPEM); err != nil {
			s.log.Warn("cluster: store cert", "err", err)
			return
		}
		metrics.Core.CertCount.Set(float64(s.certStore.Len()))
		s.log.Info("cluster: certificat appliqué", "name", payload.Name)
	}
}

// wsHeartbeatLoop envoie un heartbeat Core → Admin toutes les 30 s via WebSocket.
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
		msg, _ := corews.NewMessage(0, corews.TypeCoreHeartbeat, corews.CoreHeartbeatPayload{
			NodeName: s.cfg.Identity.NodeName,
			Role:     "core",
			Version:  buildinfo.Core,
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

