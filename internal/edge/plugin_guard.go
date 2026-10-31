// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	edgef2b "github.com/vincamok/goproxify/internal/edge/fail2ban"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/router"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

const (
	pluginBanDefaultWindow   = 300 * time.Second
	pluginBanDefaultDuration = time.Hour
	pluginGuardSweepAbove    = 4096
)

type pluginHits struct {
	at     []time.Time
	window time.Duration
}

// pluginGuard compte, par plugin et par cible de ban, les requêtes qu'un plugin de détection a refusées dans une
// fenêtre glissante. L'état est en mémoire : un redémarrage repart de zéro, comme les compteurs Fail2Ban.
type pluginGuard struct {
	mu   sync.Mutex
	hits map[string]*pluginHits
}

// record ajoute un refus et retourne leur nombre dans la fenêtre.
func (g *pluginGuard) record(key string, window time.Duration, now time.Time) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.hits == nil {
		g.hits = map[string]*pluginHits{}
	}
	if len(g.hits) > pluginGuardSweepAbove {
		for k, h := range g.hits {
			if len(h.at) == 0 || now.Sub(h.at[len(h.at)-1]) > h.window {
				delete(g.hits, k)
			}
		}
	}
	h := g.hits[key]
	if h == nil {
		h = &pluginHits{}
		g.hits[key] = h
	}
	h.window = window
	cutoff := now.Add(-window)
	kept := h.at[:0]
	for _, t := range h.at {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	h.at = append(kept, now)
	return len(h.at)
}

func (g *pluginGuard) reset(key string) {
	g.mu.Lock()
	delete(g.hits, key)
	g.mu.Unlock()
}

// configInt lit un entier de la configuration d'un plugin : un nombre JSON, ou une chaîne quand il vient d'un
// label Docker. Absent ou illisible : def.
func configInt(cfg map[string]any, key string, def int) int {
	switch v := cfg[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}

// pluginDenied traite le refus d'un plugin au hook de requête. Tout refus est compté dans la métrique du pipeline.
// Celui d'un plugin de détection est en plus signalé au journal d'accès (catégorie = nom du plugin), puis compté
// par IP : au-delà de ban_after refus en ban_window_sec secondes, l'IP est bannie ban_duration_sec secondes.
func (s *Server) pluginDenied(r *http.Request, a activePlugin) {
	name := a.p.Manifest.Name
	metrics.Pipeline.BlockedTotal.WithLabelValues(r.Host, "plugin", name).Inc()
	if !a.p.Manifest.Detector {
		return
	}
	edgelog.NoteWAF(r.Context(), name)

	after := configInt(a.cfg, "ban_after", 0)
	if after <= 0 {
		return
	}
	ip := edgelog.RealIP(r)
	if s.profileStore.IsAllowed(ip) || s.profileStore.IsWhitelisted(ip) {
		return
	}
	var whitelist []string
	if s.f2bEngine != nil {
		whitelist = s.f2bEngine.GetConfig().Whitelist
	}
	target, ok := edgef2b.BanTarget(ip, whitelist)
	if !ok {
		return
	}
	window := time.Duration(configInt(a.cfg, "ban_window_sec", 0)) * time.Second
	if window <= 0 {
		window = pluginBanDefaultWindow
	}
	duration := time.Duration(configInt(a.cfg, "ban_duration_sec", 0)) * time.Second
	if duration <= 0 {
		duration = pluginBanDefaultDuration
	}
	key := name + "\x00" + target
	if s.pluginGuard.record(key, window, time.Now()) < after {
		return
	}
	s.pluginGuard.reset(key)
	s.banForPlugin(target, name, after, window, duration)
}

// banForPlugin pose le ban d'un plugin de détection. Comme pour Ephor et Fail2Ban, il est persisté
// localement et propagé aux pairs : il s'applique et survit à un redémarrage sans l'Admin, qui est seulement notifié.
func (s *Server) banForPlugin(ip, plugin string, after int, window, duration time.Duration) {
	source := edgews.PluginBanSourcePrefix + plugin
	expires := time.Now().Add(duration)
	reason := plugin + ": trop de refus"
	b := &router.RuntimeBan{ID: source + "-" + ip, IP: ip, Reason: reason, Source: source, ExpiresAt: &expires, UserAgent: s.lastUA.Get(ip)}
	s.addBanEvent(ip, source)
	s.gossipBanToPeers(b)
	if s.bansDB != nil {
		if err := s.bansDB.UpsertRuntimeBan(b); err != nil {
			s.log.Warn("plugin: persistance ban DB échouée", "plugin", plugin, "err", err)
		}
	}
	s.reloadBanStore()
	s.log.Info("plugin: IP bannie", "plugin", plugin, "ip", ip, "refus", after, "fenetre", window, "duree", duration)

	payload := edgews.ThreatBanPayload{
		IP: ip, Reason: reason, Source: source,
		ExpiresAt: expires.UTC().Format(time.RFC3339),
		NodeName:  s.cfg.Identity.NodeName,
		UserAgent: b.UserAgent,
	}
	if msg, err := edgews.NewMessage(0, edgews.TypeThreatBan, payload); err == nil {
		s.wsHub.BroadcastToAdmins(msg)
	}
}
