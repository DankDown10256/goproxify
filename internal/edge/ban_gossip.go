// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/edge/bansdb"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
)

const bansGossipPath = "/internal/v1/bans/gossip"

// Les bans circulent normalement par l'Admin (il les diffuse à toutes les passerelles connectées). Ce
// circuit entre passerelles pairs prend le relais quand l'Admin est indisponible : un ban décidé
// localement est envoyé aux pairs tout de suite, et chaque passerelle récupère périodiquement les
// bans actifs de ses pairs. Un ban reçu d'un pair n'est jamais réémis (pas de boucle d'échanges).

// gossipBanToPeers envoie un ban local aux passerelles pairs (au mieux, sans bloquer).
func (s *Server) gossipBanToPeers(b *router.RuntimeBan) {
	if s.peers == nil || b == nil || b.IP == "" {
		return
	}
	body, err := json.Marshal([]*router.RuntimeBan{b})
	if err != nil {
		return
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for _, p := range s.peers.All() {
		p := p
		go func() {
			req, err := http.NewRequest(http.MethodPost, p.Endpoint+bansGossipPath, bytes.NewReader(body))
			if err != nil {
				return
			}
			req.Header.Set("Authorization", "Bearer "+p.Token)
			req.Header.Set("Content-Type", "application/json")
			if resp, err := client.Do(req); err == nil {
				resp.Body.Close()
			}
		}()
	}
}

// POST /internal/v1/bans/gossip : un pair transmet des bans locaux.
func (s *Server) handleBansGossip(w http.ResponseWriter, r *http.Request) {
	var list []router.RuntimeBan
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&list); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if n := s.mergePeerBans(list); n > 0 {
		s.log.Info("bans: reçus d'une passerelle pair", "count", n)
	}
	w.WriteHeader(http.StatusNoContent)
}

// syncBansFromPeer récupère les bans actifs d'un pair (filet de sécurité du circuit d'envoi).
func (s *Server) syncBansFromPeer(ctx context.Context, client *http.Client, p proxy.PeerInfo) {
	if s.bansDB == nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Endpoint+"/internal/v1/bans", nil)
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
	var rows []bansdb.BanRow
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&rows); err != nil {
		return
	}
	unbans, _ := s.bansDB.Unbans()
	list := make([]router.RuntimeBan, 0, len(rows))
	for _, r := range rows {
		// Ban posé avant un déban de son IP que le pair n'a pas encore reçu (Admin injoignable pour lui).
		if t, ok := unbans[r.IP]; ok && !r.CreatedAt.After(t) {
			continue
		}
		list = append(list, router.RuntimeBan{ID: r.ID, IP: r.IP, Reason: r.Reason, Source: r.Source, Scope: r.Scope, UserAgent: r.UserAgent, ExpiresAt: r.ExpiresAt})
	}
	if n := s.mergePeerBans(list); n > 0 {
		s.log.Info("bans: rattrapés auprès d'une passerelle pair", "pair", p.Name, "count", n)
	}
}

// banScopeApplies dit si un ban visant `scope` (nom de passerelle ou "group:<nom>", vide = toutes) concerne
// cette passerelle. Les pairs se partagent leurs bans, mais un ban limité à une passerelle ou à un groupe
// ne doit pas être adopté par les autres.
func (s *Server) banScopeApplies(scope string) bool {
	if scope == "" || scope == s.cfg.Identity.NodeName {
		return true
	}
	if group, ok := strings.CutPrefix(scope, "group:"); ok && s.portal != nil {
		if g, _, _, has := s.portal.HAGroupInfo(); has && g == group {
			return true
		}
	}
	return false
}

// mergePeerBans ajoute les bans non expirés que la passerelle ne connaît pas (même identifiant ou même IP).
func (s *Server) mergePeerBans(list []router.RuntimeBan) int {
	if s.bansDB == nil || len(list) == 0 {
		return 0
	}
	known := map[string]bool{}
	if rows, err := s.bansDB.ActiveBans(); err == nil {
		for _, r := range rows {
			known[r.ID] = true
			known["ip:"+r.IP] = true
		}
	}
	now := time.Now()
	added := 0
	for _, b := range list {
		if b.IP == "" || b.ID == "" || known[b.ID] || known["ip:"+b.IP] {
			continue
		}
		if !s.banScopeApplies(b.Scope) {
			continue
		}
		if b.ExpiresAt != nil && !b.ExpiresAt.After(now) {
			continue
		}
		if err := s.bansDB.UpsertRuntimeBan(&b); err != nil {
			s.log.Warn("bans: persistance d'un ban de pair échouée", "err", err)
			continue
		}
		known[b.ID], known["ip:"+b.IP] = true, true
		added++
	}
	if added > 0 {
		s.reloadBanStore()
	}
	return added
}
