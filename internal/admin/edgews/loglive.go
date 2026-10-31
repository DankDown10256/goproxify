// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"encoding/json"
	"sync"
	"time"

	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

const (
	// liveTTL : durée d'une demande Live ; renouvelée toutes les liveRenew tant qu'une vue est ouverte, de sorte
	// qu'une Admin qui s'arrête ne laisse pas les passerelles émettre plus de liveTTL.
	liveTTL   = 30
	liveRenew = 10 * time.Second
)

// liveState compte les vues Live ouvertes.
type liveState struct {
	mu      sync.Mutex
	viewers int
	stop    chan struct{}
}

// AcquireLive signale qu'une vue Live est ouverte et rend la fonction qui la ferme. L'Admin ne reçoit pas les accès
// ordinaires : les passerelles ne lui envoient leurs lignes qu'entre l'ouverture de la première vue et la fermeture
// de la dernière.
func (m *Manager) AcquireLive() (release func()) {
	l := &m.live
	l.mu.Lock()
	l.viewers++
	if l.viewers == 1 {
		l.stop = make(chan struct{})
		go m.renewLive(l.stop)
	}
	l.mu.Unlock()
	m.pushLiveToAll()
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			if l.viewers--; l.viewers == 0 {
				close(l.stop)
			}
		})
	}
}

func (m *Manager) renewLive(stop chan struct{}) {
	t := time.NewTicker(liveRenew)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			m.pushLiveToAll()
		}
	}
}

func (m *Manager) liveWanted() bool {
	m.live.mu.Lock()
	defer m.live.mu.Unlock()
	return m.live.viewers > 0
}

func (m *Manager) pushLiveToAll() {
	m.mu.RLock()
	entries := make([]*edgeEntry, 0, len(m.edges))
	for _, e := range m.edges {
		entries = append(entries, e)
	}
	m.mu.RUnlock()
	for _, e := range entries {
		m.sendLiveSubscribe(e)
	}
}

// sendLiveSubscribe demande à la passerelle d'envoyer ses nouvelles lignes, si une vue Live est ouverte.
func (m *Manager) sendLiveSubscribe(e *edgeEntry) {
	// Avec le volume de logs, la vue Live est alimentée par les lignes qui arrivent (voir handleVault) : la passerelle n'a rien
	// à lui envoyer en plus.
	if e.client == nil || !m.liveWanted() || (m.logStream != nil && m.logStream.Vault != nil) {
		return
	}
	if err := e.client.PushJSON(edgeWS.TypeLogLive, edgeWS.LogLivePayload{TTLSec: liveTTL}); err != nil {
		m.log.Debug("edgews: demande Live non envoyée", "edge", e.nodeName, "err", err)
	}
}

// handleLiveRows diffuse aux vues Live les lignes qu'une passerelle envoie à la demande. Elles ne sont pas
// enregistrées : la passerelle les garde dans sa base.
func (m *Manager) handleLiveRows(e *edgeEntry, raw json.RawMessage) {
	if m.logStream == nil {
		return
	}
	var p edgeWS.LogLiveRowsPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return
	}
	for _, item := range p.Entries {
		item.NodeID = e.id
		if item.NodeName == "" {
			item.NodeName = e.nodeName
		}
		m.logStream.Store.Publish(LogEntryFromPayload(item))
	}
}

// trafficFresh : au-delà, un débit n'est plus celui de la passerelle (elle s'est tue ou déconnectée) et vaut zéro.
const trafficFresh = 20 * time.Second

type trafficSample struct {
	at                        time.Time
	requests, blocked, errors int64
}

type trafficState struct {
	mu     sync.Mutex
	byNode map[string]trafficSample
}

// handleEdgeTraffic retient le dernier débit récent annoncé par une passerelle.
func (m *Manager) handleEdgeTraffic(raw json.RawMessage) {
	var p edgeWS.EdgeTrafficPayload
	if err := json.Unmarshal(raw, &p); err != nil || p.NodeName == "" {
		return
	}
	m.traffic.mu.Lock()
	defer m.traffic.mu.Unlock()
	if m.traffic.byNode == nil {
		m.traffic.byNode = map[string]trafficSample{}
	}
	m.traffic.byNode[p.NodeName] = trafficSample{at: time.Now(), requests: p.Requests, blocked: p.Blocked, errors: p.Errors}
}

// RecentTraffic rend le débit de la dernière minute d'une passerelle d'après son dernier message ; ok est faux si elle
// n'en a pas envoyé depuis quelques secondes.
func (m *Manager) RecentTraffic(nodeName string) (requests, blocked, errors int64, ok bool) {
	m.traffic.mu.Lock()
	defer m.traffic.mu.Unlock()
	s, found := m.traffic.byNode[nodeName]
	if !found || time.Since(s.at) > trafficFresh {
		return 0, 0, 0, false
	}
	return s.requests, s.blocked, s.errors, true
}
