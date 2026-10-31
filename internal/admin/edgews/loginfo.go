// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/admin/api"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

// logInfoStale : une passerelle qui n'a rien annoncé depuis trois envois (30 s chacun) n'est plus garantie.
const logInfoStale = 90 * time.Second

type logInfoState struct {
	mu     sync.Mutex
	byNode map[string]api.EdgeLogInfo
	at     map[string]time.Time
	last   map[string][2]int64 // derniers identifiants annoncés (accès, système)
	alerted map[string]time.Time // dernière alerte « logs non rangés » de chaque passerelle
}

func (m *Manager) handleLogInfo(raw json.RawMessage) {
	var p edgeWS.LogInfoPayload
	if err := json.Unmarshal(raw, &p); err != nil || p.NodeName == "" {
		return
	}
	now := time.Now()
	m.logInfo.mu.Lock()
	defer m.logInfo.mu.Unlock()
	if m.logInfo.byNode == nil {
		m.logInfo.byNode, m.logInfo.at = map[string]api.EdgeLogInfo{}, map[string]time.Time{}
	}
	m.logInfo.byNode[p.NodeName] = api.EdgeLogInfo{NodeName: p.NodeName, AccessDays: p.AccessDays, SystemDays: p.SystemDays, ReportedAt: now.UTC().Format(time.RFC3339),
		BufferActive: p.BufferActive, UnackedDays: p.UnackedDays, BufferMaxDays: p.BufferMaxDays}
	m.logInfo.at[p.NodeName] = now
	m.logInfo.setLast(p.NodeName, p.AccessLast, p.SystemLast)
	if m.logInfo.alerted == nil {
		m.logInfo.alerted = map[string]time.Time{}
	}
	if ev := logBufferEvent(p.NodeName, p.BufferActive, p.UnackedDays, p.BufferMaxDays, m.logInfo.alerted, now); ev != nil && m.alertEngine != nil {
		go m.alertEngine.Emit(*ev)
	}
}

// LogInfo rend la conservation des logs que chaque passerelle a annoncé appliquer.
func (m *Manager) LogInfo() []api.EdgeLogInfo {
	m.logInfo.mu.Lock()
	defer m.logInfo.mu.Unlock()
	out := make([]api.EdgeLogInfo, 0, len(m.logInfo.byNode))
	for node, info := range m.logInfo.byNode {
		info.Stale = time.Since(m.logInfo.at[node]) > logInfoStale
		out = append(out, info)
	}
	return out
}

// pushLogRetentionTo envoie à une passerelle la conservation qui la concerne. Rien n'est envoyé tant que personne ne l'a
// réglée : la passerelle garde celle de son edge.json.
func (m *Manager) pushLogRetentionTo(e *edgeEntry) {
	r, configured := api.LoadEdgeRetention(m.db)
	if !configured || e.client == nil {
		return
	}
	access, system := r.For(e.nodeName)
	if err := e.client.PushJSON(edgeWS.TypePushLogRetention, edgeWS.LogRetentionPayload{AccessDays: access, SystemDays: system}); err != nil {
		m.log.Warn("edgews: push log retention", "edge", e.nodeName, "err", err)
	}
}

// PushLogRetention envoie à chaque passerelle la durée de conservation de ses logs ; elle la garde chiffrée et
// l'applique seule ensuite, Admin éteint.
func (m *Manager) PushLogRetention(ctx context.Context) {
	for _, e := range m.allEntries() {
		e := e
		go m.pushLogRetentionTo(e)
	}
}
