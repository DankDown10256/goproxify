// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"time"

	"github.com/vincamok/goproxify/internal/admin/logs"
	"github.com/vincamok/goproxify/internal/edge/logstore"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

// Réception des lignes avec le volume de logs (ADR 0018). Deux consommateurs lisent le même flux :
//   - le store de la passerelle dans le volume de logs, qui reçoit toutes les lignes et dont la position fait foi ;
//   - la table logs de l'Admin, qui garde ce que ses lecteurs actuels lui demandent encore (les événements de sécurité
//     et les logs système) jusqu'à ce qu'ils lisent le volume de logs.
//
// Chacun a sa position. La passerelle reprend à la plus basse, et chaque consommateur écarte ce qu'il a déjà.

// liveWindow : une ligne plus ancienne que cela, un rejeu par exemple, ne passe pas dans la vue Live.
const liveWindow = 2 * time.Minute

func shipKind(stream string) logstore.Kind {
	if stream == edgeWS.LogStreamSystem {
		return logstore.KindSystem
	}
	return logstore.KindAccess
}

// shipCursor rend la position à annoncer à la passerelle : la plus basse des deux consommateurs. Sans volume de logs, c'est
// celle de la table logs.
func (g *LogStreamIngestor) shipCursor(nodeID, stream string, tableSeq int64) int64 {
	if g.Vault == nil || (stream != edgeWS.LogStreamAccess && stream != edgeWS.LogStreamSystem) {
		return tableSeq
	}
	st, err := g.Vault.Store(nodeID, "")
	if err != nil {
		g.Log.Warn("edgews: ouverture du store de logs d'une passerelle", "edge", nodeID, "err", err)
		return 0
	}
	vaultSeq, err := st.ShipCursor(shipKind(stream))
	if err != nil {
		g.Log.Warn("edgews: lecture de la position du store de logs", "edge", nodeID, "stream", stream, "err", err)
		return 0
	}
	return min(tableSeq, vaultSeq)
}

// isSecurityEvent : un accès que le WAF ou Ephor ont signalé, ou tout log système.
func isSecurityEvent(item edgeWS.LogEntryPayload, stream string) bool {
	return stream == edgeWS.LogStreamSystem || len(item.WAFMatches) > 0 || item.ThreatSignal != ""
}

func storeEntryFromPayload(item edgeWS.LogEntryPayload) logstore.Entry {
	ts, _ := time.Parse(time.RFC3339Nano, item.Ts)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, item.Ts)
	}
	component := item.Component
	if component == "" {
		component = "edge"
	}
	return logstore.Entry{
		Ts: ts, Level: item.Level, Component: component, Domain: item.Domain, Method: item.Method, Path: item.Path,
		Status: item.Status, Bytes: item.Bytes, LatencyMs: item.LatencyMs, IP: item.IP, RealIP: item.RealIP,
		IPTruncated: item.IPTruncated, UserAgent: item.UserAgent, Referrer: item.Referrer, RequestID: item.RequestID,
		WAFMatches: item.WAFMatches, ThreatSignal: item.ThreatSignal, TLSJA3: item.TLSJA3, TLSJA4: item.TLSJA4, Message: item.Message,
	}
}

// handleVault range un lot dans le store de la passerelle puis, pour les lecteurs qui ne lisent pas encore le volume de
// logs, dans la table logs. Il rend true quand la passerelle doit reprendre depuis la position de l'Admin.
func (g *LogStreamIngestor) handleVault(nodeID, nodeName string, p edgeWS.LogStreamPayload) (resume bool) {
	st, err := g.Vault.Store(nodeID, nodeName)
	if err != nil {
		g.Log.Warn("edgews: ouverture du store de logs d'une passerelle", "edge", nodeName, "err", err)
		return true
	}
	kind := shipKind(p.Stream)
	vaultSeq, err := st.ShipCursor(kind)
	if err != nil {
		g.Log.Warn("edgews: lecture de la position du store de logs", "edge", nodeName, "stream", p.Stream, "err", err)
		return true
	}
	tableSeq, err := g.Store.StreamCursor(nodeID, p.Stream)
	if err != nil {
		g.Log.Warn("edgews: lecture de la position d'un flux de logs", "edge", nodeID, "stream", p.Stream, "err", err)
		return true
	}
	if p.Reset {
		// Seulement si la passerelle parle bien de la position que l'Admin a : un message retardé ne doit pas la ramener.
		if p.After == vaultSeq && vaultSeq > 0 {
			g.Log.Warn("edgews: la base de logs de la passerelle a été remplacée, le flux repart du début", "edge", nodeName, "stream", p.Stream, "position", vaultSeq)
			if err := st.ResetShipCursor(kind); err != nil {
				g.Log.Warn("edgews: remise à zéro d'une position de flux", "edge", nodeName, "stream", p.Stream, "err", err)
				return true
			}
		}
		if p.After == tableSeq && tableSeq > 0 {
			if err := g.Store.ResetStreamCursor(nodeID, p.Stream); err != nil {
				g.Log.Warn("edgews: remise à zéro d'une position de flux", "edge", nodeName, "stream", p.Stream, "err", err)
				return true
			}
		}
		return false
	}
	if p.After > min(vaultSeq, tableSeq) {
		g.Log.Warn("edgews: lot de logs hors séquence, reprise demandée", "edge", nodeName, "stream", p.Stream, "position", min(vaultSeq, tableSeq), "lot_apres", p.After)
		return true
	}

	var last int64
	shipped := make([]logstore.ShippedRow, 0, len(p.Entries))
	var live []logs.Entry
	for _, item := range p.Entries {
		last = max(last, item.Seq)
		if item.Seq <= vaultSeq {
			continue
		}
		entry := storeEntryFromPayload(item)
		shipped = append(shipped, logstore.ShippedRow{Seq: item.Seq, Entry: entry})
		// Les événements de sécurité sont diffusés à la vue Live par la table logs ; les autres le sont ici, pour les lignes
		// récentes seulement (le rejeu d'un historique ne doit pas inonder une vue ouverte).
		if time.Since(entry.Ts) < liveWindow && !isSecurityEvent(item, p.Stream) {
			item.NodeID = nodeID
			if item.NodeName == "" {
				item.NodeName = nodeName
			}
			live = append(live, LogEntryFromPayload(item))
		}
	}
	// Through : une passerelle d'avant l'ADR 0018 a écarté des lignes jusque-là (accès non signalés) ; la position les saute.
	last = max(last, p.Through)
	if last > vaultSeq {
		if _, err := st.AddShipped(kind, shipped, last); err != nil {
			g.Log.Warn("edgews: écriture d'un lot de logs échouée, reprise demandée", "edge", nodeName, "stream", p.Stream, "err", err)
			return true
		}
		for _, e := range live {
			g.Store.Publish(e)
		}
	}

	if last <= tableSeq {
		return false
	}
	fresh := make([]logs.Entry, 0)
	for _, item := range p.Entries {
		if item.Seq <= tableSeq || !isSecurityEvent(item, p.Stream) {
			continue
		}
		item.NodeID = nodeID
		if item.NodeName == "" {
			item.NodeName = nodeName
		}
		fresh = append(fresh, LogEntryFromPayload(item))
	}
	if err := g.Store.WriteStream(nodeID, p.Stream, fresh, last); err != nil {
		g.Log.Warn("edgews: écriture d'un lot de logs échouée, reprise demandée", "edge", nodeName, "stream", p.Stream, "err", err)
		return true
	}
	return false
}
