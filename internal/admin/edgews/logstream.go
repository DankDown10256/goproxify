// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"encoding/json"
	"log/slog"
	"time"

	"github.com/vincamok/goproxify/internal/admin/edgelogs"
	"github.com/vincamok/goproxify/internal/admin/logs"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

// logResumeDelay laisse respirer une passerelle dont un lot vient d'être refusé : sans lui, une base Admin en
// erreur déclencherait un renvoi immédiat, refusé à son tour, en boucle.
const logResumeDelay = 2 * time.Second

var logStreams = []string{edgeWS.LogStreamAccess, edgeWS.LogStreamSystem, edgeWS.LogStreamMinute, edgeWS.LogStreamIPErrors}

// LogEntryFromPayload convertit une ligne reçue d'une passerelle en entrée de la base de logs de l'Admin.
func LogEntryFromPayload(item edgeWS.LogEntryPayload) logs.Entry {
	ts, _ := time.Parse(time.RFC3339Nano, item.Ts)
	if ts.IsZero() {
		ts, _ = time.Parse(time.RFC3339, item.Ts)
	}
	if ts.IsZero() {
		ts = time.Now()
	}
	component := item.Component
	if component == "" {
		component = "edge"
	}
	return logs.Entry{
		Ts: ts, Level: item.Level, Component: component, NodeName: item.NodeName, NodeID: item.NodeID,
		Domain: item.Domain, Method: item.Method, Path: item.Path, Status: item.Status, IP: item.IP, RealIP: item.RealIP,
		IPTruncated: item.IPTruncated, LatencyMs: item.LatencyMs, Bytes: item.Bytes, Message: item.Message,
		Referrer: item.Referrer, RequestID: item.RequestID, WAFMatches: item.WAFMatches, ThreatSignal: item.ThreatSignal,
		TLSJA3: item.TLSJA3, TLSJA4: item.TLSJA4,
	}
}

// LogStreamIngestor enregistre les lots numérotés que les passerelles envoient depuis leur base de logs, et
// retient pour chacune la position atteinte : c'est elle qui dit à la passerelle d'où reprendre après une coupure.
type LogStreamIngestor struct {
	Store *logs.Store
	Log   *slog.Logger
	// Vault est le volume de logs de l'Admin (ADR 0018) : toutes les lignes y sont rangées, une par passerelle, et sa
	// position fait foi. Sans lui, les lignes vont dans la table logs de l'Admin, comme avant.
	Vault *edgelogs.Vault
	// SecurityOnly : sans volume de logs, la table logs ne reçoit que les événements de sécurité et les logs système ; la position
	// avance sur les autres. Évite qu'un volume indisponible ne remplisse la base de l'Admin de tous les accès.
	SecurityOnly bool
}

// Cursors retourne les positions enregistrées pour la passerelle nodeID, à envoyer dans un TypeLogResume.
func (g *LogStreamIngestor) Cursors(nodeID string) map[string]int64 {
	out := make(map[string]int64, len(logStreams))
	for _, stream := range logStreams {
		seq, err := g.Store.StreamCursor(nodeID, stream)
		if err != nil {
			g.Log.Warn("edgews: lecture de la position d'un flux de logs", "edge", nodeID, "stream", stream, "err", err)
		}
		out[stream] = g.shipCursor(nodeID, stream, seq)
	}
	return out
}

// Handle enregistre un lot. Il retourne true quand la passerelle doit reprendre depuis la position de l'Admin :
// le lot saute des lignes (il commence après la position enregistrée) ou n'a pas pu être écrit. Un lot déjà
// reçu, en tout ou en partie, est dédoublonné par le numéro de ligne.
func (g *LogStreamIngestor) Handle(nodeID, nodeName string, p edgeWS.LogStreamPayload) (resume bool) {
	if p.Stream != edgeWS.LogStreamAccess && p.Stream != edgeWS.LogStreamSystem {
		return false
	}
	if g.Vault != nil {
		return g.handleVault(nodeID, nodeName, p)
	}
	cursor, err := g.Store.StreamCursor(nodeID, p.Stream)
	if err != nil {
		g.Log.Warn("edgews: lecture de la position d'un flux de logs", "edge", nodeID, "stream", p.Stream, "err", err)
		return true
	}
	if p.Reset {
		// Seulement si la passerelle parle bien de la position que l'Admin a : un message retardé ne doit pas la ramener.
		if p.After == cursor && cursor > 0 {
			g.Log.Warn("edgews: la base de logs de la passerelle a été remplacée, le flux repart du début", "edge", nodeName, "stream", p.Stream, "position", cursor)
			if err := g.Store.ResetStreamCursor(nodeID, p.Stream); err != nil {
				g.Log.Warn("edgews: remise à zéro d'une position de flux", "edge", nodeName, "stream", p.Stream, "err", err)
				return true
			}
		}
		return false
	}
	if p.After > cursor {
		g.Log.Warn("edgews: lot de logs hors séquence, reprise demandée", "edge", nodeName, "stream", p.Stream, "position", cursor, "lot_apres", p.After)
		return true
	}
	fresh := make([]logs.Entry, 0, len(p.Entries))
	var last int64
	for _, item := range p.Entries {
		if item.Seq <= cursor {
			continue
		}
		if g.SecurityOnly && !isSecurityEvent(item, p.Stream) {
			last = max(last, item.Seq)
			continue
		}
		item.NodeID = nodeID
		if item.NodeName == "" {
			item.NodeName = nodeName
		}
		fresh = append(fresh, LogEntryFromPayload(item))
		last = max(last, item.Seq)
	}
	// Through : la passerelle a écarté des lignes jusque-là (accès non signalés) ; le curseur les saute.
	last = max(last, p.Through)
	if len(fresh) == 0 && last <= cursor {
		return false
	}
	if err := g.Store.WriteStream(nodeID, p.Stream, fresh, last); err != nil {
		g.Log.Warn("edgews: écriture d'un lot de logs échouée, reprise demandée", "edge", nodeName, "stream", p.Stream, "err", err)
		return true
	}
	return false
}

// SetLogStreamIngestor active la réception des flux de logs numérotés : à chaque connexion d'une passerelle,
// l'Admin lui annonce ses positions.
func (m *Manager) SetLogStreamIngestor(g *LogStreamIngestor) { m.logStream = g }

// sendLogResume annonce à la passerelle les positions déjà enregistrées pour qu'elle envoie la suite.
func (m *Manager) sendLogResume(e *edgeEntry) {
	if m.logStream == nil || e.client == nil {
		return
	}
	if err := e.client.PushJSON(edgeWS.TypeLogResume, edgeWS.LogResumePayload{Cursors: m.logStream.Cursors(e.id), Stored: m.logStream.Vault != nil}); err != nil {
		m.log.Warn("edgews: envoi de la reprise des logs", "edge", e.nodeName, "err", err)
	}
}

// scheduleResume redemande l'envoi à la passerelle après un court délai, une seule fois à la fois.
func (m *Manager) scheduleResume(e *edgeEntry) {
	if e.resumePending.CompareAndSwap(false, true) {
		time.AfterFunc(logResumeDelay, func() {
			e.resumePending.Store(false)
			m.sendLogResume(e)
		})
	}
}

func (m *Manager) handleAggStream(e *edgeEntry, raw json.RawMessage) {
	if m.logStream == nil {
		return
	}
	var p edgeWS.MinuteStreamPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		m.log.Debug("edgews: lot de cumuls non reconnu", "err", err)
		return
	}
	if m.logStream.HandleMinutes(e.id, e.nodeName, p) {
		m.scheduleResume(e)
	} else {
		m.scheduleAck(e)
	}
}

func (m *Manager) handleLogStream(e *edgeEntry, raw json.RawMessage) {
	if m.logStream == nil {
		return
	}
	var p edgeWS.LogStreamPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		m.log.Debug("edgews: lot de logs non reconnu", "err", err)
		return
	}
	if !m.logStream.Handle(e.id, e.nodeName, p) {
		m.scheduleAck(e)
		return
	}
	// Un seul renvoi en attente : la passerelle a déjà d'autres lots en route, refusés de la même façon.
	m.scheduleResume(e)
}

// HandleMinutes enregistre un lot de cumuls par minute. Même règle de position que Handle : un lot qui commence
// après la position enregistrée saute des mises à jour, la passerelle doit reprendre. Les cumuls déjà reçus sont
// écartés par leur numéro ; ceux qui restent remplacent la valeur de leur minute.
func (g *LogStreamIngestor) HandleMinutes(nodeID, nodeName string, p edgeWS.MinuteStreamPayload) (resume bool) {
	cursor, err := g.Store.StreamCursor(nodeID, edgeWS.LogStreamMinute)
	if err != nil {
		g.Log.Warn("edgews: lecture de la position des cumuls", "edge", nodeID, "err", err)
		return true
	}
	if p.After > cursor {
		g.Log.Warn("edgews: lot de cumuls hors séquence, reprise demandée", "edge", nodeName, "position", cursor, "lot_apres", p.After)
		return true
	}
	fresh := make([]logs.MinuteRow, 0, len(p.Rows))
	var last int64
	for _, r := range p.Rows {
		if r.Seq <= cursor {
			continue
		}
		name := r.NodeName
		if name == "" {
			name = nodeName
		}
		fresh = append(fresh, logs.MinuteRow{
			Minute: r.Minute, NodeName: name, Domain: r.Domain, Status: r.Status, Requests: r.Requests,
			Bytes: r.Bytes, LatencyMsSum: r.LatencyMsSum, Bots: r.Bots,
		})
		last = max(last, r.Seq)
	}
	if len(fresh) == 0 {
		return false
	}
	if err := g.Store.WriteMinutes(nodeID, fresh, last); err != nil {
		g.Log.Warn("edgews: écriture d'un lot de cumuls échouée, reprise demandée", "edge", nodeName, "err", err)
		return true
	}
	return false
}

// HandleIPErrors enregistre un lot de compteurs d'erreurs par IP : mêmes règles de position que HandleMinutes.
func (g *LogStreamIngestor) HandleIPErrors(nodeID, nodeName string, p edgeWS.IPStreamPayload) (resume bool) {
	cursor, err := g.Store.StreamCursor(nodeID, edgeWS.LogStreamIPErrors)
	if err != nil {
		g.Log.Warn("edgews: lecture de la position des compteurs d'erreurs", "edge", nodeID, "err", err)
		return true
	}
	if p.After > cursor {
		g.Log.Warn("edgews: lot de compteurs hors séquence, reprise demandée", "edge", nodeName, "position", cursor, "lot_apres", p.After)
		return true
	}
	fresh := make([]logs.IPErrorRow, 0, len(p.Rows))
	var last int64
	for _, r := range p.Rows {
		if r.Seq <= cursor {
			continue
		}
		fresh = append(fresh, logs.IPErrorRow{Minute: r.Minute, IP: r.IP, Errors: r.Errors})
		last = max(last, r.Seq)
	}
	if len(fresh) == 0 {
		return false
	}
	if err := g.Store.WriteIPErrors(nodeID, fresh, last); err != nil {
		g.Log.Warn("edgews: écriture d'un lot de compteurs échouée, reprise demandée", "edge", nodeName, "err", err)
		return true
	}
	return false
}

func (m *Manager) handleIPStream(e *edgeEntry, raw json.RawMessage) {
	if m.logStream == nil {
		return
	}
	var p edgeWS.IPStreamPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		m.log.Debug("edgews: lot de compteurs non reconnu", "err", err)
		return
	}
	if m.logStream.HandleIPErrors(e.id, e.nodeName, p) {
		m.scheduleResume(e)
	} else {
		m.scheduleAck(e)
	}
}

