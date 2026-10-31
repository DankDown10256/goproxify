// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"time"

	"github.com/vincamok/goproxify/internal/admin/alerting"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

// AckDelay regroupe les acquittements d'une rafale de lots : un par passerelle toutes les quelques secondes (réglable pour les tests).
var AckDelay = 5 * time.Second

// logBufferAlertEvery : intervalle entre deux rappels pour une même passerelle.
const logBufferAlertEvery = 6 * time.Hour

// scheduleAck programme l'acquittement des lignes que l'Admin vient de ranger dans son volume de logs : la passerelle peut
// alors purger ce qui est acquitté (ADR 0018). Sans volume de logs, rien ne garantit que les lignes soient rangées : aucun
// acquittement n'est envoyé.
func (m *Manager) scheduleAck(e *edgeEntry) {
	if m.logStream == nil || m.logStream.Vault == nil {
		return
	}
	if e.ackPending.CompareAndSwap(false, true) {
		time.AfterFunc(AckDelay, func() {
			e.ackPending.Store(false)
			m.sendLogAck(e)
		})
	}
}

func (m *Manager) sendLogAck(e *edgeEntry) {
	if m.logStream == nil || e.client == nil {
		return
	}
	if err := e.client.PushJSON(edgeWS.TypeLogAck, edgeWS.LogAckPayload{Cursors: m.logStream.Cursors(e.id)}); err != nil {
		m.log.Debug("edgews: acquittement des logs non envoyé", "edge", e.nodeName, "err", err)
	}
}

// logBufferEvent rend l'alerte à émettre quand des lignes que l'Admin n'a pas rangées approchent de la borne où la
// passerelle les supprime : avertissement à 80 % de la borne, critique à 90 %. alerted retient la dernière alerte de chaque
// passerelle ; une passerelle revenue à l'heure est oubliée, la prochaine dérive alertera tout de suite.
func logBufferEvent(node string, active bool, unackedDays, maxDays int, alerted map[string]time.Time, now time.Time) *alerting.Event {
	if !active || maxDays <= 0 || unackedDays*10 < maxDays*8 {
		delete(alerted, node)
		return nil
	}
	if last, ok := alerted[node]; ok && now.Sub(last) < logBufferAlertEvery {
		return nil
	}
	alerted[node] = now
	sev := alerting.SevWarning
	if unackedDays*10 >= maxDays*9 {
		sev = alerting.SevCritical
	}
	return &alerting.Event{
		Trigger: alerting.TriggerLogBufferRisk, Severity: sev, NodeName: node, Component: "edge", FiredAt: now,
		Detail: map[string]any{"node_name": node, "unacked_days": unackedDays, "max_days": maxDays},
	}
}
