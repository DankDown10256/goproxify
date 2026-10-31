// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/logstore"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

const (
	// logStreamBatch borne les lignes d'un message : de l'ordre de 300 Ko, loin de la limite de lecture du WebSocket.
	logStreamBatch = 500
	// logStreamIdle : attente maximale sans nouvelle ligne avant de vérifier que l'Admin est toujours connecté.
	logStreamIdle = 15 * time.Second
)

// logStreamKinds lie chaque flux de l'Admin au type de la base de logs, dans l'ordre d'envoi.
var logStreamKinds = []struct {
	name string
	kind logstore.Kind
}{
	{edgews.LogStreamAccess, logstore.KindAccess},
	{edgews.LogStreamSystem, logstore.KindSystem},
}

// logStreams suit l'envoi en cours vers chaque connexion Admin.
type logStreams struct {
	mu      sync.Mutex
	cancels map[string]context.CancelFunc
}

// start remplace l'envoi en cours vers connID : une Admin qui se reconnecte repart de sa position.
func (l *logStreams) start(connID string, run func(ctx context.Context)) {
	ctx, cancel := context.WithCancel(context.Background())
	l.mu.Lock()
	if l.cancels == nil {
		l.cancels = map[string]context.CancelFunc{}
	}
	if prev, ok := l.cancels[connID]; ok {
		prev()
	}
	l.cancels[connID] = cancel
	l.mu.Unlock()
	go func() {
		run(ctx)
		l.mu.Lock()
		// Ne pas retirer l'envoi qui a pris la place de celui-ci.
		if ctx.Err() == nil {
			delete(l.cancels, connID)
		}
		l.mu.Unlock()
		cancel()
	}()
}

func (l *logStreams) stopAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for id, cancel := range l.cancels {
		cancel()
		delete(l.cancels, id)
	}
}

// handleLogResume démarre l'envoi des logs vers l'Admin connID à partir des positions qu'il annonce. C'est
// l'Admin qui sait ce qu'il a enregistré : la passerelle ne retient rien à sa place, et une coupure de l'Admin ne
// lui fait rien perdre tant que sa base de logs garde les lignes.
func (s *Server) handleLogResume(connID string, raw json.RawMessage) error {
	if s.logStore == nil {
		return nil
	}
	var p edgews.LogResumePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	// Les positions annoncées à la connexion sont celles de l'Admin, ni plus ni moins : si son volume de logs a été
	// remplacé, elles reculent, et les lignes qu'il n'a plus ne sont plus protégées par un ancien acquittement.
	if p.Stored {
		for stream, pos := range p.Cursors {
			s.logStore.SetAck(stream, pos)
		}
	}
	s.logStreams.start(connID, func(ctx context.Context) { s.streamLogs(ctx, connID, p.Cursors) })
	return nil
}

// streamLogs envoie à l'Admin connID les lignes de la base au-delà de ses positions, puis suit les nouvelles. Il
// s'arrête quand l'Admin n'est plus connecté ou quand ctx est annulé.
func (s *Server) streamLogs(ctx context.Context, connID string, cursors map[string]int64) {
	pos := map[string]int64{}
	for _, k := range logStreamKinds {
		pos[k.name] = cursors[k.name]
	}
	minutePos := cursors[edgews.LogStreamMinute]
	ipPos := cursors[edgews.LogStreamIPErrors]
	for {
		// Demandé avant de lire : une écriture pendant la lecture ferme ce canal, et la boucle relit.
		changed := s.logStore.Changed()
		sent := false
		for _, k := range logStreamKinds {
			for {
				// Toutes les lignes partent vers l'Admin, qui les range (ADR 0018) : la base de la passerelle n'est qu'un tampon
				// qui couvre ses coupures.
				rows, err := s.logStore.ReadAfterRevealed(k.kind, pos[k.name], logStreamBatch)
				if err != nil {
					s.log.Warn("logs: lecture de la base pour l'Admin échouée", "stream", k.name, "err", err)
					break
				}
				if len(rows) == 0 {
					// L'Admin est plus avancé que la base : elle a été remplacée. Sans cela les lignes de la nouvelle base,
					// numérotées depuis 1, seraient prises pour des lignes déjà reçues et sautées jusqu'à rattraper la position.
					if pos[k.name] > s.logStore.LastID(k.kind) {
						s.log.Warn("logs: la base est plus récente que ne le croit l'Admin, il repart du début", "stream", k.name, "position", pos[k.name])
						msg, err := edgews.NewMessage(0, edgews.TypeLogStream, edgews.LogStreamPayload{Stream: k.name, After: pos[k.name], Reset: true})
						if err != nil {
							return
						}
						if err := s.wsHub.SendToAdmin(connID, msg); err != nil {
							return
						}
						pos[k.name] = 0
						continue
					}
					break
				}
				entries := make([]edgews.LogEntryPayload, len(rows))
				for i, r := range rows {
					entries[i] = shipPayload(edgelog.ShipEntryFromRow(r, k.kind, s.cfg.Identity.NodeName))
				}
				msg, err := edgews.NewMessage(0, edgews.TypeLogStream, edgews.LogStreamPayload{Stream: k.name, After: pos[k.name], Entries: entries})
				if err != nil {
					return
				}
				if err := s.wsHub.SendToAdmin(connID, msg); err != nil {
					return
				}
				pos[k.name] = rows[len(rows)-1].ID
				sent = true
				if ctx.Err() != nil {
					return
				}
			}
		}
		for {
			rows, err := s.logStore.ReadMinutesAfter(minutePos, logStreamBatch)
			if err != nil {
				s.log.Warn("logs: lecture des cumuls pour l'Admin échouée", "err", err)
				break
			}
			if len(rows) == 0 {
				break
			}
			payload := make([]edgews.MinuteRowPayload, len(rows))
			for i, r := range rows {
				payload[i] = edgews.MinuteRowPayload{
					Minute: r.Minute, NodeName: s.cfg.Identity.NodeName, Domain: r.Domain, Status: r.Status,
					Requests: r.Requests, Bytes: r.Bytes, LatencyMsSum: r.LatencyMsSum, Bots: r.Bots, Seq: r.Seq,
				}
			}
			msg, err := edgews.NewMessage(0, edgews.TypeAggStream, edgews.MinuteStreamPayload{After: minutePos, Rows: payload})
			if err != nil {
				return
			}
			if err := s.wsHub.SendToAdmin(connID, msg); err != nil {
				return
			}
			minutePos = rows[len(rows)-1].Seq
			sent = true
			if ctx.Err() != nil {
				return
			}
		}
		for {
			rows, err := s.logStore.ReadIPErrorsAfter(ipPos, logStreamBatch)
			if err != nil {
				s.log.Warn("logs: lecture des compteurs d'erreurs pour l'Admin échouée", "err", err)
				break
			}
			if len(rows) == 0 {
				break
			}
			payload := make([]edgews.IPErrorRowPayload, len(rows))
			for i, r := range rows {
				payload[i] = edgews.IPErrorRowPayload{Minute: r.Minute, IP: r.IP, Errors: r.Errors, Seq: r.Seq}
			}
			msg, err := edgews.NewMessage(0, edgews.TypeIPStream, edgews.IPStreamPayload{After: ipPos, Rows: payload})
			if err != nil {
				return
			}
			if err := s.wsHub.SendToAdmin(connID, msg); err != nil {
				return
			}
			ipPos = rows[len(rows)-1].Seq
			sent = true
			if ctx.Err() != nil {
				return
			}
		}
		if sent {
			continue
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
		case <-time.After(logStreamIdle):
			if !s.wsHub.HasAdmin(connID) {
				return
			}
		}
	}
}

// shipPayload convertit une entrée expédiée au format du WebSocket Admin.
func shipPayload(e edgelog.ShipEntry) edgews.LogEntryPayload {
	return edgews.LogEntryPayload{
		Ts: e.Ts, Level: e.Level, Component: e.Component, NodeName: e.NodeName, Domain: e.Domain, Method: e.Method,
		Path: e.Path, Status: e.Status, IP: e.IP, RealIP: e.RealIP, IPTruncated: e.IPTruncated, LatencyMs: e.LatencyMs,
		Bytes: e.Bytes, Message: e.Message, Referrer: e.Referrer, UserAgent: e.UserAgent, RequestID: e.RequestID, WAFMatches: e.WAFMatches,
		ThreatSignal: e.ThreatSignal, TLSJA3: e.TLSJA3, TLSJA4: e.TLSJA4, Seq: e.Seq,
	}
}

// handleLogAck fait avancer les positions que l'Admin a rangées dans son volume de logs (ADR 0018) : la base de la passerelle
// peut alors purger ce qui est acquitté une fois sa période finie depuis assez longtemps.
func (s *Server) handleLogAck(raw json.RawMessage) error {
	if s.logStore == nil {
		return nil
	}
	var p edgews.LogAckPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return err
	}
	for stream, pos := range p.Cursors {
		s.logStore.AdvanceAck(stream, pos)
	}
	return nil
}
