// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/seasonal"
)

// State est l'état appris d'Ephor qui survit à un redémarrage : scores cumulés et fenêtres d'erreurs 4xx et de
// déclenchements « rate ». Les jetons du limiteur de débit ne sont pas conservés : ils se remplissent en quelques secondes.
// Tout est daté, donc une copie ancienne se périme d'elle-même à la relecture (ADR 0011, étape 1).
type State struct {
	SavedAt      time.Time              `json:"saved_at"`
	Scores       map[string]ScoreState  `json:"scores,omitempty"`
	Errors       map[string]WindowState `json:"errors,omitempty"`
	RateTriggers map[string]WindowState `json:"rate_triggers,omitempty"`
	// Thresholds : les compteurs des Seuils (ADR 0020, étape 2.c), par clé « Seuil|IP ».
	Thresholds map[string]ThresholdState `json:"thresholds,omitempty"`
	// Seasonal : la référence saisonnière apprise de chaque route (ADR 0020, étape 3).
	Seasonal map[string]seasonal.RefState `json:"seasonal,omitempty"`
	// Enumeration : la norme de valeurs distinctes par gabarit (ADR 0020, étape 4.b), sans IP ni valeur.
	Enumeration map[string]EnumNormState `json:"enumeration,omitempty"`
	// TLSReputation : les compteurs par empreinte TLS (ADR 0020, étape 4.c), sans IP.
	TLSReputation map[string]TLSRepState `json:"tls_reputation,omitempty"`
}

// ScoreState : score à l'instant At, qui décroît de moitié toutes les HalfLife.
type ScoreState struct {
	Score    float64       `json:"score"`
	At       time.Time     `json:"at"`
	HalfLife time.Duration `json:"half_life"`
	// Parts : le score par signal, pour expliquer le ban qu'il finira par poser.
	Parts []router.BanSignal `json:"parts,omitempty"`
}

// WindowState : événements encore datés d'une fenêtre glissante.
type WindowState struct {
	Window time.Duration `json:"window"`
	Events []time.Time   `json:"events"`
}

// SnapshotState copie l'état à persister. Les entrées déjà périmées sont écartées.
func (e *Engine) SnapshotState() State {
	st := e.counters.snapshot()
	st.Thresholds = e.thresholdCounters.snapshot()
	st.Seasonal = e.seasonal.Export()
	st.Enumeration = e.enum.snapshot()
	st.TLSReputation = e.tlsrep.snapshot()
	return st
}

// RestoreState réinjecte un état relu du disque, sans dépasser les plafonds par shard. Les entrées périmées à l'instant
// de la relecture sont ignorées ; l'état courant d'une IP déjà vue depuis le démarrage n'est jamais écrasé.
func (e *Engine) RestoreState(st State) {
	e.counters.restore(st)
	e.thresholdCounters.restore(st.Thresholds)
	e.seasonal.Import(st.Seasonal)
	e.enum.restore(st.Enumeration)
	e.tlsrep.restore(st.TLSReputation)
}

func (s *counterStore) snapshot() State {
	now := s.now()
	st := State{
		SavedAt:      now,
		Scores:       map[string]ScoreState{},
		Errors:       map[string]WindowState{},
		RateTriggers: map[string]WindowState{},
	}
	for i := range s.shards {
		sh := &s.shards[i]
		sh.mu.Lock()
		for k, se := range sh.score {
			if se.value(now) >= scoreForgetBelow {
				ss := ScoreState{Score: se.score, At: se.at, HalfLife: se.halfLife}
				for name, p := range se.parts {
					ss.Parts = append(ss.Parts, router.BanSignal{Name: name, Points: p.points, Value: p.value})
				}
				st.Scores[k] = ss
			}
		}
		for k, ew := range sh.errors {
			if ws, ok := ew.state(now); ok {
				st.Errors[k] = ws
			}
		}
		for k, ew := range sh.rateTrigger {
			if ws, ok := ew.state(now); ok {
				st.RateTriggers[k] = ws
			}
		}
		sh.mu.Unlock()
	}
	return st
}

func (s *counterStore) restore(st State) {
	now := s.now()
	for k, ss := range st.Scores {
		se := &scoreEntry{score: ss.Score, at: ss.At, halfLife: ss.HalfLife}
		if len(ss.Parts) > 0 {
			se.parts = make(map[string]*scorePart, len(ss.Parts))
			for _, p := range ss.Parts {
				if len(se.parts) < maxScoreParts {
					se.parts[p.Name] = &scorePart{points: p.Points, value: clipValue(p.Value)}
				}
			}
		}
		if se.value(now) < scoreForgetBelow {
			continue
		}
		sh := s.shard(k)
		sh.mu.Lock()
		if _, exists := sh.score[k]; !exists && len(sh.score) < maxKeysPerShard {
			sh.score[k] = se
		}
		sh.mu.Unlock()
	}
	restoreWindows(s, st.Errors, now, func(sh *counterShard) map[string]*eventWindow { return sh.errors })
	restoreWindows(s, st.RateTriggers, now, func(sh *counterShard) map[string]*eventWindow { return sh.rateTrigger })
}

func restoreWindows(s *counterStore, in map[string]WindowState, now time.Time, pick func(*counterShard) map[string]*eventWindow) {
	for k, ws := range in {
		ew := newWindowFromState(ws, now)
		if ew == nil {
			continue
		}
		sh := s.shard(k)
		sh.mu.Lock()
		m := pick(sh)
		if _, exists := m[k]; !exists && len(m) < maxKeysPerShard {
			m[k] = ew
		}
		sh.mu.Unlock()
	}
}

// state copie les événements encore dans la fenêtre ; faux si la clé est inactive depuis plus que le TTL de purge.
func (w *eventWindow) state(now time.Time) (WindowState, bool) {
	if now.Sub(w.lastSeen) > counterIdleTTL || w.count(now) == 0 {
		return WindowState{}, false
	}
	return WindowState{Window: w.window, Events: append([]time.Time(nil), w.events...)}, true
}

// newWindowFromState reconstruit une fenêtre en ne gardant que les événements encore valides et en reprenant le plafond
// par clé ; nil s'il n'en reste aucun.
func newWindowFromState(ws WindowState, now time.Time) *eventWindow {
	if ws.Window <= 0 {
		return nil
	}
	cutoff := now.Add(-ws.Window)
	var kept []time.Time
	for _, t := range ws.Events {
		if !t.Before(cutoff) && !t.After(now) {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	if len(kept) > maxEventsPerKey {
		kept = kept[len(kept)-maxEventsPerKey:]
	}
	return &eventWindow{events: kept, window: ws.Window, lastSeen: kept[len(kept)-1]}
}
