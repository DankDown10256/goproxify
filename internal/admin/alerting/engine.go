// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package alerting

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/admin/alerting/channels"
)

// Engine évalue les événements entrants, fait correspondre les règles et achemine
// les notifications vers les canaux configurés.
type Engine struct {
	db     *sql.DB
	log    *slog.Logger
	events chan Event
	stop   chan struct{}

	mu          sync.Mutex
	cooldowns   map[string]time.Time // clé : ruleID + trigger
	ruleCache   []Rule
	rulesCached time.Time
}

// New crée un Engine et démarre la goroutine de traitement.
func New(db *sql.DB, log *slog.Logger) *Engine {
	e := &Engine{
		db:        db,
		log:       log,
		events:    make(chan Event, 256),
		stop:      make(chan struct{}),
		cooldowns: map[string]time.Time{},
	}
	go e.loop()
	return e
}

// Emit envoie un événement dans la file de traitement (non-bloquant).
func (e *Engine) Emit(ev Event) {
	if ev.FiredAt.IsZero() {
		ev.FiredAt = time.Now()
	}
	select {
	case e.events <- ev:
	default:
		e.log.Warn("alerting: file d'événements pleine, événement ignoré", "trigger", ev.Trigger)
	}
}

// Stop arrête l'Engine proprement.
func (e *Engine) Stop() {
	close(e.stop)
}

func (e *Engine) loop() {
	for {
		select {
		case ev := <-e.events:
			e.eval(ev)
		case <-e.stop:
			return
		}
	}
}

func (e *Engine) eval(ev Event) {
	rules, err := e.loadRules()
	if err != nil {
		e.log.Error("alerting: chargement règles", "err", err)
		return
	}
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		if !matchesTrigger(rule, ev) || !matchesScope(rule.Scope, ev) {
			continue
		}
		key := rule.ID + ":" + string(ev.Trigger)
		e.mu.Lock()
		last := e.cooldowns[key]
		cooldown := time.Duration(rule.CooldownSec) * time.Second
		if cooldown == 0 {
			cooldown = 5 * time.Minute
		}
		if time.Since(last) < cooldown {
			e.mu.Unlock()
			continue
		}
		e.cooldowns[key] = time.Now()
		e.mu.Unlock()

		msg := buildMessage(rule, ev)
		e.dispatch(rule, msg)
		e.recordFired(rule, ev, msg)
	}
}

func (e *Engine) dispatch(rule Rule, msg Message) {
	chans, err := e.loadChannels(rule.Channels)
	if err != nil {
		e.log.Error("alerting: chargement canaux", "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmsg := channels.Message{
		RuleName: msg.RuleName,
		Trigger:  string(msg.Trigger),
		Severity: string(msg.Severity),
		Title:    msg.Title,
		Body:     msg.Body,
		Detail:   msg.Detail,
		FiredAt:  msg.FiredAt,
	}
	for _, ch := range chans {
		if !ch.Enabled {
			continue
		}
		cch := channels.Channel{ID: ch.ID, Name: ch.Name, Type: ch.Type, Config: ch.Config, Enabled: ch.Enabled}
		sender, err := channels.Build(cch)
		if err != nil {
			e.log.Warn("alerting: canal invalide", "channel", ch.Name, "err", err)
			continue
		}
		if err := sender.Send(ctx, cmsg); err != nil {
			e.log.Warn("alerting: envoi échoué", "channel", ch.Name, "err", err)
		} else {
			e.log.Info("alerting: notification envoyée", "channel", ch.Name, "rule", rule.Name)
		}
	}
}

func (e *Engine) recordFired(rule Rule, ev Event, msg Message) {
	detail, _ := json.Marshal(ev.Detail)
	chansJSON, _ := json.Marshal(rule.Channels)
	_, _ = e.db.Exec(
		`INSERT INTO alert_events (rule_id, trigger, detail, channels) VALUES (?, ?, ?, ?)`,
		rule.ID, string(ev.Trigger), string(detail), string(chansJSON),
	)
	// Purge des événements > 30 jours
	_, _ = e.db.Exec(`DELETE FROM alert_events WHERE fired_at < datetime('now', '-30 days')`)
	_ = msg
}

// loadRules charge et cache les règles actives (TTL 30 s).
func (e *Engine) loadRules() ([]Rule, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if time.Since(e.rulesCached) < 30*time.Second {
		return e.ruleCache, nil
	}
	rows, err := e.db.Query(
		`SELECT id, name, scope, triggers, channels, cooldown_sec, priority, enabled
		 FROM alert_rules ORDER BY priority DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []Rule
	for rows.Next() {
		var r Rule
		var scopeJSON, triggersJSON, chansJSON string
		var enabled int
		if err := rows.Scan(&r.ID, &r.Name, &scopeJSON, &triggersJSON, &chansJSON, &r.CooldownSec, &r.Priority, &enabled); err != nil {
			continue
		}
		r.Enabled = enabled == 1
		_ = json.Unmarshal([]byte(scopeJSON), &r.Scope)
		_ = json.Unmarshal([]byte(triggersJSON), &r.Triggers)
		_ = json.Unmarshal([]byte(chansJSON), &r.Channels)
		rules = append(rules, r)
	}
	e.ruleCache = rules
	e.rulesCached = time.Now()
	return rules, nil
}

func (e *Engine) loadChannels(ids []string) ([]Channel, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = "?"
		args[i] = id
	}
	rows, err := e.db.Query(
		`SELECT id, name, type, config, enabled FROM alert_channels WHERE id IN (`+
			joinStrings(placeholders, ",")+`)`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var chans []Channel
	for rows.Next() {
		var ch Channel
		var cfgJSON string
		var enabled int
		if err := rows.Scan(&ch.ID, &ch.Name, &ch.Type, &cfgJSON, &enabled); err != nil {
			continue
		}
		ch.Enabled = enabled == 1
		_ = json.Unmarshal([]byte(cfgJSON), &ch.Config)
		chans = append(chans, ch)
	}
	return chans, nil
}

// InvalidateRuleCache force le rechargement des règles au prochain événement.
func (e *Engine) InvalidateRuleCache() {
	e.mu.Lock()
	e.rulesCached = time.Time{}
	e.mu.Unlock()
}

// --- matching helpers ---

func matchesTrigger(r Rule, ev Event) bool {
	for _, t := range r.Triggers {
		if t == ev.Trigger {
			return true
		}
	}
	return false
}

func matchesScope(s Scope, ev Event) bool {
	if len(s.Nodes) > 0 && ev.NodeName != "" {
		found := false
		for _, n := range s.Nodes {
			if n == ev.NodeName {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if s.DomainGlob != "" && ev.Domain != "" {
		if ok, _ := filepath.Match(s.DomainGlob, ev.Domain); !ok {
			return false
		}
	}
	if len(s.Components) > 0 && ev.Component != "" {
		found := false
		for _, c := range s.Components {
			if c == ev.Component {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if s.MinSev != "" && !sevGTE(ev.Severity, s.MinSev) {
		return false
	}
	return true
}

func sevGTE(a, b Severity) bool {
	order := map[Severity]int{SevInfo: 0, SevWarning: 1, SevCritical: 2}
	return order[a] >= order[b]
}

func buildMessage(r Rule, ev Event) Message {
	label := TriggerLabels[ev.Trigger]
	if label == "" {
		label = string(ev.Trigger)
	}
	title := fmt.Sprintf("[%s] %s", ev.Severity, label)
	body := label
	if ev.NodeName != "" {
		body += "\nNœud : " + ev.NodeName
	}
	if ev.Domain != "" {
		body += "\nDomaine : " + ev.Domain
	}
	return Message{
		RuleName: r.Name,
		Trigger:  ev.Trigger,
		Severity: ev.Severity,
		Title:    title,
		Body:     body,
		Detail:   ev.Detail,
		FiredAt:  ev.FiredAt,
	}
}

func joinStrings(s []string, sep string) string {
	result := ""
	for i, v := range s {
		if i > 0 {
			result += sep
		}
		result += v
	}
	return result
}
