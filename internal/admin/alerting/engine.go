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

	groupMu  sync.Mutex
	groupBuf map[string][]groupedEvent // clé : ruleID, en attente de regroupement
	groupTmr map[string]*time.Timer
}

// groupedEvent est un événement en attente dans le tampon de regroupement d'une règle.
type groupedEvent struct {
	ev  Event
	msg Message
}

// New crée un Engine et démarre la goroutine de traitement.
func New(db *sql.DB, log *slog.Logger) *Engine {
	e := &Engine{
		db:        db,
		log:       log,
		events:    make(chan Event, 256),
		stop:      make(chan struct{}),
		cooldowns: map[string]time.Time{},
		groupBuf:  map[string][]groupedEvent{},
		groupTmr:  map[string]*time.Timer{},
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

// Stop arrête l'Engine proprement et annule les regroupements en attente
// (les événements déjà tamponnés ne partent pas — ils resteront visibles dans
// leurs événements d'origine s'ils sont réémis après redémarrage).
func (e *Engine) Stop() {
	close(e.stop)
	e.groupMu.Lock()
	for _, tmr := range e.groupTmr {
		tmr.Stop()
	}
	e.groupTmr = map[string]*time.Timer{}
	e.groupBuf = map[string][]groupedEvent{}
	e.groupMu.Unlock()
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
		// Le délai de rappel est propre à chaque passerelle et domaine : une alerte sur l'une ne doit pas masquer celle d'une autre.
		key := rule.ID + ":" + string(ev.Trigger) + ":" + ev.NodeName + ":" + ev.Domain
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
		e.mu.Unlock()

		msg := buildMessage(rule, ev)
		if e.isSilenced(rule.ID) {
			// Le silence bloque l'envoi mais ne consomme pas le cooldown : la
			// première alerte réelle après sa fin part immédiatement.
			e.recordSilenced(rule, ev, msg)
			continue
		}

		e.mu.Lock()
		e.cooldowns[key] = time.Now()
		e.mu.Unlock()

		if rule.GroupWindowSec > 0 {
			e.bufferGrouped(rule, ev, msg)
			continue
		}

		e.dispatch(rule, msg)
		eventID := e.recordFired(rule, ev, msg)
		e.scheduleEscalation(rule, eventID)
	}
}

// scheduleEscalation programme les paliers d'escalade d'une règle pour un
// événement donné : tant que l'événement n'est pas acquitté, chaque palier
// renotifie (vers ses canaux propres, ou ceux de la règle si non précisés) au
// bout de son délai. Un accusé de réception (POST /alert-events/{id}/ack)
// n'annule pas les minuteurs déjà lancés : chacun revérifie l'état au moment
// de se déclencher, donc un accusé après programmation les rend simplement
// silencieux.
func (e *Engine) scheduleEscalation(rule Rule, eventID int64) {
	if eventID == 0 || len(rule.Escalation) == 0 {
		return
	}
	for _, step := range rule.Escalation {
		if step.AfterSec <= 0 {
			continue
		}
		step := step
		time.AfterFunc(time.Duration(step.AfterSec)*time.Second, func() {
			e.fireEscalation(rule, eventID, step)
		})
	}
}

func (e *Engine) fireEscalation(rule Rule, eventID int64, step EscalationStep) {
	var acked int
	if err := e.db.QueryRow(`SELECT acked FROM alert_events WHERE id=?`, eventID).Scan(&acked); err != nil || acked == 1 {
		return // acquitté, ou l'événement a été purgé
	}
	channelIDs := step.Channels
	if len(channelIDs) == 0 {
		channelIDs = rule.Channels
	}
	escRule := rule
	escRule.Channels = channelIDs
	var title, body string
	_ = e.db.QueryRow(`SELECT message_title, message_body FROM alert_events WHERE id=?`, eventID).Scan(&title, &body)
	msg := Message{
		RuleName: rule.Name,
		Severity: SevCritical, // une escalade est par nature plus urgente que l'alerte d'origine
		Title:    "[ESCALADE] " + title,
		Body:     body + fmt.Sprintf("\n\nToujours pas acquittée — accusez réception depuis Automatisation > Alertes > Journal (événement #%d).", eventID),
		FiredAt:  time.Now(),
	}
	e.dispatch(escRule, msg)
	e.log.Info("alerting: escalade relancée", "rule", rule.Name, "event_id", eventID, "after_sec", step.AfterSec)
}

// bufferGrouped ajoute l'événement au tampon de regroupement d'une règle et
// programme (ou reprogramme) l'envoi groupé à la fin de la fenêtre. Le premier
// événement d'une fenêtre démarre le minuteur ; les suivants s'y ajoutent sans
// le repousser, pour garantir un délai maximal borné même sous flot continu.
func (e *Engine) bufferGrouped(rule Rule, ev Event, msg Message) {
	e.groupMu.Lock()
	defer e.groupMu.Unlock()
	e.groupBuf[rule.ID] = append(e.groupBuf[rule.ID], groupedEvent{ev: ev, msg: msg})
	if e.groupTmr[rule.ID] != nil {
		return // minuteur déjà en cours pour cette règle
	}
	window := time.Duration(rule.GroupWindowSec) * time.Second
	e.groupTmr[rule.ID] = time.AfterFunc(window, func() { e.flushGrouped(rule.ID) })
}

// flushGrouped envoie une notification unique résumant tous les événements
// accumulés pendant la fenêtre de regroupement d'une règle, puis les journalise.
func (e *Engine) flushGrouped(ruleID string) {
	e.groupMu.Lock()
	events := e.groupBuf[ruleID]
	delete(e.groupBuf, ruleID)
	delete(e.groupTmr, ruleID)
	e.groupMu.Unlock()
	if len(events) == 0 {
		return
	}

	rules, err := e.loadRules()
	if err != nil {
		e.log.Error("alerting: chargement règles (flush groupé)", "err", err)
		return
	}
	var rule *Rule
	for i := range rules {
		if rules[i].ID == ruleID {
			rule = &rules[i]
			break
		}
	}
	if rule == nil {
		return // règle supprimée entre-temps
	}

	first := events[0].msg
	label := TriggerLabels[first.Trigger]
	if label == "" {
		label = string(first.Trigger)
	}
	combined := Message{
		RuleName: rule.Name,
		Trigger:  first.Trigger,
		Severity: first.Severity,
		Title:    fmt.Sprintf("[%s] %d× %s", first.Severity, len(events), label),
		Body:     groupedBody(events, label),
		Detail:   map[string]any{"grouped_count": len(events)},
		FiredAt:  time.Now(),
	}
	e.dispatch(*rule, combined)
	eventID := e.recordFired(*rule, Event{Trigger: first.Trigger, Detail: combined.Detail, FiredAt: combined.FiredAt}, combined)
	e.scheduleEscalation(*rule, eventID)
}

// groupedBody énumère jusqu'à 5 événements regroupés, puis résume le reste.
func groupedBody(events []groupedEvent, label string) string {
	body := fmt.Sprintf("%d événements « %s » regroupés :\n", len(events), label)
	max := len(events)
	if max > 5 {
		max = 5
	}
	for i := 0; i < max; i++ {
		body += "· " + events[i].msg.Body + "\n"
	}
	if len(events) > max {
		body += fmt.Sprintf("… et %d de plus", len(events)-max)
	}
	return body
}

// isSilenced indique si un silence actif (créé depuis Automatisation > Alertes
// > Silences & maintenance, table partagée avec le moteur de règles) couvre
// actuellement ruleID.
func (e *Engine) isSilenced(ruleID string) bool {
	rows, err := e.db.Query(
		`SELECT rule_ids FROM automation_silences
		 WHERE starts_at <= CURRENT_TIMESTAMP AND ends_at >= CURRENT_TIMESTAMP`,
	)
	if err != nil {
		e.log.Warn("alerting: chargement silences", "err", err)
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var ruleIDsJSON string
		if err := rows.Scan(&ruleIDsJSON); err != nil {
			continue
		}
		var ids []string
		_ = json.Unmarshal([]byte(ruleIDsJSON), &ids)
		if len(ids) == 0 {
			return true // silence sans portée = toutes les règles
		}
		for _, id := range ids {
			if id == ruleID {
				return true
			}
		}
	}
	return false
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

// recordFired journalise une notification effectivement envoyée et retourne
// l'ID de l'événement (0 si l'insertion a échoué), utilisé pour programmer
// l'escalade et pour l'accusé de réception.
func (e *Engine) recordFired(rule Rule, ev Event, msg Message) int64 {
	detail, _ := json.Marshal(ev.Detail)
	chansJSON, _ := json.Marshal(rule.Channels)
	res, err := e.db.Exec(
		`INSERT INTO alert_events (rule_id, trigger, detail, channels, message_title, message_body, priority, silenced) VALUES (?, ?, ?, ?, ?, ?, ?, 0)`,
		rule.ID, string(ev.Trigger), string(detail), string(chansJSON), msg.Title, msg.Body, rule.Priority,
	)
	// Purge des événements > 30 jours
	_, _ = e.db.Exec(`DELETE FROM alert_events WHERE fired_at < datetime('now', '-30 days')`)
	if err != nil {
		return 0
	}
	id, _ := res.LastInsertId()
	return id
}

// recordSilenced journalise une correspondance bloquée par un silence actif :
// aucun canal n'est notifié, mais l'événement reste visible (journal, MCP, CLI).
func (e *Engine) recordSilenced(rule Rule, ev Event, msg Message) {
	detail, _ := json.Marshal(ev.Detail)
	_, _ = e.db.Exec(
		`INSERT INTO alert_events (rule_id, trigger, detail, channels, message_title, message_body, priority, silenced) VALUES (?, ?, ?, '[]', ?, ?, ?, 1)`,
		rule.ID, string(ev.Trigger), string(detail), msg.Title, msg.Body, rule.Priority,
	)
}

// loadRules charge et cache les règles actives (TTL 30 s).
func (e *Engine) loadRules() ([]Rule, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if time.Since(e.rulesCached) < 30*time.Second {
		return e.ruleCache, nil
	}
	rows, err := e.db.Query(
		`SELECT id, name, scope, triggers, channels, cooldown_sec, priority, enabled, COALESCE(group_window_sec,0), COALESCE(escalation_json,'[]')
		 FROM alert_rules ORDER BY priority DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []Rule
	for rows.Next() {
		var r Rule
		var scopeJSON, triggersJSON, chansJSON, escalationJSON string
		var enabled int
		if err := rows.Scan(&r.ID, &r.Name, &scopeJSON, &triggersJSON, &chansJSON, &r.CooldownSec, &r.Priority, &enabled, &r.GroupWindowSec, &escalationJSON); err != nil {
			continue
		}
		r.Enabled = enabled == 1
		_ = json.Unmarshal([]byte(scopeJSON), &r.Scope)
		_ = json.Unmarshal([]byte(triggersJSON), &r.Triggers)
		_ = json.Unmarshal([]byte(chansJSON), &r.Channels)
		_ = json.Unmarshal([]byte(escalationJSON), &r.Escalation)
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
