// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"context"
	"database/sql"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/admin/alerting"
)

// Deps regroupe ce que les conditions et les actions appellent hors du paquet.
type Deps struct {
	DisableProxy     func(ctx context.Context, proxyID string) error
	CreateBan        func(ctx context.Context, ip, reason string, durationSec int) error
	Emit             func(alerting.Event)
	FleetLastActivity func() time.Time
	CrowdSecLastSync func() time.Time
	RunBackup        func(ctx context.Context, name string, retention int) error
	// Metrics fournit les séries de la condition metric_threshold (nil : condition toujours fausse).
	Metrics MetricSource
}

// Options règle le service.
type Options struct {
	// IsLeader : seul le leader d'un Admin en haute disponibilité déclenche et fait avancer les flux
	// (nil : toujours leader).
	IsLeader func() bool
	// OnEdgeRulesChange est appelé quand la liste des flux exécutés par les passerelles peut avoir changé.
	OnEdgeRulesChange func()
	// Now remplace l'horloge (tests).
	Now func() time.Time
}

// Service porte les flux : enregistrement, déclenchement, exécution.
type Service struct {
	db   *sql.DB
	log  *slog.Logger
	deps Deps
	opts Options

	mu        sync.Mutex
	cooldowns map[string]time.Time // flux (+ clé de délai) → dernier déclenchement
	noted     map[string]time.Time // dernier journal « en sourdine » / « erreur de condition » par flux
	lastEval  map[string]time.Time // dernière évaluation par flux à condition

	events   chan alerting.Event
	stop     chan struct{}
	loops    sync.WaitGroup
	inflight sync.WaitGroup
	started  bool
}

// New crée le service. Start lance les déclencheurs.
func New(db *sql.DB, log *slog.Logger, deps Deps, opts Options) *Service {
	return &Service{
		db: db, log: log, deps: deps, opts: opts,
		cooldowns: map[string]time.Time{},
		noted:     map[string]time.Time{},
		lastEval:  map[string]time.Time{},
		events:    make(chan alerting.Event, 256),
		stop:      make(chan struct{}),
	}
}

func (s *Service) now() time.Time {
	if s.opts.Now != nil {
		return s.opts.Now()
	}
	return time.Now()
}

func (s *Service) leader() bool { return s.opts.IsLeader == nil || s.opts.IsLeader() }

func (s *Service) edgeChanged() {
	if s.opts.OnEdgeRulesChange != nil {
		s.opts.OnEdgeRulesChange()
	}
}

// Start reprend l'état laissé par l'arrêt précédent et lance les déclencheurs.
func (s *Service) Start() {
	s.recoverRuns()
	s.started = true
	s.loop(10*time.Second, s.pollConditions)
	s.loop(5*time.Second, s.resumeDue)
	s.loop(time.Hour, s.purge)
	s.loops.Add(2)
	go s.cronLoop()
	go s.eventLoop()
}

// Stop arrête les déclencheurs et attend la fin des étapes en cours.
func (s *Service) Stop() {
	if !s.started {
		return
	}
	close(s.stop)
	s.loops.Wait()
	s.inflight.Wait()
}

func (s *Service) loop(every time.Duration, fn func()) {
	s.loops.Add(1)
	go func() {
		defer s.loops.Done()
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				if s.leader() {
					fn()
				}
			case <-s.stop:
				return
			}
		}
	}()
}

// ── Déclencheur « condition » ───────────────────────────────────────────

// pollConditions évalue les flux à condition dont l'intervalle est écoulé. Les flux exécutés par les
// passerelles n'y sont pas : la passerelle les évalue elle-même, sur ses données.
func (s *Service) pollConditions() {
	start := time.Now()
	flows, err := s.queryFlows(context.Background(), `WHERE f.enabled=1 AND f.trigger_kind=?`, string(TriggerCondition))
	if err != nil {
		s.log.Error("automation: lecture des flux", "err", err)
		return
	}
	now := s.now()
	for _, f := range flows {
		if p, _ := placement(f); p == PlacementEdge {
			continue
		}
		interval := time.Duration(f.Trigger.IntervalSec) * time.Second
		if interval < minIntervalSec*time.Second {
			interval = 60 * time.Second
		}
		s.mu.Lock()
		due := now.Sub(s.lastEval[f.ID]) >= interval-time.Second
		if due {
			s.lastEval[f.ID] = now
		}
		s.mu.Unlock()
		if due {
			s.evalConditionFlow(f)
		}
	}
	countActive(s)
	adminmetricsEval(time.Since(start))
}

func (s *Service) evalConditionFlow(f *Flow) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	matched, detail, err := s.evalCond(ctx, f.Trigger.Condition, flowScope(f))
	if err != nil {
		s.log.Warn("automation: évaluation de condition", "flow", f.Name, "err", err)
		if s.noteOnce("err:"+f.ID, f) {
			s.recordFailure(f, "condition : "+err.Error(), RunFailed, nil)
		}
		return
	}
	if matched {
		s.fire(ctx, f, fireOpts{source: "admin", detail: detail})
	}
}

func flowScope(f *Flow) map[string]any {
	return map[string]any{"flow": map[string]any{"id": f.ID, "name": f.Name}}
}

// ── Déclencheur « horaire » ─────────────────────────────────────────────

func (s *Service) cronLoop() {
	defer s.loops.Done()
	for {
		now := time.Now()
		next := now.Truncate(time.Minute).Add(time.Minute)
		select {
		case <-time.After(time.Until(next)):
			if s.leader() {
				s.runSchedules(next)
			}
		case <-s.stop:
			return
		}
	}
}

func (s *Service) runSchedules(at time.Time) {
	flows, err := s.queryFlows(context.Background(), `WHERE f.enabled=1 AND f.trigger_kind=?`, string(TriggerSchedule))
	if err != nil {
		s.log.Error("automation: lecture des planifications", "err", err)
		return
	}
	for _, f := range flows {
		expr, err := ParseExpr(f.Trigger.Schedule.Cron)
		if err != nil || !expr.Matches(at) {
			continue
		}
		s.fire(context.Background(), f, fireOpts{source: "admin", detail: map[string]any{"scheduled_at": at.Format(time.RFC3339)}})
	}
}

// ── Déclencheur « événement » ───────────────────────────────────────────

// OnEvent reçoit les événements du moteur d'alertes (alerting.Engine.Subscribe). Il ne bloque jamais : la
// file pleine, l'événement est ignoré et compté.
func (s *Service) OnEvent(ev alerting.Event) {
	select {
	case s.events <- ev:
	default:
		adminmetricsDrop()
		s.log.Warn("automation: file des événements pleine, événement ignoré", "event", ev.Trigger)
	}
}

func (s *Service) eventLoop() {
	defer s.loops.Done()
	for {
		select {
		case ev := <-s.events:
			if s.leader() {
				s.handleEvent(ev)
			}
		case <-s.stop:
			return
		}
	}
}

func (s *Service) handleEvent(ev alerting.Event) {
	flows, err := s.queryFlows(context.Background(), `WHERE f.enabled=1 AND f.trigger_kind=?`, string(TriggerEvent))
	if err != nil || len(flows) == 0 {
		return
	}
	chain := chainOf(ev.Detail)
	for _, f := range flows {
		if !eventMatches(f.Trigger.Event, ev) || contains(chain, f.ID) || len(chain) >= maxDepth {
			continue
		}
		detail := map[string]any{}
		for k, v := range ev.Detail {
			if k != "flow_chain" {
				detail[k] = v
			}
		}
		detail["event"], detail["severity"] = string(ev.Trigger), string(ev.Severity)
		for k, v := range map[string]string{"node_name": ev.NodeName, "domain": ev.Domain, "component": ev.Component} {
			if _, set := detail[k]; !set && v != "" {
				detail[k] = v
			}
		}
		s.fire(context.Background(), f, fireOpts{source: "admin", detail: detail, chain: chain})
	}
}

func eventMatches(t *EventTrigger, ev alerting.Event) bool {
	if t == nil || t.Event != string(ev.Trigger) {
		return false
	}
	scope := alerting.Scope{Nodes: t.Nodes, DomainGlob: t.DomainGlob, MinSev: alerting.Severity(t.MinSeverity)}
	if !alerting.MatchScope(scope, ev) {
		return false
	}
	for key, pattern := range t.Match {
		if ok, _ := matchGlob(pattern, text(ev.Detail[key])); !ok {
			return false
		}
	}
	return true
}

func chainOf(detail map[string]any) []string {
	switch c := detail["flow_chain"].(type) {
	case []string:
		return c
	case []any:
		var out []string
		for _, e := range c {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

// DB retourne la base du service (tests des paquets qui l'utilisent).
func (s *Service) DB() *sql.DB { return s.db }

// ActorLabel remplace l'identifiant de l'utilisateur par son adresse dans l'acteur d'une décision ou d'un
// lancement : le journal d'un flux se lit par des personnes.
func (s *Service) ActorLabel(ctx context.Context, userID, actor string) string {
	var email string
	if userID == "" || s.db.QueryRowContext(ctx, `SELECT email FROM users WHERE id=?`, userID).Scan(&email) != nil || email == "" {
		return actor
	}
	return strings.Replace(actor, userID, email, 1)
}
