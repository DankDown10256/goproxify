// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rulesengine

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/admin/adminmetrics"
)

const defaultInterval = 60 * time.Second

// Deps regroupe les dépendances externes que le moteur peut appeler pour les actions.
type Deps struct {
	// DisableProxy désactive un proxy par ID dans la DB et pousse la config.
	DisableProxy func(ctx context.Context, proxyID string) error
	// CreateBan crée un ban (ip, reason, durationSec=0 pour permanent).
	CreateBan func(ctx context.Context, ip, reason string, durationSec int) error
	// EmitAlert envoie une notification via le moteur d'alertes existant.
	EmitAlert func(trigger, severity, title, body string, detail map[string]any)
	// GetF2BLastActivity retourne l'heure de la dernière activité Fail2Ban.
	GetF2BLastActivity func() time.Time
	// GetCrowdSecLastSync retourne l'heure de la dernière sync CrowdSec.
	GetCrowdSecLastSync func() time.Time
}

// Engine évalue périodiquement les règles et exécute les actions.
type Engine struct {
	db       *sql.DB
	log      *slog.Logger
	deps     Deps
	interval time.Duration

	mu        sync.Mutex
	cooldowns map[string]time.Time // clé : ruleID
	stop      chan struct{}
	done      chan struct{}
}

// New crée un Engine. Appeler Start() pour démarrer la boucle d'évaluation.
func New(db *sql.DB, log *slog.Logger, deps Deps) *Engine {
	return &Engine{
		db:        db,
		log:       log,
		deps:      deps,
		interval:  defaultInterval,
		cooldowns: map[string]time.Time{},
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
}

// Start lance la goroutine d'évaluation. Appeler Stop() pour l'arrêter proprement.
func (e *Engine) Start() {
	go e.loop()
}

// Stop arrête la goroutine et attend qu'elle se termine.
func (e *Engine) Stop() {
	close(e.stop)
	<-e.done
}

func (e *Engine) loop() {
	defer close(e.done)
	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()
	// première évaluation immédiate au démarrage
	e.evalAll()
	for {
		select {
		case <-ticker.C:
			e.evalAll()
		case <-e.stop:
			return
		}
	}
}

func (e *Engine) evalAll() {
	adminmetrics.RulesEngine.EvalsTotal.Inc()
	rules, err := e.loadRules()
	if err != nil {
		e.log.Error("rulesengine: chargement règles", "err", err)
		return
	}
	ctx := context.Background()
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		e.evalRule(ctx, rule)
	}
}

func (e *Engine) evalRule(ctx context.Context, rule Rule) {
	matched, detail, err := e.evalCondition(ctx, rule.Condition)
	if err != nil {
		e.log.Warn("rulesengine: évaluation condition", "rule", rule.Name, "err", err)
		e.recordExec(rule, false, false, "", err.Error())
		return
	}
	if !matched {
		return
	}

	// cooldown
	e.mu.Lock()
	last := e.cooldowns[rule.ID]
	cooldown := time.Duration(rule.CooldownSec) * time.Second
	if cooldown == 0 {
		cooldown = 5 * time.Minute
	}
	if time.Since(last) < cooldown {
		e.mu.Unlock()
		return
	}
	e.cooldowns[rule.ID] = time.Now()
	e.mu.Unlock()

	actionErr := e.execAction(ctx, ActionContext{Rule: rule, Detail: detail})
	errStr := ""
	if actionErr != nil {
		errStr = actionErr.Error()
		adminmetrics.RulesEngine.ActionsTotal.WithLabelValues(string(rule.Action.Type), "error").Inc()
		e.log.Warn("rulesengine: action échouée", "rule", rule.Name, "action", rule.Action.Type, "err", actionErr)
	} else {
		adminmetrics.RulesEngine.ActionsTotal.WithLabelValues(string(rule.Action.Type), "success").Inc()
		e.log.Info("rulesengine: règle déclenchée", "rule", rule.Name, "action", rule.Action.Type)
	}

	detailJSON, _ := json.Marshal(detail)
	e.recordExec(rule, true, actionErr == nil, string(detailJSON), errStr)
}

// evalCondition évalue la condition et retourne (matched, detail, err).
func (e *Engine) evalCondition(ctx context.Context, c Condition) (bool, map[string]any, error) {
	switch c.Type {
	case CondCVECritical:
		return e.evalCVECritical(ctx, c)
	case CondBanSpike:
		return e.evalBanSpike(ctx, c)
	case CondEngineSilent:
		return e.evalEngineSilent(c)
	case CondProxyErrorRate:
		return e.evalProxyErrorRate(ctx, c)
	case CondBanRepeat:
		return e.evalBanRepeat(ctx, c)
	default:
		return false, nil, fmt.Errorf("type de condition inconnu: %s", c.Type)
	}
}

// execAction exécute l'action d'une règle déclenchée.
func (e *Engine) execAction(ctx context.Context, ac ActionContext) error {
	switch ac.Rule.Action.Type {
	case ActionDisableProxy:
		return e.execDisableProxy(ctx, ac)
	case ActionBanIP:
		return e.execBanIP(ctx, ac)
	case ActionNotify:
		e.execNotify(ac)
		return nil
	case ActionEnableStrict:
		return e.execEnableStrict(ctx, ac)
	default:
		return fmt.Errorf("type d'action inconnu: %s", ac.Rule.Action.Type)
	}
}

// EvalNow force une évaluation immédiate d'une règle (dry-run si dryRun=true).
func (e *Engine) EvalNow(ctx context.Context, ruleID string, dryRun bool) (bool, map[string]any, error) {
	rules, err := e.loadRules()
	if err != nil {
		return false, nil, err
	}
	for _, r := range rules {
		if r.ID == ruleID {
			matched, detail, err := e.evalCondition(ctx, r.Condition)
			if err != nil {
				return false, nil, err
			}
			if matched && !dryRun {
				_ = e.execAction(ctx, ActionContext{Rule: r, Detail: detail})
			}
			return matched, detail, nil
		}
	}
	return false, nil, fmt.Errorf("règle %q introuvable", ruleID)
}

func (e *Engine) recordExec(rule Rule, matched, actionTaken bool, detail, errStr string) {
	m := 0
	if matched {
		m = 1
	}
	a := 0
	if actionTaken {
		a = 1
	}
	_, _ = e.db.Exec(
		`INSERT INTO rules_engine_history (rule_id, cond_result, action_taken, detail, error)
		 VALUES (?, ?, ?, ?, ?)`,
		rule.ID, m, a, detail, errStr,
	)
	_, _ = e.db.Exec(
		`DELETE FROM rules_engine_history WHERE fired_at < datetime('now', '-30 days')`,
	)
	if matched && actionTaken {
		_, _ = e.db.Exec(
			`UPDATE rules_engine_rules SET last_fired_at=CURRENT_TIMESTAMP,
			 fire_count=fire_count+1 WHERE id=?`, rule.ID,
		)
	}
}

func (e *Engine) loadRules() ([]Rule, error) {
	rows, err := e.db.Query(
		`SELECT id, name, description, enabled, condition_json, action_json,
		        cooldown_sec, created_at, updated_at, last_fired_at, fire_count
		 FROM rules_engine_rules ORDER BY created_at`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rules []Rule
	for rows.Next() {
		var r Rule
		var condJSON, actionJSON string
		var enabled int
		var lastFired sql.NullString
		if err := rows.Scan(
			&r.ID, &r.Name, &r.Description, &enabled,
			&condJSON, &actionJSON, &r.CooldownSec,
			&r.CreatedAt, &r.UpdatedAt, &lastFired, &r.FireCount,
		); err != nil {
			continue
		}
		r.Enabled = enabled == 1
		_ = json.Unmarshal([]byte(condJSON), &r.Condition)
		_ = json.Unmarshal([]byte(actionJSON), &r.Action)
		if lastFired.Valid && lastFired.String != "" {
			t, err := time.Parse("2006-01-02T15:04:05Z", lastFired.String)
			if err != nil {
				t, _ = time.Parse("2006-01-02 15:04:05", lastFired.String)
			}
			if !t.IsZero() {
				r.LastFiredAt = &t
			}
		}
		rules = append(rules, r)
	}
	return rules, nil
}
