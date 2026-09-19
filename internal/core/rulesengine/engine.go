// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rulesengine

import (
	"fmt"
	"sync"
	"time"
)

const defaultInterval = 60 * time.Second

// Deps regroupe les dépendances en mémoire que le moteur interroge pour évaluer les conditions.
type Deps struct {
	// GetRecentBanCount retourne le nombre de bans depuis `since` (source="" = toutes).
	GetRecentBanCount func(since time.Time, source string) int
	// GetRepeatBanIP retourne l'IP bannie ≥ minCount fois depuis `since` et son nombre de bans.
	GetRepeatBanIP func(since time.Time, minCount int) (ip string, count int)
	// GetF2BLastActivity retourne l'heure du dernier ban Fail2Ban (zéro si jamais).
	GetF2BLastActivity func() time.Time
	// GetCrowdSecLastSync retourne l'heure de la dernière sync CrowdSec.
	GetCrowdSecLastSync func() time.Time
	// GetProxyErrorRate retourne le pire taux d'erreurs HTTP (0-100) et le domaine/proxy concerné.
	GetProxyErrorRate func(since time.Time) (rate float64, host string)
	// DisableProxy désactive une route par son ID (ou host si pas d'ID).
	DisableProxy func(id string) error
	// BanIP ajoute un ban IP avec durée (0 = permanent).
	BanIP func(ip, reason string, duration time.Duration) error
	// EnableStrictF2B réduit max_errors Fail2Ban temporairement.
	EnableStrictF2B func(duration time.Duration) error
	// EmitNotify envoie une notification (pour ActionNotify).
	EmitNotify func(ruleID, severity, title, message string, detail map[string]any)
}

// Engine évalue périodiquement les règles en mémoire.
type Engine struct {
	mu        sync.RWMutex
	rules     []Rule
	cooldowns map[string]time.Time
	deps      Deps
	interval  time.Duration
	log       logger

	// OnRuleFired est appelé après chaque règle déclenchée (ou tentée).
	OnRuleFired func(ExecLog)

	stop chan struct{}
	done chan struct{}
}

type logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Debug(msg string, args ...any)
}

// New crée un Engine. Appeler Start() pour démarrer la boucle d'évaluation.
func New(log logger, deps Deps) *Engine {
	return &Engine{
		deps:      deps,
		interval:  defaultInterval,
		cooldowns: map[string]time.Time{},
		log:       log,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
}

// ReplaceRules remplace atomiquement les règles en mémoire (appelé sur TypePushAutoRules).
func (e *Engine) ReplaceRules(rules []Rule) {
	e.mu.Lock()
	e.rules = rules
	e.mu.Unlock()
}

// Rules retourne une copie des règles courantes.
func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// Start lance la goroutine d'évaluation.
func (e *Engine) Start() {
	go e.loop()
}

// Stop arrête la goroutine proprement.
func (e *Engine) Stop() {
	close(e.stop)
	<-e.done
}

func (e *Engine) loop() {
	defer close(e.done)
	ticker := time.NewTicker(e.interval)
	defer ticker.Stop()
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
	e.mu.RLock()
	rules := make([]Rule, len(e.rules))
	copy(rules, e.rules)
	e.mu.RUnlock()

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		e.evalRule(rule)
	}
}

func (e *Engine) evalRule(rule Rule) {
	matched, detail, err := e.evalCondition(rule.Condition)
	if err != nil {
		e.log.Warn("rulesengine: évaluation condition", "rule", rule.Name, "err", err)
		e.emit(ExecLog{
			RuleID: rule.ID, RuleName: rule.Name,
			CondResult: false, ActionTaken: false,
			Error: err.Error(), FiredAt: time.Now(),
		})
		return
	}
	if !matched {
		return
	}

	// cooldown
	cooldown := time.Duration(rule.CooldownSec) * time.Second
	if cooldown == 0 {
		cooldown = 5 * time.Minute
	}
	e.mu.Lock()
	last := e.cooldowns[rule.ID]
	if time.Since(last) < cooldown {
		e.mu.Unlock()
		return
	}
	e.cooldowns[rule.ID] = time.Now()
	e.mu.Unlock()

	actionErr := e.execAction(ActionContext{Rule: rule, Detail: detail})
	log := ExecLog{
		RuleID: rule.ID, RuleName: rule.Name,
		CondResult: true, ActionTaken: actionErr == nil,
		Detail: detail, FiredAt: time.Now(),
	}
	if actionErr != nil {
		log.Error = actionErr.Error()
		e.log.Warn("rulesengine: action échouée", "rule", rule.Name, "err", actionErr)
	} else {
		e.log.Info("rulesengine: règle déclenchée", "rule", rule.Name, "action", rule.Action.Type)
	}
	e.emit(log)
}

func (e *Engine) evalCondition(c Condition) (bool, map[string]any, error) {
	switch c.Type {
	case CondCVECritical:
		return false, nil, nil // pas de données CVE en Core
	case CondBanSpike:
		return e.evalBanSpike(c)
	case CondEngineSilent:
		return e.evalEngineSilent(c)
	case CondProxyErrorRate:
		return e.evalProxyErrorRate(c)
	case CondBanRepeat:
		return e.evalBanRepeat(c)
	default:
		return false, nil, fmt.Errorf("type de condition inconnu: %s", c.Type)
	}
}

func (e *Engine) execAction(ac ActionContext) error {
	switch ac.Rule.Action.Type {
	case ActionDisableProxy:
		return e.execDisableProxy(ac)
	case ActionBanIP:
		return e.execBanIP(ac)
	case ActionNotify:
		e.execNotify(ac)
		return nil
	case ActionEnableStrict:
		return e.execEnableStrict(ac)
	default:
		return fmt.Errorf("type d'action inconnu: %s", ac.Rule.Action.Type)
	}
}

func (e *Engine) emit(log ExecLog) {
	if e.OnRuleFired != nil {
		e.OnRuleFired(log)
	}
}

// ActionContext est passé aux exécuteurs d'actions.
type ActionContext struct {
	Rule   Rule
	Detail map[string]any
}
