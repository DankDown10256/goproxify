// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package scheduler

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/vincamok/goproxify/internal/admin/rulesengine"
)

// ActionRunner exécute une action du moteur de règles indépendamment de toute
// condition — implémenté par rulesengine.Engine.
type ActionRunner interface {
	RunAction(ctx context.Context, action rulesengine.Action, name string, detail map[string]any) error
}

// Engine évalue chaque minute les planifications actives et exécute celles
// dont l'expression cron correspond à l'instant présent.
type Engine struct {
	db     *sql.DB
	log    *slog.Logger
	rules  ActionRunner
	stop   chan struct{}
	done   chan struct{}
	lastAt time.Time // dernière minute évaluée, pour ne jamais rejouer deux fois la même
}

// New crée un Engine. Appeler Start() pour démarrer la boucle.
func New(db *sql.DB, log *slog.Logger, rules ActionRunner) *Engine {
	return &Engine{db: db, log: log, rules: rules, stop: make(chan struct{}), done: make(chan struct{})}
}

// Start lance la goroutine d'évaluation (alignée sur le début de chaque minute).
func (e *Engine) Start() { go e.loop() }

// Stop arrête l'Engine proprement.
func (e *Engine) Stop() {
	close(e.stop)
	<-e.done
}

func (e *Engine) loop() {
	defer close(e.done)
	e.waitNextMinute()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	e.tick()
	for {
		select {
		case <-ticker.C:
			e.tick()
		case <-e.stop:
			return
		}
	}
}

func (e *Engine) waitNextMinute() {
	now := time.Now()
	next := now.Truncate(time.Minute).Add(time.Minute)
	select {
	case <-time.After(time.Until(next)):
	case <-e.stop:
	}
}

func (e *Engine) tick() {
	now := time.Now().Truncate(time.Minute)
	if now.Equal(e.lastAt) {
		return // déjà évalué (garde contre un double tick au démarrage)
	}
	e.lastAt = now

	tasks, err := e.loadEnabledTasks()
	if err != nil {
		e.log.Error("scheduler: chargement planifications", "err", err)
		return
	}
	for _, t := range tasks {
		expr, err := ParseExpr(t.CronExpr)
		if err != nil {
			e.log.Warn("scheduler: expression invalide, planification ignorée", "task", t.Name, "cron", t.CronExpr, "err", err)
			continue
		}
		if !expr.Matches(now) {
			continue
		}
		e.runTask(t)
	}
}

// task est une planification chargée depuis la DB.
type task struct {
	ID       string
	Name     string
	CronExpr string
	Action   rulesengine.Action
}

func (e *Engine) loadEnabledTasks() ([]task, error) {
	rows, err := e.db.Query(`SELECT id, name, cron_expr, action_json FROM scheduled_tasks WHERE enabled=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tasks []task
	for rows.Next() {
		var t task
		var actionJSON string
		if err := rows.Scan(&t.ID, &t.Name, &t.CronExpr, &actionJSON); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(actionJSON), &t.Action)
		tasks = append(tasks, t)
	}
	return tasks, nil
}

func (e *Engine) runTask(t task) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := e.rules.RunAction(ctx, t.Action, t.Name, map[string]any{"scheduled_task_id": t.ID})
	errStr := ""
	success := 1
	if err != nil {
		errStr = err.Error()
		success = 0
		e.log.Warn("scheduler: exécution échouée", "task", t.Name, "action", t.Action.Type, "err", err)
	} else {
		e.log.Info("scheduler: planification exécutée", "task", t.Name, "action", t.Action.Type)
	}
	_, _ = e.db.Exec(`UPDATE scheduled_tasks SET last_run_at=CURRENT_TIMESTAMP WHERE id=?`, t.ID)
	_, _ = e.db.Exec(`INSERT INTO scheduled_task_runs (task_id, success, error) VALUES (?, ?, ?)`, t.ID, success, errStr)
	_, _ = e.db.Exec(`DELETE FROM scheduled_task_runs WHERE ran_at < datetime('now', '-30 days')`)
}

// RunNow force l'exécution immédiate d'une planification (bouton « Exécuter
// maintenant », indépendamment de son expression cron).
func (e *Engine) RunNow(id string) error {
	var t task
	var actionJSON string
	err := e.db.QueryRow(`SELECT id, name, cron_expr, action_json FROM scheduled_tasks WHERE id=?`, id).
		Scan(&t.ID, &t.Name, &t.CronExpr, &actionJSON)
	if err != nil {
		return err
	}
	_ = json.Unmarshal([]byte(actionJSON), &t.Action)
	e.runTask(t)
	return nil
}
