// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package playbooks

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/rulesengine"
)

// ActionRunner est implémenté par rulesengine.Engine.
type ActionRunner interface {
	RunAction(ctx context.Context, action rulesengine.Action, name string, detail map[string]any) error
	EvalCondition(ctx context.Context, c rulesengine.Condition) (bool, map[string]any, error)
}

// Engine exécute des playbooks : chaque run avance dans sa propre goroutine,
// avec un time.AfterFunc pour les étapes "wait" et une pause indéfinie pour
// les étapes "approval" jusqu'à une décision explicite. L'état persiste en
// base (playbook_runs) mais l'avancement lui-même ne survit pas à un
// redémarrage de l'Admin, au même titre que les autres minuteurs en mémoire
// du moteur d'alertes (regroupement, escalade).
type Engine struct {
	db    *sql.DB
	log   *slog.Logger
	rules ActionRunner
}

// New crée un Engine.
func New(db *sql.DB, log *slog.Logger, rules ActionRunner) *Engine {
	return &Engine{db: db, log: log, rules: rules}
}

// StartRun charge un playbook et démarre son exécution en arrière-plan.
// Retourne l'ID du run créé immédiatement (avant que la première étape ne
// s'exécute), pour que l'appelant puisse le suivre.
func (e *Engine) StartRun(ctx context.Context, playbookID string, detail map[string]any) (string, error) {
	pb, err := e.loadPlaybook(playbookID)
	if err != nil {
		return "", err
	}
	if !pb.Enabled {
		return "", fmt.Errorf("playbook %q désactivé", pb.Name)
	}
	stepsJSON, _ := json.Marshal(pb.Steps)
	if detail == nil {
		detail = map[string]any{}
	}
	contextJSON, _ := json.Marshal(detail)
	id := uuid.New().String()
	if _, err := e.db.Exec(
		`INSERT INTO playbook_runs (id, playbook_id, playbook_name, steps_json, current_step, status, log_json, context_json)
		 VALUES (?, ?, ?, ?, 0, 'running', '[]', ?)`,
		id, pb.ID, pb.Name, string(stepsJSON), string(contextJSON),
	); err != nil {
		return "", err
	}
	go e.advance(id)
	return id, nil
}

// RunNow relance un playbook depuis le début (bouton « Exécuter maintenant »).
func (e *Engine) RunNow(id string) (string, error) {
	return e.StartRun(context.Background(), id, nil)
}

// advance exécute les étapes d'un run à partir de son CurrentStep, jusqu'à un
// wait (qui reprogramme advance via time.AfterFunc), une approbation (qui
// suspend jusqu'à Decide), une fin de séquence, ou une erreur/condition fausse.
func (e *Engine) advance(runID string) {
	run, err := e.loadRun(runID)
	if err != nil {
		e.log.Error("playbooks: chargement run", "run_id", runID, "err", err)
		return
	}
	if run.status != string(RunRunning) {
		return // suspendu (approbation) ou déjà terminé : rien à faire
	}
	ctx := context.Background()
	for i := run.step; i < len(run.steps); i++ {
		step := run.steps[i]
		switch step.Type {
		case StepAction:
			err := e.rules.RunAction(ctx, step.Action, run.playbookName, run.context)
			e.appendLog(runID, i, step, err == nil, errString(err))
			if err != nil {
				e.finish(runID, i, string(RunFailed))
				return
			}

		case StepCondition:
			matched, _, err := e.rules.EvalCondition(ctx, step.Condition)
			if err != nil {
				e.appendLog(runID, i, step, false, err.Error())
				e.finish(runID, i, string(RunFailed))
				return
			}
			e.appendLog(runID, i, step, matched, conditionDetail(matched))
			if !matched {
				e.finish(runID, i, string(RunStopped))
				return
			}

		case StepWait:
			e.appendLog(runID, i, step, true, fmt.Sprintf("attente %ds", step.WaitSec))
			e.setStep(runID, i+1)
			wait := time.Duration(step.WaitSec) * time.Second
			time.AfterFunc(wait, func() { e.advance(runID) })
			return // reprend plus tard via le minuteur

		case StepApproval:
			e.appendLog(runID, i, step, true, "en attente d'approbation")
			e.setStatus(runID, i, string(RunWaitingApproval))
			return // reprend via Decide()

		default:
			e.appendLog(runID, i, step, false, "type d'étape inconnu: "+string(step.Type))
			e.finish(runID, i, string(RunFailed))
			return
		}
	}
	e.finish(runID, len(run.steps), string(RunCompleted))
}

// Decide approuve ou refuse un run suspendu à une étape d'approbation.
// Approuver reprend l'avancement à l'étape suivante ; refuser arrête le run.
func (e *Engine) Decide(runID string, approve bool) error {
	run, err := e.loadRun(runID)
	if err != nil {
		return err
	}
	if run.status != string(RunWaitingApproval) {
		return fmt.Errorf("ce run n'attend pas d'approbation (statut: %s)", run.status)
	}
	if !approve {
		e.finish(runID, run.step, string(RunStopped))
		return nil
	}
	e.setStep(runID, run.step+1)
	if _, err := e.db.Exec(`UPDATE playbook_runs SET status='running', updated_at=CURRENT_TIMESTAMP WHERE id=?`, runID); err != nil {
		return err
	}
	go e.advance(runID)
	return nil
}

// ── Persistance ──────────────────────────────────────────────────────────────

type loadedRun struct {
	step         int
	status       string
	steps        []Step
	context      map[string]any
	playbookName string
}

func (e *Engine) loadRun(id string) (*loadedRun, error) {
	var stepsJSON, contextJSON, status, playbookName string
	var step int
	err := e.db.QueryRow(
		`SELECT steps_json, context_json, status, current_step, playbook_name FROM playbook_runs WHERE id=?`, id,
	).Scan(&stepsJSON, &contextJSON, &status, &step, &playbookName)
	if err != nil {
		return nil, err
	}
	var steps []Step
	var ctxMap map[string]any
	_ = json.Unmarshal([]byte(stepsJSON), &steps)
	_ = json.Unmarshal([]byte(contextJSON), &ctxMap)
	return &loadedRun{step: step, status: status, steps: steps, context: ctxMap, playbookName: playbookName}, nil
}

func (e *Engine) loadPlaybook(id string) (*Playbook, error) {
	var pb Playbook
	var stepsJSON string
	var enabled int
	err := e.db.QueryRow(
		`SELECT id, name, description, steps_json, enabled, created_at, updated_at FROM playbooks WHERE id=?`, id,
	).Scan(&pb.ID, &pb.Name, &pb.Description, &stepsJSON, &enabled, &pb.CreatedAt, &pb.UpdatedAt)
	if err != nil {
		return nil, err
	}
	pb.Enabled = enabled == 1
	_ = json.Unmarshal([]byte(stepsJSON), &pb.Steps)
	return &pb, nil
}

func (e *Engine) appendLog(runID string, stepIndex int, step Step, success bool, detail string) {
	var logJSON string
	if err := e.db.QueryRow(`SELECT log_json FROM playbook_runs WHERE id=?`, runID).Scan(&logJSON); err != nil {
		return
	}
	var log []LogEntry
	_ = json.Unmarshal([]byte(logJSON), &log)
	log = append(log, LogEntry{StepIndex: stepIndex, Type: step.Type, Note: step.Note, Success: success, Detail: detail, At: time.Now()})
	b, _ := json.Marshal(log)
	_, _ = e.db.Exec(`UPDATE playbook_runs SET log_json=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, string(b), runID)
}

func (e *Engine) setStep(runID string, step int) {
	_, _ = e.db.Exec(`UPDATE playbook_runs SET current_step=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, step, runID)
}

func (e *Engine) setStatus(runID string, step int, status string) {
	_, _ = e.db.Exec(`UPDATE playbook_runs SET current_step=?, status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, step, status, runID)
}

func (e *Engine) finish(runID string, step int, status string) {
	_, _ = e.db.Exec(
		`UPDATE playbook_runs SET current_step=?, status=?, updated_at=CURRENT_TIMESTAMP, finished_at=CURRENT_TIMESTAMP WHERE id=?`,
		step, status, runID,
	)
	e.log.Info("playbooks: run terminé", "run_id", runID, "status", status)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func conditionDetail(matched bool) string {
	if matched {
		return "condition vraie — poursuite"
	}
	return "condition fausse — arrêt du playbook"
}
