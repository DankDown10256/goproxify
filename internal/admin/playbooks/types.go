// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package playbooks enchaîne plusieurs étapes (action, attente, condition,
// approbation) déclenchées comme une action du moteur de règles
// (rulesengine.ActionRunPlaybook) ou manuellement. Contrairement à une règle
// simple (une condition → une action), un playbook exécute une séquence, peut
// attendre un délai ou une décision humaine entre deux étapes, et s'arrête si
// une étape de type condition échoue.
package playbooks

import (
	"time"

	"github.com/vincamok/goproxify/internal/admin/rulesengine"
)

// StepType identifie le type d'une étape de playbook.
type StepType string

const (
	StepAction    StepType = "action"    // exécute une action du moteur de règles
	StepWait      StepType = "wait"      // attend N secondes avant l'étape suivante
	StepCondition StepType = "condition" // évalue une condition ; arrête le playbook si fausse
	StepApproval  StepType = "approval"  // suspend jusqu'à une décision humaine (Approuver/Refuser)
)

// Step est une étape d'un playbook.
type Step struct {
	Type StepType `json:"type"`

	// StepAction
	Action rulesengine.Action `json:"action,omitempty"`

	// StepWait
	WaitSec int `json:"wait_sec,omitempty"`

	// StepCondition
	Condition rulesengine.Condition `json:"condition,omitempty"`

	// Note libre affichée dans l'éditeur et le journal (toutes étapes).
	Note string `json:"note,omitempty"`
}

// Playbook est une séquence d'étapes nommée.
type Playbook struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	Steps       []Step    `json:"steps"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RunStatus est l'état d'une exécution de playbook.
type RunStatus string

const (
	RunRunning         RunStatus = "running"
	RunWaitingApproval RunStatus = "waiting_approval"
	RunCompleted       RunStatus = "completed"
	RunFailed          RunStatus = "failed"
	RunStopped         RunStatus = "stopped" // condition fausse : arrêt normal, pas un échec
)

// LogEntry journalise le résultat d'une étape exécutée.
type LogEntry struct {
	StepIndex int       `json:"step_index"`
	Type      StepType  `json:"type"`
	Note      string    `json:"note,omitempty"`
	Success   bool      `json:"success"`
	Detail    string    `json:"detail,omitempty"`
	At        time.Time `json:"at"`
}

// Run est une exécution en cours ou terminée d'un playbook.
type Run struct {
	ID           string         `json:"id"`
	PlaybookID   string         `json:"playbook_id"`
	PlaybookName string         `json:"playbook_name"`
	Steps        []Step         `json:"steps"` // instantané au démarrage : une modification du playbook n'affecte pas les runs en cours
	CurrentStep  int            `json:"current_step"`
	Status       RunStatus      `json:"status"`
	Log          []LogEntry     `json:"log"`
	Context      map[string]any `json:"context,omitempty"` // détail transmis à chaque étape action/condition
	StartedAt    time.Time      `json:"started_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
	FinishedAt   *time.Time     `json:"finished_at,omitempty"`
}
