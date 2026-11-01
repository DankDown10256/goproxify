// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/alerting"
	"github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/modules"
)

// Briques de test : une action qui note ses appels (et échoue sur demande), une condition pilotée.
var (
	recMu    sync.Mutex
	recorded []map[string]any
	condOn   = map[string]bool{}
)

func init() {
	RegisterAction(modules.Manifest{Type: "test_record", Label: "Test", Fields: []modules.Field{
		{Key: "value", Label: "Valeur", Kind: modules.KindText},
		{Key: "fail", Label: "Échouer", Kind: modules.KindBool},
		{Key: "token", Label: "Jeton", Kind: modules.KindPassword, Secret: true},
	}}, func(_ context.Context, _ *Service, c ActionCall) (map[string]any, error) {
		recMu.Lock()
		defer recMu.Unlock()
		recorded = append(recorded, c.Config)
		if f, _ := c.Config["fail"].(bool); f {
			return nil, errors.New("échec voulu")
		}
		return map[string]any{"echo": c.Config["value"]}, nil
	}, nil)
	RegisterCondition(modules.Manifest{Type: "test_cond", Label: "Test", Fields: []modules.Field{
		{Key: "name", Label: "Nom", Kind: modules.KindText},
	}}, func(_ context.Context, _ *Service, cfg map[string]any) (bool, map[string]any, error) {
		recMu.Lock()
		defer recMu.Unlock()
		name := cfgStr(cfg, "name")
		if name == "err" {
			return false, nil, errors.New("condition en erreur")
		}
		return condOn[name], map[string]any{"ip": "10.0.0." + name, "name": name}, nil
	}, nil)
}

func resetRecorded() []map[string]any {
	recMu.Lock()
	defer recMu.Unlock()
	out := recorded
	recorded = nil
	return out
}

func setCond(name string, on bool) {
	recMu.Lock()
	condOn[name] = on
	recMu.Unlock()
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type env struct {
	t      *testing.T
	s      *Service
	path   string
	clock  *clock
	events []alerting.Event
	mu     sync.Mutex
}

func newEnv(t *testing.T) *env {
	t.Helper()
	path := filepath.Join(t.TempDir(), "t.db")
	e := &env{t: t, path: path, clock: &clock{t: time.Now().UTC().Truncate(time.Second)}}
	e.open()
	resetRecorded()
	return e
}

func (e *env) open() {
	d, err := db.Open(e.path)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { d.Close() })
	e.s = New(d, slog.Default(), Deps{Emit: func(ev alerting.Event) {
		e.mu.Lock()
		e.events = append(e.events, ev)
		e.mu.Unlock()
	}}, Options{Now: e.clock.now})
}

// reopen simule un redémarrage de l'Admin : nouveau service sur la même base.
func (e *env) reopen() {
	e.s.inflight.Wait()
	e.open()
	e.s.recoverRuns()
}

func (e *env) create(f *Flow) *Flow {
	e.t.Helper()
	out, err := e.s.Create(context.Background(), f, "test")
	if err != nil {
		e.t.Fatalf("Create %s : %v", f.Name, err)
	}
	return out
}

func (e *env) run(id string, inputs map[string]any) *Run {
	e.t.Helper()
	res, err := e.s.RunNow(context.Background(), id, inputs, "alice")
	if err != nil {
		e.t.Fatalf("RunNow : %v", err)
	}
	e.s.inflight.Wait()
	return e.get(res.RunID)
}

func (e *env) get(runID string) *Run {
	e.t.Helper()
	r, err := e.s.GetRun(context.Background(), runID)
	if err != nil {
		e.t.Fatalf("GetRun : %v", err)
	}
	return r
}

func act(id, value string) Step {
	return Step{ID: id, Type: StepAction, Action: &Node{Type: "test_record", Config: map[string]any{"value": value}}}
}

func manual(name string, steps ...Step) *Flow {
	return &Flow{Name: name, Enabled: true, Trigger: Trigger{Kind: TriggerManual}, Steps: steps}
}

func TestRunActionsAndVariables(t *testing.T) {
	e := newEnv(t)
	f := e.create(&Flow{Name: "pb", Enabled: true,
		Trigger: Trigger{Kind: TriggerManual, Manual: &ManualTrigger{Inputs: []modules.Field{{Key: "ip", Label: "IP", Kind: modules.KindText, Required: true}}}},
		Steps:   []Step{act("a", "ban {{detail.ip}}"), act("b", "{{steps.a.echo}} / {{flow.name}}")}})
	r := e.run(f.ID, map[string]any{"ip": "1.2.3.4"})
	if r.Status != RunCompleted {
		t.Fatalf("statut %s (%s)", r.Status, r.Error)
	}
	got := resetRecorded()
	if len(got) != 2 || got[0]["value"] != "ban 1.2.3.4" || got[1]["value"] != "ban 1.2.3.4 / pb" {
		t.Fatalf("valeurs reçues : %v", got)
	}
	if len(r.Steps) != 2 || r.Steps[0].Status != "done" {
		t.Fatalf("journal : %+v", r.Steps)
	}
	if _, err := e.s.RunNow(context.Background(), f.ID, nil, "alice"); err == nil {
		t.Fatal("paramètre requis manquant accepté")
	}
}

func TestIfBranchesAndStopAndOnError(t *testing.T) {
	e := newEnv(t)
	setCond("on", true)
	f := e.create(manual("branches",
		Step{ID: "check", Type: StepIf, Condition: &Cond{Type: "test_cond", Config: map[string]any{"name": "on"}},
			Then: []Step{act("t1", "alors {{steps.check.ip}}")},
			Else: []Step{act("e1", "sinon")}},
		Step{ID: "f", Type: StepAction, OnError: "continue", Action: &Node{Type: "test_record", Config: map[string]any{"fail": true}}},
		act("after", "après {{steps.f.ok}}"),
		Step{ID: "end", Type: StepStop, Config: map[string]any{"status": "stopped", "reason": "fin"}},
		act("never", "jamais"),
	))
	r := e.run(f.ID, nil)
	if r.Status != RunStopped || r.Error != "fin" {
		t.Fatalf("statut %s (%s)", r.Status, r.Error)
	}
	var values []string
	for _, c := range resetRecorded() {
		values = append(values, fmt.Sprint(c["value"]))
	}
	if strings.Join(values, "|") != "alors 10.0.0.on|<nil>|après false" {
		t.Fatalf("parcours : %v", values)
	}

	g := e.create(manual("échec", Step{ID: "x", Type: StepAction, Action: &Node{Type: "test_record", Config: map[string]any{"fail": true}}}, act("y", "jamais")))
	r = e.run(g.ID, nil)
	if r.Status != RunFailed || !strings.Contains(r.Error, "échec voulu") || len(resetRecorded()) != 1 {
		t.Fatalf("échec non arrêté : %s %s", r.Status, r.Error)
	}
}

func TestWaitSurvivesRestart(t *testing.T) {
	e := newEnv(t)
	f := e.create(manual("attente", act("a", "avant"), Step{ID: "w", Type: StepWait, Config: map[string]any{"duration": "10m"}}, act("b", "après")))
	r := e.run(f.ID, nil)
	if r.Status != RunWaiting || r.ResumeAt == nil {
		t.Fatalf("pas en attente : %s", r.Status)
	}
	resetRecorded()
	e.reopen()
	e.s.resumeDue()
	e.s.inflight.Wait()
	if st := e.get(r.ID).Status; st != RunWaiting {
		t.Fatalf("reprise avant l'échéance : %s", st)
	}
	e.clock.add(11 * time.Minute)
	e.s.resumeDue()
	e.s.inflight.Wait()
	if st := e.get(r.ID).Status; st != RunCompleted {
		t.Fatalf("pas repris après redémarrage : %s", st)
	}
	if got := resetRecorded(); len(got) != 1 || got[0]["value"] != "après" {
		t.Fatalf("étapes après reprise : %v", got)
	}
}

func TestApprovalDecideAndTimeout(t *testing.T) {
	e := newEnv(t)
	f := e.create(manual("appro",
		Step{ID: "ok", Type: StepApproval, Config: map[string]any{"message": "Couper {{detail.what}} ?", "timeout": "1h", "on_timeout": "reject"}},
		act("a", "accordé par {{steps.ok.actor}}")))
	r := e.run(f.ID, map[string]any{"what": "api"})
	if r.Status != RunWaitingApproval || r.Pending == nil || r.Pending.Message != "Couper api ?" {
		t.Fatalf("approbation : %s %+v", r.Status, r.Pending)
	}
	e.mu.Lock()
	notified := len(e.events) == 1 && e.events[0].Trigger == alerting.TriggerAutomationNotify
	e.mu.Unlock()
	if !notified {
		t.Fatal("approbation sans notification")
	}
	e.reopen() // l'approbation survit au redémarrage
	if err := e.s.Decide(context.Background(), r.ID, true, "bob"); err != nil {
		t.Fatal(err)
	}
	e.s.inflight.Wait()
	if st := e.get(r.ID).Status; st != RunCompleted {
		t.Fatalf("après approbation : %s", st)
	}
	if got := resetRecorded(); len(got) != 1 || got[0]["value"] != "accordé par bob" {
		t.Fatalf("action après approbation : %v", got)
	}
	if err := e.s.Decide(context.Background(), r.ID, true, "bob"); err == nil {
		t.Fatal("seconde décision acceptée")
	}

	r = e.run(f.ID, map[string]any{"what": "x"})
	e.clock.add(2 * time.Hour)
	e.s.resumeDue()
	e.s.inflight.Wait()
	if got := e.get(r.ID); got.Status != RunRejected || len(resetRecorded()) != 0 {
		t.Fatalf("échéance : %s", got.Status)
	}
}

func TestCallWaitsForPlaybook(t *testing.T) {
	e := newEnv(t)
	child := e.create(&Flow{Name: "enfant", Enabled: true,
		Trigger: Trigger{Kind: TriggerManual, Manual: &ManualTrigger{Inputs: []modules.Field{{Key: "who", Label: "Qui", Kind: modules.KindText, Default: "défaut"}}}},
		Steps:   []Step{act("c1", "enfant {{detail.who}}")}})
	parent := e.create(manual("parent",
		Step{ID: "call", Type: StepCall, Config: map[string]any{"flow_id": child.ID, "wait": true, "inputs": map[string]any{"who": "{{detail.name}}"}}},
		act("p2", "après {{steps.call.status}}")))
	r := e.run(parent.ID, map[string]any{"name": "zoé"})
	if r.Status != RunCompleted {
		t.Fatalf("parent : %s (%s)", r.Status, r.Error)
	}
	var values []string
	for _, c := range resetRecorded() {
		values = append(values, fmt.Sprint(c["value"]))
	}
	if strings.Join(values, "|") != "enfant zoé|après completed" {
		t.Fatalf("ordre : %v", values)
	}
	// Un appel circulaire est refusé à l'enregistrement.
	if _, err := e.s.Update(context.Background(), child.ID, manual("enfant",
		Step{ID: "back", Type: StepCall, Config: map[string]any{"flow_id": parent.ID}}), "test"); err == nil {
		t.Fatal("appel vers un flux non manuel accepté")
	}
	loop := e.create(manual("boucle", act("x", "x")))
	if _, err := e.s.Update(context.Background(), loop.ID, manual("boucle",
		Step{ID: "self", Type: StepCall, Config: map[string]any{"flow_id": loop.ID}}), "test"); err == nil {
		t.Fatal("appel circulaire accepté")
	}
}

func TestInterruptedAtRestart(t *testing.T) {
	e := newEnv(t)
	f := e.create(manual("long", act("a", "a")))
	r := &Run{ID: "r1", FlowID: f.ID, FlowName: f.Name, Status: RunRunning, Cursor: "a", StartedAt: e.clock.now(),
		Context: RunContext{Detail: map[string]any{}, Steps: map[string]map[string]any{}}, definition: f.definition()}
	if err := e.s.insertRun(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	e.reopen()
	got := e.get("r1")
	if got.Status != RunInterrupted || len(resetRecorded()) != 0 {
		t.Fatalf("exécution coupée : %s (rejouée d'office ?)", got.Status)
	}
	res, err := e.s.Replay(context.Background(), "r1", "alice")
	if err != nil {
		t.Fatal(err)
	}
	e.s.inflight.Wait()
	if st := e.get(res.RunID).Status; st != RunCompleted || len(resetRecorded()) != 1 {
		t.Fatalf("rejeu : %s", st)
	}
}

func TestGuardsCooldownKeySilenceConcurrency(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	f := e.create(&Flow{Name: "par ip", Enabled: true,
		Trigger: Trigger{Kind: TriggerEvent, Event: &EventTrigger{Event: "fleet_ban"}},
		Guard:   Guard{CooldownSec: 600, CooldownKey: "{{detail.ip}}", MaxConcurrent: 5},
		Steps:   []Step{act("a", "{{detail.ip}}")}})
	for _, ip := range []string{"1.1.1.1", "1.1.1.1", "2.2.2.2"} {
		e.s.handleEvent(alerting.Event{Trigger: alerting.TriggerFleetBan, Detail: map[string]any{"ip": ip}})
	}
	e.s.inflight.Wait()
	if got := resetRecorded(); len(got) != 2 {
		t.Fatalf("délai par IP : %d exécutions, attendu 2", len(got))
	}
	e.clock.add(11 * time.Minute)
	if _, err := e.s.CreateSilence(ctx, Silence{Name: "maintenance", RuleIDs: []string{f.ID}, StartsAt: e.clock.now().Add(-time.Minute), EndsAt: e.clock.now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	e.s.handleEvent(alerting.Event{Trigger: alerting.TriggerFleetBan, Detail: map[string]any{"ip": "1.1.1.1"}})
	e.s.inflight.Wait()
	runs, _ := e.s.Runs(ctx, RunFilter{FlowID: f.ID, Status: []RunStatus{RunSilenced}})
	if len(resetRecorded()) != 0 || len(runs) != 1 {
		t.Fatalf("sourdine : %d exécutions en sourdine", len(runs))
	}

	g := e.create(manual("une à la fois", Step{ID: "w", Type: StepApproval}))
	g.Trigger, g.Guard = Trigger{Kind: TriggerEvent, Event: &EventTrigger{Event: "backend_down"}}, Guard{CooldownSec: 1}
	if _, err := e.s.Update(ctx, g.ID, g, "test"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		e.clock.add(2 * time.Second)
		e.s.handleEvent(alerting.Event{Trigger: alerting.TriggerBackendDown, Detail: map[string]any{"url": "x"}})
		e.s.inflight.Wait()
	}
	if n := e.s.activeRuns(ctx, g.ID); n != 1 {
		t.Fatalf("concurrence : %d exécutions en cours, attendu 1", n)
	}
}

func TestEventChainPreventsLoops(t *testing.T) {
	e := newEnv(t)
	f := e.create(&Flow{Name: "écho", Enabled: true,
		Trigger: Trigger{Kind: TriggerEvent, Event: &EventTrigger{Event: "automation_notify"}},
		Guard:   Guard{CooldownSec: 1},
		Steps:   []Step{{ID: "n", Type: StepAction, Action: &Node{Type: "notify", Config: map[string]any{"notify_message": "écho"}}}}})
	e.s.handleEvent(alerting.Event{Trigger: alerting.TriggerAutomationNotify, Detail: map[string]any{"flow_chain": []string{"autre"}}})
	e.s.inflight.Wait()
	e.mu.Lock()
	evs := append([]alerting.Event{}, e.events...)
	e.mu.Unlock()
	if len(evs) != 1 {
		t.Fatalf("notification attendue, %d", len(evs))
	}
	chain := chainOf(evs[0].Detail)
	if len(chain) != 2 || chain[1] != f.ID {
		t.Fatalf("chaîne : %v", chain)
	}
	e.clock.add(time.Minute)
	e.s.handleEvent(evs[0]) // l'écho de sa propre notification
	e.s.inflight.Wait()
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.events) != 1 {
		t.Fatal("le flux s'est redéclenché sur sa propre notification")
	}
}

func TestConditionTriggerAndErrorsThrottled(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	setCond("c", true)
	f := e.create(&Flow{Name: "cond", Enabled: true,
		Trigger: Trigger{Kind: TriggerCondition, Condition: &Cond{All: []Cond{
			{Type: "test_cond", Config: map[string]any{"name": "c"}},
			{Not: &Cond{Type: "test_cond", Config: map[string]any{"name": "off"}}},
		}}},
		Steps: []Step{act("a", "{{detail.ip}}")}})
	e.s.pollConditions()
	e.s.inflight.Wait()
	if got := resetRecorded(); len(got) != 1 || got[0]["value"] != "10.0.0.c" {
		t.Fatalf("condition composée : %v", got)
	}
	e.clock.add(61 * time.Second)
	e.s.pollConditions()
	e.s.inflight.Wait()
	if len(resetRecorded()) != 0 {
		t.Fatal("délai minimum par défaut ignoré")
	}
	bad := e.create(&Flow{Name: "erreur", Enabled: true,
		Trigger: Trigger{Kind: TriggerCondition, Condition: &Cond{Type: "test_cond", Config: map[string]any{"name": "err"}}},
		Steps:   []Step{act("a", "x")}})
	for i := 0; i < 3; i++ {
		e.clock.add(61 * time.Second)
		e.s.pollConditions()
	}
	runs, _ := e.s.Runs(ctx, RunFilter{FlowID: bad.ID})
	if len(runs) != 1 || runs[0].Status != RunFailed {
		t.Fatalf("erreurs de condition journalisées %d fois", len(runs))
	}
	_ = f
}

func TestSimulateHasNoSideEffects(t *testing.T) {
	e := newEnv(t)
	setCond("s", true)
	child := e.create(manual("enfant", act("c", "enfant")))
	draft := &Flow{Name: "brouillon", Enabled: true,
		Trigger: Trigger{Kind: TriggerCondition, Condition: &Cond{Type: "test_cond", Config: map[string]any{"name": "s"}}},
		Steps: []Step{
			act("a", "{{detail.ip}}"),
			{ID: "w", Type: StepWait, Config: map[string]any{"duration": "1h"}},
			{ID: "ok", Type: StepApproval},
			{ID: "call", Type: StepCall, Config: map[string]any{"flow_id": child.ID}},
		}}
	res, err := e.s.Simulate(context.Background(), draft, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Matched || len(res.Trace) != 5 || res.Trace[0].Output["value"] != "10.0.0.s" || res.Trace[4].Flow != "enfant" {
		t.Fatalf("trace : %+v", res.Trace)
	}
	runs, _ := e.s.Runs(context.Background(), RunFilter{})
	if len(resetRecorded()) != 0 || len(runs) != 0 {
		t.Fatal("la simulation a agi ou journalisé")
	}
}

func TestSecretsMaskedAndKeptByStepID(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	f := e.create(manual("secret",
		Step{ID: "x", Type: StepIf, Condition: &Cond{Type: "test_cond", Config: map[string]any{"name": "n"}},
			Then: []Step{{ID: "deep", Type: StepAction, Action: &Node{Type: "test_record", Config: map[string]any{"token": "s3cret"}}}}}))
	got, _ := e.s.Get(ctx, f.ID)
	if tok := got.Steps[0].Then[0].Action.Config["token"]; tok != modules.Masque {
		t.Fatalf("secret exposé : %v", tok)
	}
	// Étape déplacée, secret renvoyé masqué : conservé.
	moved := manual("secret", Step{ID: "deep", Type: StepAction, Action: &Node{Type: "test_record", Config: map[string]any{"token": modules.Masque, "value": "v"}}})
	if _, err := e.s.Update(ctx, f.ID, moved, "test"); err != nil {
		t.Fatal(err)
	}
	stored, _ := e.s.getFlow(ctx, f.ID)
	if tok := stored.Steps[0].Action.Config["token"]; tok != "s3cret" {
		t.Fatalf("secret perdu : %v", tok)
	}
	// Nouvelle étape avec le masque : refusée (aucune valeur à reprendre).
	fresh := manual("secret", Step{ID: "other", Type: StepAction, Action: &Node{Type: "test_record", Config: map[string]any{"token": modules.Masque}}})
	if _, err := e.s.Update(ctx, f.ID, fresh, "test"); err == nil {
		t.Fatal("secret masqué accepté sur une nouvelle étape")
	}
	data, _ := e.s.Export(ctx)
	if strings.Contains(string(data), "s3cret") {
		t.Fatal("secret dans l'export")
	}
}

func TestValidation(t *testing.T) {
	e := newEnv(t)
	deep := Step{ID: "d0", Type: StepIf, Condition: &Cond{Type: "test_cond"}}
	cur := &deep
	for i := 1; i <= maxDepth; i++ {
		cur.Then = []Step{{ID: fmt.Sprintf("d%d", i), Type: StepIf, Condition: &Cond{Type: "test_cond"}}}
		cur = &cur.Then[0]
	}
	cur.Then = []Step{act("leaf", "x")}
	for name, f := range map[string]*Flow{
		"sans nom":             manual("", act("a", "x")),
		"sans étape":           manual("x"),
		"type d'étape":         manual("x", Step{ID: "a", Type: "boom"}),
		"action inconnue":      manual("x", Step{ID: "a", Type: StepAction, Action: &Node{Type: "boom"}}),
		"id en double":         manual("x", act("a", "1"), act("a", "2")),
		"id invalide":          manual("x", act("a b", "1")),
		"variable future":      manual("x", act("a", "{{steps.b.echo}}"), act("b", "2")),
		"variable inconnue":    manual("x", act("a", "{{secret.x}}")),
		"branche hors si":      manual("x", Step{ID: "a", Type: StepWait, Config: map[string]any{"duration": "1m"}, Then: []Step{act("b", "1")}}),
		"durée":                manual("x", Step{ID: "a", Type: StepWait, Config: map[string]any{"duration": "bientôt"}}),
		"trop profond":         manual("x", deep),
		"cron":                 {Name: "x", Trigger: Trigger{Kind: TriggerSchedule, Schedule: &ScheduleTrigger{Cron: "* *"}}, Steps: []Step{act("a", "1")}},
		"événement inconnu":    {Name: "x", Trigger: Trigger{Kind: TriggerEvent, Event: &EventTrigger{Event: "boom"}}, Steps: []Step{act("a", "1")}},
		"groupe et feuille":    {Name: "x", Trigger: Trigger{Kind: TriggerCondition, Condition: &Cond{Type: "test_cond", Any: []Cond{{Type: "test_cond"}}}}, Steps: []Step{act("a", "1")}},
		"intervalle":           {Name: "x", Trigger: Trigger{Kind: TriggerCondition, IntervalSec: 5, Condition: &Cond{Type: "test_cond"}}, Steps: []Step{act("a", "1")}},
		"variable déclencheur": {Name: "x", Trigger: Trigger{Kind: TriggerCondition, Condition: &Cond{Type: "test_cond", Config: map[string]any{"name": "{{detail.ip}}"}}}, Steps: []Step{act("a", "1")}},
		"appel introuvable":    manual("x", Step{ID: "c", Type: StepCall, Config: map[string]any{"flow_id": "nope"}}),
	} {
		if _, err := e.s.Create(context.Background(), f, "test"); err == nil {
			t.Errorf("%s : accepté", name)
		} else if _, ok := err.(*ValidationError); !ok {
			t.Errorf("%s : erreur non typée %T (%v)", name, err, err)
		}
	}
	e.create(manual("unique", act("a", "1")))
	if _, err := e.s.Create(context.Background(), manual("unique", act("a", "1")), "test"); err == nil {
		t.Error("nom en double accepté")
	}
}

func TestVersionsRestore(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	f := e.create(manual("v", act("a", "un")))
	if _, err := e.s.Update(ctx, f.ID, manual("v", act("a", "deux")), "test"); err != nil {
		t.Fatal(err)
	}
	vs, _ := e.s.Versions(ctx, f.ID)
	if len(vs) != 2 || vs[0].Version != 2 {
		t.Fatalf("versions : %d", len(vs))
	}
	got, err := e.s.Restore(ctx, f.ID, 1, "test")
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != 3 || got.Steps[0].Action.Config["value"] != "un" {
		t.Fatalf("restauration : v%d %v", got.Version, got.Steps[0].Action.Config)
	}
}
