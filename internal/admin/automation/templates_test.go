// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	edgere "github.com/vincamok/goproxify/internal/edge/rulesengine"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

func TestEveryTemplateRendersAndValidates(t *testing.T) {
	e := newEnv(t)
	list, err := Templates()
	if err != nil || len(list) < 15 {
		t.Fatalf("modèles : %d, %v", len(list), err)
	}
	seen := map[string]bool{}
	for _, tpl := range list {
		if seen[tpl.ID] {
			t.Errorf("%s en double", tpl.ID)
		}
		seen[tpl.ID] = true
		if tpl.Kind == "" || tpl.Version < 1 {
			t.Errorf("%s : type ou version manquant", tpl.ID)
		}
		f, err := e.s.Install(context.Background(), tpl.ID, TemplateUpdate{Enabled: true}, "test")
		if err != nil {
			t.Errorf("%s : %v", tpl.ID, err)
			continue
		}
		if f.Origin.Kind != OriginTemplate || f.Origin.TemplateID != tpl.ID {
			t.Errorf("%s : origine %+v", tpl.ID, f.Origin)
		}
	}
}

func TestTemplateParamsDetach(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	f, err := e.s.Install(ctx, "cve-critical-autodisable", TemplateUpdate{Name: "CVE prod", Enabled: true, Params: map[string]any{"cvss": 8.5}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if v := f.Trigger.Condition.Config["cvss_threshold"]; v != 8.5 {
		t.Fatalf("paramètre non appliqué : %v", v)
	}
	if f.Placement != PlacementAdmin {
		t.Errorf("cve_critical ne tourne pas sur les passerelles : %s", f.Placement)
	}
	if _, err := e.s.Update(ctx, f.ID, manual("CVE prod", act("a", "x")), "test"); !errors.Is(err, ErrTemplateManaged) {
		t.Fatalf("modification directe d'un flux de modèle : %v", err)
	}
	if _, err := e.s.UpdateParams(ctx, f.ID, TemplateUpdate{Name: "CVE prod", Enabled: true, Params: map[string]any{"cvss": "beaucoup"}}, "test"); err == nil {
		t.Fatal("paramètre invalide accepté")
	}
	g, err := e.s.UpdateParams(ctx, f.ID, TemplateUpdate{Name: "CVE prod", Enabled: false, Params: map[string]any{"cvss": 7}}, "test")
	if err != nil {
		t.Fatal(err)
	}
	if g.Version != 2 || g.Enabled || g.Trigger.Condition.Config["cvss_threshold"] != float64(7) {
		t.Fatalf("réédition : v%d %v", g.Version, g.Trigger.Condition.Config)
	}
	d, err := e.s.Detach(ctx, f.ID, "test")
	if err != nil || d.Origin.Kind != OriginManual {
		t.Fatalf("détacher : %v %+v", err, d.Origin)
	}
	if _, err := e.s.Update(ctx, f.ID, manual("CVE prod", act("a", "x")), "test"); err != nil {
		t.Fatalf("flux détaché non modifiable : %v", err)
	}
}

func TestEdgePlacementAndRules(t *testing.T) {
	cond := func(typ string, cfg map[string]any) Trigger {
		return Trigger{Kind: TriggerCondition, Condition: &Cond{Type: typ, Config: cfg}}
	}
	ban := Step{ID: "s1", Type: StepAction, Action: &Node{Type: "ban_ip", Config: map[string]any{"ip": "{{detail.ip}}", "ban_duration": "1h"}}}
	for name, c := range map[string]struct {
		f    Flow
		want string
	}{
		"simple":            {Flow{Trigger: cond("ban_repeat", nil), Steps: []Step{ban}}, PlacementEdge},
		"forcé admin":       {Flow{Trigger: cond("ban_repeat", nil), Guard: Guard{Placement: PlacementAdmin}, Steps: []Step{ban}}, PlacementAdmin},
		"condition admin":   {Flow{Trigger: cond("node_offline", nil), Steps: []Step{ban}}, PlacementAdmin},
		"action admin":      {Flow{Trigger: cond("ban_repeat", nil), Steps: []Step{{ID: "s1", Type: StepAction, Action: &Node{Type: "run_backup"}}}}, PlacementAdmin},
		"deux étapes":       {Flow{Trigger: cond("ban_repeat", nil), Steps: []Step{ban, act("b", "x")}}, PlacementAdmin},
		"variable inconnue": {Flow{Trigger: cond("ban_repeat", nil), Steps: []Step{{ID: "s1", Type: StepAction, Action: &Node{Type: "ban_ip", Config: map[string]any{"ip": "{{detail.other}}"}}}}}, PlacementAdmin},
		"clé de délai":      {Flow{Trigger: cond("ban_repeat", nil), Guard: Guard{CooldownKey: "{{detail.ip}}"}, Steps: []Step{ban}}, PlacementAdmin},
		"composée":          {Flow{Trigger: Trigger{Kind: TriggerCondition, Condition: &Cond{Any: []Cond{{Type: "ban_repeat"}}}}, Steps: []Step{ban}}, PlacementAdmin},
		"événement":         {Flow{Trigger: Trigger{Kind: TriggerEvent, Event: &EventTrigger{Event: "fleet_ban"}}, Steps: []Step{ban}}, PlacementAdmin},
	} {
		if got, _ := placement(&c.f); got != c.want {
			t.Errorf("%s : %s, attendu %s", name, got, c.want)
		}
	}

	e := newEnv(t)
	pushes := 0
	e.s.opts.OnEdgeRulesChange = func() { pushes++ }
	f := e.create(&Flow{Name: "récidive", Enabled: true, Trigger: cond("ban_repeat", map[string]any{"repeat_count": 4, "repeat_window": "12h"}),
		Guard: Guard{CooldownSec: 120}, Steps: []Step{ban}})
	if pushes != 1 {
		t.Fatalf("changement non poussé aux passerelles (%d)", pushes)
	}
	rules, err := e.s.EdgeRules(context.Background())
	if err != nil || len(rules) != 1 {
		t.Fatalf("règles de passerelle : %v %v", rules, err)
	}
	// Le format doit être relu à l'identique par la passerelle.
	b, _ := json.Marshal(rules)
	var decoded []edgere.Rule
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	r := decoded[0]
	if r.ID != f.ID || r.Condition.Type != "ban_repeat" || r.Condition.RepeatCount != 4 || r.Condition.RepeatWindow != "12h" ||
		r.Action.Type != "ban_ip" || r.Action.BanDuration != "1h" || r.CooldownSec != 120 {
		t.Fatalf("règle traduite : %+v", r)
	}

	// L'Admin n'évalue pas un flux exécuté par les passerelles, mais journalise ce qu'elles remontent.
	e.s.pollConditions()
	runs, _ := e.s.Runs(context.Background(), RunFilter{FlowID: f.ID})
	if len(runs) != 0 {
		t.Fatal("flux de passerelle évalué par l'Admin")
	}
	e.s.RecordEdgeFired(edgews.RuleFiredPayload{NodeName: "paris-01", RuleID: f.ID, ActionType: "ban_ip", CondResult: true, ActionTaken: true, Detail: map[string]any{"ip": "9.9.9.9"}})
	runs, _ = e.s.Runs(context.Background(), RunFilter{FlowID: f.ID})
	if len(runs) != 1 || runs[0].Source != "edge:paris-01" || runs[0].Status != RunCompleted {
		t.Fatalf("remontée de passerelle : %+v", runs)
	}
}

// Une mise en sourdine part aux passerelles avec le flux qu'elle vise : la passerelle l'applique seule, et
// ce qu'elle a ignoré est journalisé « en sourdine » sans conséquence (ni ban conservé, ni notification).
func TestEdgeFlowSilence(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ban := Step{ID: "s1", Type: StepAction, Action: &Node{Type: "ban_ip", Config: map[string]any{"ban_duration": "1h"}}}
	f := e.create(&Flow{Name: "récidive", Enabled: true, Trigger: Trigger{Kind: TriggerCondition, Condition: &Cond{Type: "ban_repeat"}},
		Steps: []Step{ban}})
	other := e.create(&Flow{Name: "pic", Enabled: true, Trigger: Trigger{Kind: TriggerCondition, Condition: &Cond{Type: "ban_spike"}},
		Steps: []Step{ban}})
	pushes := 0
	e.s.opts.OnEdgeRulesChange = func() { pushes++ }

	now := e.clock.now()
	sl, err := e.s.CreateSilence(ctx, Silence{Name: "maintenance", RuleIDs: []string{f.ID}, StartsAt: now.Add(time.Hour), EndsAt: now.Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if pushes != 1 {
		t.Fatalf("mise en sourdine non poussée aux passerelles (%d)", pushes)
	}
	rules, _ := e.s.EdgeRules(ctx)
	windows := map[string][]edgere.SilenceWindow{}
	for _, r := range rules {
		windows[r.ID] = r.SilenceWindows
	}
	if w := windows[f.ID]; len(w) != 1 || !w[0].Starts.Equal(sl.StartsAt) || !w[0].Ends.Equal(sl.EndsAt) {
		t.Fatalf("fenêtre du flux visé : %+v", w)
	}
	if len(windows[other.ID]) != 0 {
		t.Fatalf("fenêtre envoyée à un flux non visé : %+v", windows[other.ID])
	}

	e.s.RecordEdgeFired(edgews.RuleFiredPayload{NodeName: "paris-01", RuleID: f.ID, ActionType: "ban_ip", CondResult: true, Silenced: true,
		Detail: map[string]any{"ip": "9.9.9.9"}})
	runs, _ := e.s.Runs(ctx, RunFilter{FlowID: f.ID})
	if len(runs) != 1 || runs[0].Status != RunSilenced || runs[0].Source != "edge:paris-01" {
		t.Fatalf("déclenchement en sourdine remonté : %+v", runs)
	}

	if err := e.s.DeleteSilence(ctx, sl.ID); err != nil {
		t.Fatal(err)
	}
	if pushes != 2 {
		t.Fatalf("suppression non poussée aux passerelles (%d)", pushes)
	}
	rules, _ = e.s.EdgeRules(ctx)
	for _, r := range rules {
		if len(r.SilenceWindows) != 0 {
			t.Fatalf("fenêtre restée après suppression : %+v", r)
		}
	}

	// Sans flux visé, la mise en sourdine couvre tous les flux ; une mise en sourdine terminée n'est plus envoyée.
	if _, err := e.s.CreateSilence(ctx, Silence{Name: "tout", StartsAt: now.Add(-3 * time.Hour), EndsAt: now.Add(-2 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.CreateSilence(ctx, Silence{Name: "tout", EndsAt: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	rules, _ = e.s.EdgeRules(ctx)
	for _, r := range rules {
		if len(r.SilenceWindows) != 1 {
			t.Fatalf("mise en sourdine globale : %+v", r)
		}
	}
}

func TestEdgeNotifyReachesChannels(t *testing.T) {
	e := newEnv(t)
	f := e.create(&Flow{Name: "silence fleet", Enabled: true,
		Trigger: Trigger{Kind: TriggerCondition, Condition: &Cond{Type: "engine_silent", Config: map[string]any{"engine_type": "fleet"}}},
		Steps: []Step{{ID: "s1", Type: StepAction, Action: &Node{Type: "notify", Config: map[string]any{
			"notify_severity": "critical", "notify_message": "{{detail.engine_type}} muet"}}}}})
	e.s.RecordEdgeFired(edgews.RuleFiredPayload{NodeName: "lyon", RuleID: f.ID, ActionType: "notify", CondResult: true, ActionTaken: true,
		Detail: map[string]any{"engine_type": "fleet"}})
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.events) != 1 || e.events[0].Detail["message"] != "fleet muet" || e.events[0].Severity != "critical" {
		t.Fatalf("notification de passerelle : %+v", e.events)
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	child := e.create(manual("enfant", act("c", "x")))
	e.create(&Flow{Name: "planifié", Enabled: true, Trigger: Trigger{Kind: TriggerSchedule, Schedule: &ScheduleTrigger{Cron: "0 3 * * *"}},
		Steps: []Step{{ID: "call", Type: StepCall, Config: map[string]any{"flow_id": child.ID}}}})
	data, err := e.s.Export(ctx)
	if err != nil {
		t.Fatal(err)
	}
	other := newEnv(t)
	sum, err := other.s.Import(ctx, data, "test")
	if err != nil || sum.FlowsCreated != 2 || sum.FlowsRejected != 0 {
		t.Fatalf("import : %+v %v", sum, err)
	}
	sum, err = other.s.Import(ctx, data, "test")
	if err != nil || sum.FlowsUpdated != 2 {
		t.Fatalf("réimport : %+v %v", sum, err)
	}
	list, _ := other.s.List(ctx, TriggerSchedule)
	if len(list) != 1 || list[0].State.NextRunAt == nil {
		t.Fatalf("planification importée : %+v", list)
	}
}

// Un seuil sur une métrique que la passerelle calcule elle-même part aux passerelles, qui l'évaluent sur
// leur propre trafic ; une métrique qui n'a de sens que pour le cluster reste sur l'Admin.
func TestMetricThresholdOnEdge(t *testing.T) {
	disable := Step{ID: "s1", Type: StepAction, Action: &Node{Type: "disable_proxy", Config: map[string]any{"proxy_id": "{{detail.proxy_id}}"}}}
	flow := func(metric string, cfg map[string]any) *Flow {
		c := map[string]any{"metric": metric, "aggregation": "avg", "window": "5m", "operator": ">", "value": 500.0, "min_samples": 2}
		for k, v := range cfg {
			c[k] = v
		}
		return &Flow{Name: "p95 " + metric, Enabled: true, Steps: []Step{disable},
			Trigger: Trigger{Kind: TriggerCondition, Condition: &Cond{Type: "metric_threshold", Config: c}}}
	}
	for name, c := range map[string]struct {
		f    *Flow
		want string
	}{
		"latence d'un proxy":       {flow("proxy.p95_ms", nil), PlacementEdge},
		"débit d'un proxy":         {flow("proxy.rps", nil), PlacementAdmin},
		"débit total":              {flow("global.rps", nil), PlacementAdmin},
		"compteur de l'Admin":      {flow("fleet.bans_total", nil), PlacementAdmin},
		"variable dans le réglage": {flow("proxy.p95_ms", map[string]any{"entity": "{{flow.name}}"}), PlacementAdmin},
	} {
		if got, why := placement(c.f); got != c.want {
			t.Errorf("%s : %s (%s), attendu %s", name, got, why, c.want)
		}
	}
	if _, why := placement(flow("proxy.rps", nil)); why == "" {
		t.Error("raison du placement sur l'Admin absente")
	}

	e := newEnv(t)
	f := e.create(flow("proxy.p95_ms", nil))
	rules, err := e.s.EdgeRules(context.Background())
	if err != nil || len(rules) != 1 {
		t.Fatalf("règles de passerelle : %v %v", rules, err)
	}
	b, _ := json.Marshal(rules)
	var decoded []edgere.Rule
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatal(err)
	}
	c := decoded[0].Condition
	if decoded[0].ID != f.ID || c.Type != edgere.CondMetricThreshold || c.Metric != "proxy.p95_ms" || c.Window != "5m" ||
		c.Value == nil || *c.Value != 500 || c.MinSamples == nil || *c.MinSamples != 2 {
		t.Fatalf("condition traduite : %+v", c)
	}

	var disabled []string
	eng := edgere.New(nopLog{}, edgere.Deps{
		QueryMetric: func(key, entity string, window time.Duration, agg string) []MetricValue {
			if key != "proxy.p95_ms" || window != 5*time.Minute || agg != "avg" {
				t.Errorf("requête : %s %s %s %s", key, entity, window, agg)
			}
			return []MetricValue{{Entity: "lent.example", Value: 900, Samples: 30}, {Entity: "ok.example", Value: 80, Samples: 30}}
		},
		DisableProxy: func(id string) error { disabled = append(disabled, id); return nil },
	})
	var logs []edgere.ExecLog
	eng.OnRuleFired = func(l edgere.ExecLog) { logs = append(logs, l) }
	eng.ReplaceRules(decoded)
	eng.Start()
	eng.Stop()
	if len(disabled) != 1 || disabled[0] != "lent.example" || len(logs) != 1 || logs[0].Detail["value"] != 900.0 {
		t.Fatalf("évaluation par la passerelle : désactivés %v, journal %+v", disabled, logs)
	}
}

type nopLog struct{}

func (nopLog) Info(string, ...any)  {}
func (nopLog) Warn(string, ...any)  {}
func (nopLog) Debug(string, ...any) {}
