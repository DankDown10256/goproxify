// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/alerting"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

func sg(conf, method, path string) edgeWS.SurfaceSuggestionPayload {
	return edgeWS.SurfaceSuggestionPayload{Key: "unknown_path " + method + " " + path, Method: method, Path: path, Confidence: conf}
}

func proxy(route, host string, s ...edgeWS.SurfaceSuggestionPayload) edgeWS.SurfaceProxyPayload {
	return edgeWS.SurfaceProxyPayload{Route: route, Host: host, Suggestions: s}
}

func state(node string, px ...edgeWS.SurfaceProxyPayload) map[string]map[string]edgeWS.SurfaceProxyPayload {
	m := map[string]edgeWS.SurfaceProxyPayload{}
	for _, p := range px {
		m[p.Route] = p
	}
	return map[string]map[string]edgeWS.SurfaceProxyPayload{node: m}
}

func TestSurfaceAlertFiresOncePerNewHighSuggestion(t *testing.T) {
	alerted := map[string]time.Time{}
	now := time.Now()
	by := state("gw-a", proxy("p1", "app.test", sg("high", "GET", "/nouveau/{int}"), sg("low", "GET", "/rapports/{int}")))
	evs := surfaceSuggestionEvents("gw-a", by, alerted, now)
	if len(evs) != 1 {
		t.Fatalf("%d alerte(s), attendu 1", len(evs))
	}
	ev := evs[0]
	if ev.Trigger != alerting.TriggerSurfaceSuggestion || ev.Severity != alerting.SevInfo || ev.Domain != "app.test" || ev.NodeName != "gw-a" {
		t.Errorf("événement : %+v", ev)
	}
	if ev.Detail["count"] != 1 || ev.Detail["low_confidence"] != 1 || ev.Detail["suggestions"] != "GET /nouveau/{int}" || ev.Detail["proxy"] != "p1" {
		t.Errorf("détail : %v", ev.Detail)
	}

	// Le même état envoyé de nouveau (toutes les 5 minutes) ne re-déclenche rien.
	if evs := surfaceSuggestionEvents("gw-a", by, alerted, now.Add(5*time.Minute)); len(evs) != 0 {
		t.Errorf("répétition : %d alerte(s)", len(evs))
	}

	// Une nouvelle suggestion alerte, seule.
	by = state("gw-a", proxy("p1", "app.test", sg("high", "GET", "/nouveau/{int}"), sg("high", "POST", "/autre")))
	evs = surfaceSuggestionEvents("gw-a", by, alerted, now.Add(10*time.Minute))
	if len(evs) != 1 || evs[0].Detail["count"] != 1 || evs[0].Detail["suggestions"] != "POST /autre" {
		t.Fatalf("nouvelle suggestion : %+v", evs)
	}
}

func TestSurfaceAlertForgetsResolvedSuggestions(t *testing.T) {
	alerted := map[string]time.Time{}
	now := time.Now()
	with := state("gw-a", proxy("p1", "app.test", sg("high", "GET", "/nouveau/{int}")))
	surfaceSuggestionEvents("gw-a", with, alerted, now)
	// Acceptée : le proxy n'a plus de suggestion et disparaît de l'état.
	surfaceSuggestionEvents("gw-a", state("gw-a"), alerted, now.Add(time.Hour))
	if len(alerted) != 0 {
		t.Fatalf("une suggestion réglée doit être oubliée : %v", alerted)
	}
	// Si elle revient, elle alerte de nouveau.
	if evs := surfaceSuggestionEvents("gw-a", with, alerted, now.Add(2*time.Hour)); len(evs) != 1 {
		t.Errorf("retour de la suggestion : %d alerte(s)", len(evs))
	}
}

func TestSurfaceAlertLowConfidenceAloneStaysSilent(t *testing.T) {
	alerted := map[string]time.Time{}
	by := state("gw-a", proxy("p1", "app.test", sg("low", "GET", "/rapports/{int}")))
	if evs := surfaceSuggestionEvents("gw-a", by, alerted, time.Now()); len(evs) != 0 {
		t.Errorf("une suggestion à examiner ne réveille personne : %+v", evs)
	}
	if len(alerted) != 0 {
		t.Errorf("rien à retenir : %v", alerted)
	}
}

func TestSurfaceAlertGroupMembersDoNotAlertTwice(t *testing.T) {
	alerted := map[string]time.Time{}
	now := time.Now()
	s := proxy("p1", "app.test", sg("high", "GET", "/nouveau/{int}"))
	by := state("gw-a", s)
	if evs := surfaceSuggestionEvents("gw-a", by, alerted, now); len(evs) != 1 {
		t.Fatalf("première passerelle : %d", len(evs))
	}
	// Le pair du groupe rend le même profil fusionné : même suggestion, pas de seconde alerte.
	by["gw-b"] = map[string]edgeWS.SurfaceProxyPayload{"p1": s}
	if evs := surfaceSuggestionEvents("gw-b", by, alerted, now.Add(time.Minute)); len(evs) != 0 {
		t.Errorf("le pair a alerté une seconde fois : %+v", evs)
	}
	// Tant qu'un membre la signale, elle n'est pas oubliée.
	by["gw-a"] = map[string]edgeWS.SurfaceProxyPayload{}
	surfaceSuggestionEvents("gw-a", by, alerted, now.Add(2*time.Minute))
	if len(alerted) != 1 {
		t.Errorf("la suggestion existe encore chez le pair : %v", alerted)
	}
}

func TestSurfaceAlertListsAtMostFiveAndOneEventPerProxy(t *testing.T) {
	alerted := map[string]time.Time{}
	var many []edgeWS.SurfaceSuggestionPayload
	for i := 0; i < 8; i++ {
		many = append(many, sg("high", "GET", fmt.Sprintf("/p%d", i)))
	}
	by := state("gw-a", proxy("p1", "a.test", many...), proxy("p2", "b.test", sg("high", "GET", "/x")))
	evs := surfaceSuggestionEvents("gw-a", by, alerted, time.Now())
	if len(evs) != 2 {
		t.Fatalf("une alerte par proxy : %d", len(evs))
	}
	if evs[0].Detail["count"] != 8 || !strings.Contains(evs[0].Detail["suggestions"].(string), "(+3)") || strings.Count(evs[0].Detail["suggestions"].(string), "GET /p") != 5 {
		t.Errorf("liste tronquée : %v", evs[0].Detail["suggestions"])
	}
}

func TestHandleSurfaceSuggestionsKeepsGatewayStateAndIgnoresGarbage(t *testing.T) {
	m := &Manager{} // sans moteur d'alertes : l'état est tenu, rien ne doit planter
	raw, _ := json.Marshal(edgeWS.SurfaceSuggestionsPayload{NodeName: "gw-a", Proxies: []edgeWS.SurfaceProxyPayload{proxy("p1", "app.test", sg("high", "GET", "/x"))}})
	m.handleSurfaceSuggestions(raw)
	m.handleSurfaceSuggestions(json.RawMessage(`{"node_name":""}`))
	m.handleSurfaceSuggestions(json.RawMessage(`pas du json`))
	if len(m.surfaceAlerts.byNode["gw-a"]) != 1 {
		t.Errorf("l'état de la passerelle doit être gardé : %v", m.surfaceAlerts.byNode)
	}
}
