// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/alerting"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

func trafficMsg(node string, alerts ...edgeWS.TrafficAlertPayload) edgeWS.TrafficDeviationPayload {
	return edgeWS.TrafficDeviationPayload{NodeName: node, Alerts: alerts}
}

func TestTrafficAlertFiresOnceThenOnEscalationThenAgain(t *testing.T) {
	seen := map[trafficAlertKey]trafficAlertSeen{}
	t0 := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	warn := edgeWS.TrafficAlertPayload{Route: "app.example.fr", Level: "warning", Since: t0, RPS: 240.04, Expected: 12.4}

	ev := trafficDeviationEvents(trafficMsg("paris", warn), seen)
	if len(ev) != 1 || ev[0].Trigger != alerting.TriggerTrafficDeviation || ev[0].Severity != alerting.SevWarning || ev[0].NodeName != "paris" || ev[0].Domain != "app.example.fr" {
		t.Fatalf("première alerte : %+v", ev)
	}
	if ev[0].Detail["rps"] != 240.0 || ev[0].Detail["level"] != "warning" {
		t.Fatalf("détail : %+v", ev[0].Detail)
	}
	if got := trafficDeviationEvents(trafficMsg("paris", warn), seen); len(got) != 0 {
		t.Fatalf("la même alerte redite chaque minute ne doit pas re-alerter : %+v", got)
	}

	probable := warn
	probable.Level, probable.Natures = "probable", []string{"distinct_ips", "errors"}
	ev = trafficDeviationEvents(trafficMsg("paris", probable), seen)
	if len(ev) != 1 || ev[0].Severity != alerting.SevCritical || ev[0].Detail["natures"] != "distinct_ips, errors" {
		t.Fatalf("l'aggravation doit alerter, en critique : %+v", ev)
	}
	if got := trafficDeviationEvents(trafficMsg("paris", warn), seen); len(got) != 0 {
		t.Fatalf("une redescente à l'avertissement n'alerte pas : %+v", got)
	}

	trafficDeviationEvents(trafficMsg("paris"), seen)
	if len(seen) != 0 {
		t.Fatalf("alerte finie : oubliée, %+v", seen)
	}
	again := warn
	again.Since = t0.Add(time.Hour)
	if ev = trafficDeviationEvents(trafficMsg("paris", again), seen); len(ev) != 1 {
		t.Fatalf("une nouvelle alerte après la fin doit repartir : %+v", ev)
	}
}

func TestTrafficAlertsAreKeptPerGateway(t *testing.T) {
	seen := map[trafficAlertKey]trafficAlertSeen{}
	t0 := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	a := edgeWS.TrafficAlertPayload{Route: "app.example.fr", Level: "warning", Since: t0}
	if len(trafficDeviationEvents(trafficMsg("paris", a), seen)) != 1 || len(trafficDeviationEvents(trafficMsg("lyon", a), seen)) != 1 {
		t.Fatal("chaque passerelle a ses propres alertes, même pour une route du même nom")
	}
	trafficDeviationEvents(trafficMsg("lyon"), seen)
	if len(trafficDeviationEvents(trafficMsg("paris", a), seen)) != 0 {
		t.Fatal("la fin des alertes de lyon ne doit pas effacer celles de paris")
	}
}

func TestTrafficAlertFiresAgainWhenTheRouteGetsHardened(t *testing.T) {
	seen := map[trafficAlertKey]trafficAlertSeen{}
	t0 := time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)
	a := edgeWS.TrafficAlertPayload{Route: "app.example.fr", Level: "probable", Since: t0}
	if len(trafficDeviationEvents(trafficMsg("paris", a), seen)) != 1 {
		t.Fatal("première alerte")
	}
	a.Hardened = true
	ev := trafficDeviationEvents(trafficMsg("paris", a), seen)
	if len(ev) != 1 || ev[0].Detail["hardened"] != true {
		t.Fatalf("le durcissement de la route doit être signalé : %+v", ev)
	}
	if len(trafficDeviationEvents(trafficMsg("paris", a), seen)) != 0 {
		t.Fatal("pas de répétition ensuite")
	}
}
