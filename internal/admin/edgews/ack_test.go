// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/alerting"
)

func TestLogBufferEventThresholdsAndReminders(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	alerted := map[string]time.Time{}
	if ev := logBufferEvent("gw", true, 10, 30, alerted, now); ev != nil {
		t.Fatalf("alerte à 10 jours sur 30 : %+v", ev)
	}
	if ev := logBufferEvent("gw", false, 29, 30, alerted, now); ev != nil {
		t.Fatalf("alerte sans tampon actif : %+v", ev)
	}
	ev := logBufferEvent("gw", true, 24, 30, alerted, now)
	if ev == nil || ev.Severity != alerting.SevWarning || ev.Trigger != alerting.TriggerLogBufferRisk {
		t.Fatalf("à 80 %% de la borne : %+v", ev)
	}
	// Pas de rappel avant l'intervalle, puis rappel, critique à 90 %.
	if again := logBufferEvent("gw", true, 24, 30, alerted, now.Add(time.Hour)); again != nil {
		t.Fatalf("rappel avant l'intervalle : %+v", again)
	}
	crit := logBufferEvent("gw", true, 27, 30, alerted, now.Add(7*time.Hour))
	if crit == nil || crit.Severity != alerting.SevCritical {
		t.Fatalf("à 90 %% de la borne : %+v", crit)
	}
	// Revenue à l'heure : oubliée, la prochaine dérive alerte tout de suite.
	if ev := logBufferEvent("gw", true, 2, 30, alerted, now.Add(8*time.Hour)); ev != nil {
		t.Fatalf("alerte alors que tout est acquitté : %+v", ev)
	}
	if ev := logBufferEvent("gw", true, 25, 30, alerted, now.Add(9*time.Hour)); ev == nil {
		t.Fatal("pas d'alerte immédiate après un retour à l'heure")
	}
}
