// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/db"
)

func TestAlertEventsList(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	d.Exec(`INSERT INTO alert_rules (id, name, scope, triggers, channels, cooldown_sec, priority, enabled) VALUES ('r1','SLO','{}','["slo_burn"]','[]',300,1,1)`)
	ins := func(trigger, detail, age string) {
		if _, err := d.Exec(`INSERT INTO alert_events (rule_id, trigger, detail, channels, message_title, message_body, priority, fired_at)
			VALUES ('r1',?,?,'[]','titre','corps',1,datetime('now',?))`, trigger, detail, age); err != nil {
			t.Fatal(err)
		}
	}
	ins("slo_burn", `{"node_name":"lyon-03","state":"critical"}`, "-1 hours")
	ins("slo_burn", `{"node_name":"paris-01"}`, "-2 hours")
	ins("high_latency", `{"domain":"a.fr"}`, "-3 hours")
	ins("slo_burn", `{"node_name":"lyon-03"}`, "-10 days")

	h := &AlertEventsHandler{DB: d}
	get := func(url string) []map[string]any {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, url, nil))
		var out []map[string]any
		if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if all := get("/api/v1/alert-events"); len(all) != 4 || all[0]["rule_name"] != "SLO" {
		t.Fatalf("4 événements attendus, plus récent d'abord : %+v", all)
	}
	if week := get("/api/v1/alert-events?days=7"); len(week) != 3 {
		t.Errorf("filtre de période : %d événements", len(week))
	}
	if lyon := get("/api/v1/alert-events?node=lyon-03&days=7"); len(lyon) != 1 {
		t.Errorf("filtre passerelle : %+v", lyon)
	}
	if lat := get("/api/v1/alert-events?trigger=high_latency"); len(lat) != 1 {
		t.Errorf("filtre déclencheur : %+v", lat)
	}
}
