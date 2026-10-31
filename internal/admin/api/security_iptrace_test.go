// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/edge/logapi/logapitest"
	"github.com/vincamok/goproxify/internal/edge/logstore"
	"github.com/vincamok/goproxify/internal/sqltime"
)

func TestIPTraceFollowsACIDRAcrossSources(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	gw := logapitest.New(t, "gw-a")
	if err := gw.Register(db); err != nil {
		t.Fatal(err)
	}
	src := &prismedge.Source{DB: db}
	logRow := func(at time.Time, ip string, status int, waf string) {
		e := logstore.Entry{Ts: at, IP: ip, Domain: "a.test", Method: "GET", Path: "/admin", Status: status}
		if waf != "" {
			e.WAFMatches = []string{waf}
		}
		gw.Add(e)
	}
	// Deux épisodes à 40 jours d'écart, deux IP du /24, plus du bruit hors cible.
	logRow(ago(41*24*time.Hour), "203.0.113.5", 404, "")
	logRow(ago(41*24*time.Hour-time.Minute), "203.0.113.6", 403, "sqli")
	logRow(ago(2*time.Hour), "203.0.113.5", 200, "")
	logRow(ago(2*time.Hour), "203.0.114.5", 200, "")
	logRow(ago(2*time.Hour), "198.51.100.1", 200, "")
	exec(`INSERT INTO security_ban_history (ip, action, reason, source, user_agent, created_at) VALUES ('203.0.113.5', 'banned', 'scan', 'fail2ban', 'sqlmap/1.7', ?)`, sqltime.Format(ago(41*24*time.Hour)))
	exec(`INSERT INTO security_ban_history (ip, action, reason, source, created_at) VALUES ('203.0.113.0/24', 'unbanned', '', 'native', ?)`, sqltime.Format(ago(40*24*time.Hour)))
	exec(`INSERT INTO security_ban_history (ip, action, source, created_at) VALUES ('198.51.100.1', 'banned', 'native', ?)`, sqltime.Format(ago(time.Hour)))
	exec(`INSERT INTO security_threats (ip, scenario, origin, occurrences, created_at, last_seen_at) VALUES ('203.0.113.6', 'http-probing', 'crowdsec', 3, ?, ?)`, sqltime.Format(ago(41*24*time.Hour)), sqltime.Format(ago(41*24*time.Hour)))
	exec(`INSERT INTO security_bans (id, ip, reason, source, user_agent) VALUES ('b1', '203.0.113.5', 'scan', 'native', 'sqlmap/1.7')`)
	exec(`INSERT INTO ip_profiles (id, name, profile_type, mode, cidrs, enabled) VALUES ('p1', 'Scanners', 'custom', 'deny', '["203.0.113.0/25"]', 1)`)

	get := func(path string) map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		(&SecurityHandler{DB: db, Edge: src}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s : %d %s", path, rec.Code, rec.Body)
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// Défaut : 30 jours — l'épisode d'il y a 41 jours n'y est pas.
	short := get("/api/v1/security/ip-trace?target=203.0.113.0/24")
	if short["kind"] != "cidr" || short["target"] != "203.0.113.0/24" {
		t.Errorf("cible : %v / %v", short["kind"], short["target"])
	}
	if n := short["summary"].(map[string]any)["requests"].(float64); n != 1 {
		t.Errorf("30 jours : %v requêtes, attendu 1", n)
	}

	from60 := ago(60*24*time.Hour).Format("2006-01-02")
	res := get("/api/v1/security/ip-trace?order=asc&target=203.0.113.0/24&from=" + from60)
	sum := res["summary"].(map[string]any)
	if sum["requests"].(float64) != 3 || sum["blocked"].(float64) != 1 || sum["ip_count"].(float64) != 2 || sum["episodes"].(float64) != 2 {
		t.Errorf("synthèse : %v", sum)
	}
	if sum["bans"].(float64) != 1 || sum["unbans"].(float64) != 1 || sum["threats"].(float64) != 1 {
		t.Errorf("bans/débans/menaces : %v", sum)
	}
	if len(sum["active_bans"].([]any)) != 1 || len(sum["profiles"].([]any)) != 1 {
		t.Errorf("état actuel : bans %v, profils %v", sum["active_bans"], sum["profiles"])
	}
	var kinds []string
	var last time.Time
	for _, s := range res["steps"].([]any) {
		step := s.(map[string]any)
		kinds = append(kinds, step["kind"].(string))
		ts, _ := time.Parse(time.RFC3339Nano, step["ts"].(string))
		if ts.Before(last) {
			t.Errorf("étapes non chronologiques : %v", step)
		}
		last = ts
	}
	// activity (41 j) + ban + threat au même instant, unban (40 j), activity (2 h) — le ban de
	// 198.51.100.1 est hors cible.
	if len(kinds) != 5 {
		t.Fatalf("étapes : %v", kinds)
	}
	if kinds[len(kinds)-1] != "activity" || kinds[len(kinds)-2] != "unban" {
		t.Errorf("ordre des étapes : %v", kinds)
	}

	// Par défaut, le plus récent d'abord ; le ban et le ban en cours disent quel User-Agent les a provoqués.
	newest := get("/api/v1/security/ip-trace?target=203.0.113.0/24&from=" + from60)
	steps := newest["steps"].([]any)
	if steps[0].(map[string]any)["kind"] != "activity" || steps[len(steps)-1].(map[string]any)["kind"] == "unban" {
		t.Errorf("ordre par défaut : le plus récent d'abord, obtenu %v", steps[0])
	}
	var banUA string
	for _, s := range steps {
		if step := s.(map[string]any); step["kind"] == "ban" {
			banUA, _ = step["user_agent"].(string)
		}
	}
	if banUA != "sqlmap/1.7" {
		t.Errorf("User-Agent du ban dans la chronologie : %q", banUA)
	}
	if ab := newest["summary"].(map[string]any)["active_bans"].([]any); ab[0].(map[string]any)["user_agent"] != "sqlmap/1.7" {
		t.Errorf("User-Agent du ban en cours : %v", ab[0])
	}

	// Une IP seule ne remonte pas le reste du /24, mais voit le ban posé sur le /24.
	one := get("/api/v1/security/ip-trace?target=203.0.113.5&from=" + ago(60*24*time.Hour).Format("2006-01-02"))
	if one["kind"] != "ip" || one["summary"].(map[string]any)["requests"].(float64) != 2 {
		t.Errorf("IP seule : %v", one["summary"])
	}
	if one["summary"].(map[string]any)["unbans"].(float64) != 1 {
		t.Error("le déban du /24 doit apparaître dans le parcours d'une IP qu'il contient")
	}

	// Pagination
	p := get("/api/v1/security/ip-trace?target=203.0.113.0/24&from=" + ago(60*24*time.Hour).Format("2006-01-02") + "&limit=2&offset=1")
	if len(p["steps"].([]any)) != 2 || p["total_steps"].(float64) != 5 || p["has_more"] != true {
		t.Errorf("pagination : %v", p)
	}

	rec := httptest.NewRecorder()
	(&SecurityHandler{DB: db}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/security/ip-trace?target=nope", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("cible invalide : %d", rec.Code)
	}
}

// Les listes vides doivent sortir en [] : la page appelle .map dessus et plante sur null.
func TestIPTraceEmptyListsAreNeverNull(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rec := httptest.NewRecorder()
	(&SecurityHandler{DB: db}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/security/ip-trace?target=198.51.100.9", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var res struct {
		Summary map[string]json.RawMessage `json:"summary"`
		Steps   json.RawMessage            `json:"steps"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"active_bans", "profiles", "days", "top_ips", "top_domains", "top_paths", "waf_matches", "threat_signals", "countries", "statuses"} {
		if string(res.Summary[k]) == "null" || res.Summary[k] == nil {
			t.Errorf("summary.%s = %s", k, res.Summary[k])
		}
	}
	if string(res.Steps) != "[]" {
		t.Errorf("steps = %s", res.Steps)
	}
}
