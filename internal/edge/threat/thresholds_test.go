// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
)

func thresholdCount(result string) float64 {
	return testutil.ToFloat64(threatThresholdTotal.WithLabelValues(result))
}

// obsReq : une requête portant une observation du WAF, comme celle que le dispatch fabrique.
func obsReq(method, path string, hits int, blocked bool) *http.Request {
	r := httptest.NewRequest(method, path, nil)
	ctx, obs := behavior.WithObservation(context.Background())
	if hits > 0 {
		obs.NoteWAFScore(hits * 5)
		obs.NoteWAFHits(behavior.WAFHit{RuleID: 942100})
	}
	if blocked {
		obs.NoteWAFBlocked()
	}
	return r.WithContext(ctx)
}

func observe(e *Engine, ip string, r *http.Request, status int) { e.Observe(r, ip, "app.test", status) }

func TestBucketWindowSlides(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	b := &bucketWindow{window: 10 * time.Minute}
	for i := 0; i < 5; i++ {
		b.add(now)
	}
	if got := b.add(now.Add(5 * time.Minute)); got != 6 {
		t.Fatalf("à mi-fenêtre les 5 premiers comptent encore : %d, attendu 6", got)
	}
	if got := b.add(now.Add(11 * time.Minute)); got != 2 {
		// 5 sortis de la fenêtre, 1 de 5 min encore dedans, 1 nouveau
		t.Fatalf("après la fenêtre, seuls les récents comptent : %d, attendu 2", got)
	}
	if got := b.add(now.Add(2 * time.Hour)); got != 1 {
		t.Fatalf("après un long silence, tout est oublié : %d, attendu 1", got)
	}
}

func thresholdEngine(t *testing.T, tc ThresholdsConfig, extra ...func(*Config)) (*Engine, *time.Time, *[]explained) {
	t.Helper()
	cfg := Config{Thresholds: tc}
	for _, f := range extra {
		f(&cfg)
	}
	return explainEngine(t, cfg)
}

func TestProvidedAuthFailBansAfterTenFailuresOnALoginRoute(t *testing.T) {
	e, now, bans := thresholdEngine(t, ThresholdsConfig{Mode: ThresholdBlock})
	for i := 0; i < 9; i++ {
		*now = now.Add(time.Second)
		observe(e, "198.51.100.1", obsReq("POST", "/login", 0, false), 401)
	}
	if len(*bans) != 0 {
		t.Fatalf("neuf échecs sous le seuil : %+v", *bans)
	}
	observe(e, "198.51.100.1", obsReq("POST", "/login", 0, false), 403)
	if len(*bans) != 1 || (*bans)[0].reason != "threat: seuil auth-fail" {
		t.Fatalf("dix échecs en 5 minutes : %+v", *bans)
	}
	s := (*bans)[0].signals
	if len(s) != 1 || s[0].Name != "threshold:auth-fail" || s[0].Points != 10 || !strings.Contains(s[0].Value, "10 événements en 5m0s") {
		t.Fatalf("le ban explique le Seuil, le nombre d'événements et la fenêtre : %+v", s)
	}
}

func TestProvidedAuthFailIgnoresWhatIsNotALoginFailure(t *testing.T) {
	e, now, bans := thresholdEngine(t, ThresholdsConfig{Mode: ThresholdBlock})
	for i := 0; i < 30; i++ {
		*now = now.Add(time.Second)
		observe(e, "198.51.100.1", obsReq("GET", "/page", 0, false), 401)   // pas un point d'entrée de connexion
		observe(e, "198.51.100.1", obsReq("POST", "/login", 0, false), 200) // une connexion réussie
		observe(e, "198.51.100.1", obsReq("POST", "/login", 0, false), 404)
		observe(e, "198.51.100.1", obsReq("POST", "/login", 0, true), 403) // refus du WAF : le WAF a son propre barème
	}
	if len(*bans) != 0 {
		t.Fatalf("ni un autre chemin, ni un succès, ni un 404, ni un refus du WAF : %+v", *bans)
	}
}

func TestProvidedAuthFailWindowForgetsOldFailures(t *testing.T) {
	e, now, bans := thresholdEngine(t, ThresholdsConfig{Mode: ThresholdBlock})
	for i := 0; i < 9; i++ {
		observe(e, "198.51.100.1", obsReq("POST", "/login", 0, false), 401)
	}
	*now = now.Add(20 * time.Minute)
	for i := 0; i < 9; i++ {
		observe(e, "198.51.100.1", obsReq("POST", "/login", 0, false), 401)
	}
	if len(*bans) != 0 {
		t.Fatalf("deux séries de neuf, séparées de vingt minutes : %+v", *bans)
	}
}

func TestProvidedWAFRepeat(t *testing.T) {
	e, _, bans := thresholdEngine(t, ThresholdsConfig{Mode: ThresholdBlock})
	for i := 0; i < 4; i++ {
		observe(e, "198.51.100.2", obsReq("GET", fmt.Sprintf("/p%d", i), 1, false), 200)
	}
	observe(e, "198.51.100.2", obsReq("GET", "/propre", 0, false), 200) // sans règle du WAF : ne compte pas
	if len(*bans) != 0 {
		t.Fatalf("quatre requêtes marquées : %+v", *bans)
	}
	observe(e, "198.51.100.2", obsReq("GET", "/p5", 1, true), 403)
	if len(*bans) != 1 || (*bans)[0].reason != "threat: seuil waf-repeat" {
		t.Fatalf("la cinquième requête marquée par le WAF : %+v", *bans)
	}
}

func TestThresholdsDetectCountsWithoutBanning(t *testing.T) {
	e, _, bans := thresholdEngine(t, ThresholdsConfig{Mode: ThresholdDetect})
	before := thresholdCount("shadow")
	for i := 0; i < 25; i++ {
		observe(e, "198.51.100.1", obsReq("POST", "/login", 0, false), 401)
	}
	if len(*bans) != 0 || thresholdCount("shadow") != before+2 {
		t.Fatalf("en detect : deux dépassements comptés, aucun ban (%d bans)", len(*bans))
	}
}

func TestThresholdsOffByDefault(t *testing.T) {
	e, _, bans := thresholdEngine(t, ThresholdsConfig{})
	for i := 0; i < 50; i++ {
		observe(e, "198.51.100.1", obsReq("POST", "/login", 0, false), 401)
	}
	if len(*bans) != 0 || len(e.ThresholdNames()) != 0 {
		t.Fatal("aucun Seuil par défaut")
	}
}

func TestCustomThresholdFiltersAndKeysPerIP(t *testing.T) {
	e, _, bans := thresholdEngine(t, ThresholdsConfig{Rules: []ThresholdRule{{
		Name: "api-5xx", Mode: ThresholdBlock, Status: []string{"5xx"}, Paths: []string{"/api/"}, Methods: []string{"post"}, Hosts: []string{"APP.test"},
		Count: 3, Window: Duration{time.Minute}, Action: ThresholdBan,
	}}})
	do := func(ip, method, path string, status int, host string) {
		e.Observe(httptest.NewRequest(method, path, nil), ip, host, status)
	}
	do("198.51.100.1", "POST", "/api/x", 502, "app.test")
	do("198.51.100.1", "POST", "/api/x", 500, "app.test")
	do("198.51.100.1", "GET", "/api/x", 500, "app.test")    // mauvaise méthode
	do("198.51.100.1", "POST", "/web/x", 500, "app.test")   // mauvais chemin
	do("198.51.100.1", "POST", "/api/x", 500, "autre.test") // mauvaise route
	do("198.51.100.1", "POST", "/api/x", 404, "app.test")   // mauvais statut
	do("198.51.100.2", "POST", "/api/x", 500, "app.test")   // autre IP : son propre compteur
	if len(*bans) != 0 {
		t.Fatalf("deux événements pour 198.51.100.1, un pour .2 : %+v", *bans)
	}
	do("198.51.100.1", "POST", "/api/y", 503, "app.test")
	if len(*bans) != 1 || (*bans)[0].ip != "198.51.100.1" || (*bans)[0].reason != "threat: seuil api-5xx" {
		t.Fatalf("troisième événement de la même IP : %+v", *bans)
	}
}

func TestCustomThresholdScoreActionJoinsTheCommonNote(t *testing.T) {
	e, _, bans := thresholdEngine(t, ThresholdsConfig{Rules: []ThresholdRule{{
		Name: "lent", Mode: ThresholdBlock, Status: []string{"429"}, Count: 2, Window: Duration{time.Minute}, Action: ThresholdScore, Points: 4,
	}}}, func(c *Config) {
		c.IPScore = IPScoreConfig{Enabled: true, BanThreshold: 6, HalfLife: Duration{time.Hour}}
	})
	trip := func() {
		observe(e, "198.51.100.1", obsReq("GET", "/x", 0, false), 429)
		observe(e, "198.51.100.1", obsReq("GET", "/x", 0, false), 429)
	}
	trip()
	if len(*bans) != 0 || e.IPScore("198.51.100.1") < 3.9 {
		t.Fatalf("un dépassement verse 4 points sans bannir : score %v, bans %+v", e.IPScore("198.51.100.1"), *bans)
	}
	trip()
	if len(*bans) != 1 {
		t.Fatalf("deux dépassements franchissent le seuil de 6 : %+v", *bans)
	}
}

func TestThresholdCountersSurviveARestart(t *testing.T) {
	cfg := ThresholdsConfig{Mode: ThresholdBlock}
	e, now, _ := thresholdEngine(t, cfg)
	for i := 0; i < 7; i++ {
		observe(e, "198.51.100.1", obsReq("POST", "/login", 0, false), 401)
	}
	st := e.SnapshotState()
	if len(st.Thresholds) != 1 {
		t.Fatalf("un compteur à conserver : %+v", st.Thresholds)
	}

	e2, now2, bans2 := thresholdEngine(t, cfg)
	*now2 = *now
	e2.RestoreState(st)
	for i := 0; i < 3; i++ {
		observe(e2, "198.51.100.1", obsReq("POST", "/login", 0, false), 401)
	}
	if len(*bans2) != 1 {
		t.Fatalf("sept échecs avant le redémarrage, trois après : dix en tout, ban attendu : %+v", *bans2)
	}
}

func TestThresholdsForgetIP(t *testing.T) {
	e, _, bans := thresholdEngine(t, ThresholdsConfig{Mode: ThresholdBlock})
	for i := 0; i < 9; i++ {
		observe(e, "198.51.100.1", obsReq("POST", "/login", 0, false), 401)
	}
	e.ForgetIP("198.51.100.1")
	observe(e, "198.51.100.1", obsReq("POST", "/login", 0, false), 401)
	if len(*bans) != 0 || len(e.SnapshotState().Thresholds) != 1 {
		t.Fatalf("l'effacement RGPD remet le compteur à zéro : %+v", *bans)
	}
}

func TestThresholdStoreStaysBounded(t *testing.T) {
	e, _, _ := thresholdEngine(t, ThresholdsConfig{Mode: ThresholdBlock})
	for i := 0; i < thresholdShards*thresholdShardCap/8; i++ {
		observe(e, fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255), obsReq("POST", "/login", 0, false), 401)
	}
	total := 0
	for i := range e.thresholdCounters.shards {
		sh := &e.thresholdCounters.shards[i]
		sh.mu.Lock()
		if len(sh.m) > thresholdShardCap {
			t.Fatalf("shard %d : %d clés, plafond %d", i, len(sh.m), thresholdShardCap)
		}
		total += len(sh.m)
		sh.mu.Unlock()
	}
	if total == 0 {
		t.Fatal("des compteurs étaient attendus")
	}
}

func TestThresholdsSkipWhitelistedClients(t *testing.T) {
	e, _, bans := thresholdEngine(t, ThresholdsConfig{Mode: ThresholdBlock}, func(c *Config) {
		c.Whitelist = Whitelist{IPs: []string{"198.51.100.1"}, Paths: []string{"/login"}}
	})
	for i := 0; i < 30; i++ {
		observe(e, "198.51.100.1", obsReq("POST", "/login", 0, false), 401)
		observe(e, "198.51.100.3", obsReq("POST", "/login", 0, false), 401) // le chemin est en liste blanche
	}
	if len(*bans) != 0 {
		t.Fatalf("liste blanche d'Ephor : %+v", *bans)
	}
}

func TestValidateThresholds(t *testing.T) {
	good := ThresholdRule{Name: "mon-seuil_1", Mode: ThresholdBlock, Status: []string{"401", "5xx"}, Paths: []string{"/a"}, Methods: []string{"POST"}, WAF: "hit", Count: 5, Window: Duration{time.Minute}, Action: ThresholdBan}
	ok := Config{Thresholds: ThresholdsConfig{Mode: ThresholdDetect, Rules: []ThresholdRule{good}}}
	if err := ok.ValidateThresholds(); err != nil {
		t.Fatalf("configuration valide refusée : %v", err)
	}
	with := func(f func(*ThresholdRule)) Config {
		r := good
		f(&r)
		return Config{Thresholds: ThresholdsConfig{Rules: []ThresholdRule{r}}}
	}
	many := make([]ThresholdRule, maxThresholdRules+1)
	for i := range many {
		many[i] = good
		many[i].Name = fmt.Sprintf("r%d", i)
	}
	for what, c := range map[string]Config{
		"mode global inconnu":       {Thresholds: ThresholdsConfig{Mode: "bloque"}},
		"trop de Seuils":            {Thresholds: ThresholdsConfig{Rules: many}},
		"nom vide":                  with(func(r *ThresholdRule) { r.Name = "" }),
		"nom en majuscules":         with(func(r *ThresholdRule) { r.Name = "Mon-Seuil" }),
		"nom d'un Seuil fourni":     with(func(r *ThresholdRule) { r.Name = "auth-fail" }),
		"mode inconnu":              with(func(r *ThresholdRule) { r.Mode = "bloque" }),
		"action inconnue":           with(func(r *ThresholdRule) { r.Action = "ignorer" }),
		"score sans ip_score":       with(func(r *ThresholdRule) { r.Action = ThresholdScore }),
		"compte nul":                with(func(r *ThresholdRule) { r.Count = 0 }),
		"compte trop grand":         with(func(r *ThresholdRule) { r.Count = maxThresholdCount + 1 }),
		"fenêtre trop courte":       with(func(r *ThresholdRule) { r.Window = Duration{time.Millisecond} }),
		"fenêtre trop longue":       with(func(r *ThresholdRule) { r.Window = Duration{48 * time.Hour} }),
		"statut illisible":          with(func(r *ThresholdRule) { r.Status = []string{"abc"} }),
		"classe de statut inconnue": with(func(r *ThresholdRule) { r.Status = []string{"9xx"} }),
		"chemin sans barre":         with(func(r *ThresholdRule) { r.Paths = []string{"login"} }),
		"condition WAF inconnue":    with(func(r *ThresholdRule) { r.WAF = "!blocked" }),
		"points hors bornes":        with(func(r *ThresholdRule) { r.Points = 99 }),
	} {
		if err := c.ValidateThresholds(); err == nil {
			t.Errorf("%s : la configuration devait être refusée", what)
		}
	}
	dup := Config{Thresholds: ThresholdsConfig{Rules: []ThresholdRule{good, good}}}
	if err := dup.ValidateThresholds(); err == nil {
		t.Error("deux Seuils de même nom doivent être refusés")
	}
}
