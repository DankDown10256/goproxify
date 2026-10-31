// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/surface"
	"github.com/vincamok/goproxify/internal/edge/threat"
	"github.com/vincamok/goproxify/internal/edge/waf"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
)

// newSurfaceGateway construit une passerelle sans Admin qui sert un dossier statique, avec l'apprentissage de surface réglé
// par mode. Deux appels sur le même dir simulent un redémarrage.
func newSurfaceGateway(t *testing.T, dir, mode string) *Server {
	t.Helper()
	t.Setenv("GPX_SURFACE_STATE_PATH", filepath.Join(dir, "surface-state.gpx"))
	site := filepath.Join(dir, "site")
	if err := os.MkdirAll(site, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"index.html", "app.js"} {
		if err := os.WriteFile(filepath.Join(site, f), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rt := &router.Route{
		ID: "r-app", Host: "app.example.test", Type: router.RouteHTTP,
		Static:  &router.StaticConfig{Enabled: true, Root: site},
		Surface: &router.SurfaceConfig{Mode: mode},
	}
	s := newEphorGateway(t, dir, rt)
	s.behavior = behavior.NewStore(0)
	s.surface = newSurfaceCollector(s)
	return s
}

func TestSurfaceLearnsWithoutBlockingAndSurvivesRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	s := newSurfaceGateway(t, dir, surface.ModeLearn)
	for i := 0; i < 30; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i+1)
		if code := requestFrom(s, ip, "/app.js"); code != http.StatusOK {
			t.Fatalf("apprendre ne doit rien changer au trafic : /app.js a répondu %d", code)
		}
	}
	// Un scanner : 404 sur des chemins inconnus. Ni le chemin ni l'IP n'entrent dans le profil.
	for _, p := range []string{"/.env", "/wp-login.php", "/admin"} {
		if code := requestFrom(s, "192.0.2.99", p); code != http.StatusNotFound {
			t.Fatalf("%s : %d", p, code)
		}
	}

	rep, ok := s.surface.Report("r-app", surface.ModeLearn)
	if !ok {
		t.Fatal("aucun profil après 33 requêtes")
	}
	if rep.Learned != 30 || rep.Requests != 33 {
		t.Fatalf("requêtes %d, apprises %d ; attendu 33 et 30", rep.Requests, rep.Learned)
	}
	for _, ti := range rep.Templates {
		if strings.Contains(ti.Path, "env") || strings.Contains(ti.Path, "wp-login") {
			t.Errorf("le chemin d'un scanner est dans le profil : %s", ti.Path)
		}
	}

	s.saveSurfaceState()
	raw, err := os.ReadFile(surfaceStatePath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "198.51.100") || strings.Contains(string(raw), "app.js") {
		t.Error("la copie locale n'est pas chiffrée")
	}

	restarted := newSurfaceGateway(t, dir, surface.ModeLearn)
	restarted.loadSurfaceStateFromDisk()
	back, ok := restarted.surface.Report("r-app", surface.ModeLearn)
	if !ok || back.Learned != 30 || len(back.Templates) != len(rep.Templates) {
		t.Fatalf("après redémarrage sans Admin : %+v", back.Convergence)
	}
}

func TestSurfaceOffCollectsNothing(t *testing.T) {
	s := newSurfaceGateway(t, t.TempDir(), "")
	requestFrom(s, "198.51.100.1", "/app.js")
	if _, ok := s.surface.Report("r-app", surface.ModeOff); ok {
		t.Error("un proxy sans apprentissage ne doit avoir aucun profil")
	}
}

func TestSurfaceSkipsSuspiciousIPs(t *testing.T) {
	dir := t.TempDir()
	s := newSurfaceGateway(t, dir, surface.ModeLearn)
	s.threatEngine.UpdateConfig(threat.Config{Enabled: true, IPScore: threat.IPScoreConfig{Enabled: true, BanThreshold: 1000, Errors: threat.ErrorScoreConfig{Enabled: true}}})
	// Les erreurs 404 font monter la note de l'IP : ses requêtes suivantes n'enseignent plus rien.
	for i := 0; i < 20; i++ {
		requestFrom(s, "192.0.2.50", fmt.Sprintf("/absent-%d", i))
	}
	requestFrom(s, "192.0.2.50", "/app.js")
	requestFrom(s, "198.51.100.7", "/index.html")
	rep, _ := s.surface.Report("r-app", surface.ModeLearn)
	if rep.Excluded == 0 {
		t.Fatalf("aucune requête exclue : %+v", rep)
	}
	for _, ti := range rep.Templates {
		if ti.Path == "/app.js" {
			t.Errorf("/app.js a été appris d'une IP suspecte")
		}
	}
}

func TestSurfaceInternalAPI(t *testing.T) {
	s := newSurfaceGateway(t, t.TempDir(), surface.ModeLearn)
	for i := 0; i < 5; i++ {
		requestFrom(s, fmt.Sprintf("198.51.100.%d", i+1), "/index.html")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+logapi.PathSurface, s.handleSurfaceList)
	mux.HandleFunc("GET "+logapi.PathSurfaceReport, s.handleSurfaceReport)
	mux.HandleFunc("POST "+logapi.PathSurfaceReset, s.handleSurfaceReset)
	mux.HandleFunc("GET "+logapi.PathSurfaceExport, s.handleSurfaceExport)
	do := func(method, target, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, target, strings.NewReader(body)))
		return rec
	}

	var list logapi.SurfaceListResponse
	if err := json.Unmarshal(do("GET", logapi.PathSurface, "").Body.Bytes(), &list); err != nil || len(list.Proxies) != 1 {
		t.Fatalf("liste : %v %+v", err, list)
	}
	if got := list.Proxies[0]; got.Route != "r-app" || got.Host != "app.example.test" || got.Learned != 5 || got.Mode != "learn" {
		t.Errorf("résumé : %+v", got)
	}
	for _, ref := range []string{"r-app", "app.example.test"} {
		var rep surface.Report
		rec := do("GET", logapi.PathSurfaceReport+"?route="+ref, "")
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &rep) != nil || rep.Learned != 5 {
			t.Errorf("rapport par %q : %d %s", ref, rec.Code, rec.Body.String())
		}
	}
	if rec := do("GET", logapi.PathSurfaceReport, ""); rec.Code != http.StatusBadRequest {
		t.Errorf("sans route : %d", rec.Code)
	}
	if rec := do("GET", logapi.PathSurfaceExport, ""); !strings.Contains(rec.Body.String(), "r-app") {
		t.Errorf("export : %s", rec.Body.String())
	}
	var reset logapi.SurfaceResetResponse
	rec := do("POST", logapi.PathSurfaceReset, `{"route":"app.example.test"}`)
	if json.Unmarshal(rec.Body.Bytes(), &reset) != nil || !reset.Reset {
		t.Fatalf("reset : %s", rec.Body.String())
	}
	if rec := do("GET", logapi.PathSurfaceReport+"?route=r-app", ""); rec.Code != http.StatusNotFound {
		t.Errorf("après reset : %d", rec.Code)
	}
}

func TestSurfaceGroupMembersShareProfilesWithoutAdmin(t *testing.T) {
	a := newSurfaceGateway(t, t.TempDir(), surface.ModeLearn)
	b := newSurfaceGateway(t, t.TempDir(), surface.ModeLearn)
	for i := 0; i < 6; i++ {
		requestFrom(a, fmt.Sprintf("198.51.100.%d", i+1), "/app.js")
		requestFrom(b, fmt.Sprintf("203.0.113.%d", i+1), "/index.html")
	}
	srv := httptest.NewServer(http.HandlerFunc(a.handleSurfaceExport))
	defer srv.Close()
	peer := proxy.PeerInfo{Name: "a", Endpoint: srv.URL, Token: "t"}
	for i := 0; i < 3; i++ {
		b.syncSurfaceFromPeer(context.Background(), srv.Client(), peer)
	}
	rep, ok := b.surface.Report("r-app", surface.ModeLearn)
	if !ok || rep.Members != 2 || rep.Learned != 12 {
		t.Fatalf("membres %d, requêtes apprises %d ; attendu 2 et 12 (trois échanges ne comptent qu'une fois)", rep.Members, rep.Learned)
	}
	paths := map[string]bool{}
	for _, ti := range rep.Templates {
		paths[ti.Path] = true
	}
	if !paths["/app.js"] || !paths["/index.html"] {
		t.Errorf("le profil de B doit contenir les chemins vus par A et par B : %v", paths)
	}

}

func TestSurfaceProposalsAPIUsesRouteSettings(t *testing.T) {
	s := newSurfaceGateway(t, t.TempDir(), surface.ModeLearn)
	for i := 0; i < 150; i++ {
		requestFrom(s, fmt.Sprintf("198.51.100.%d", i%50+1), "/app.js")
	}
	rt, _ := s.table.ByID("r-app")
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+logapi.PathSurfaceProposals, s.handleSurfaceProposals)
	get := func(target string) (*httptest.ResponseRecorder, surface.Proposals) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		var p surface.Proposals
		_ = json.Unmarshal(rec.Body.Bytes(), &p)
		return rec, p
	}

	rec, p := get(logapi.PathSurfaceProposals + "?route=app.example.test")
	if rec.Code != http.StatusOK || p.Route != "r-app" || p.Learned != 150 {
		t.Fatalf("propositions : %d %s", rec.Code, rec.Body.String())
	}
	foundIPFilter := false
	for _, it := range p.Items {
		if it.Setting == surface.SettingIPFilter {
			foundIPFilter = true
		}
	}
	if !foundIPFilter {
		t.Errorf("un seul réseau de clients : un filtre d'IP doit être proposé : %+v", p.Items)
	}

	// Un réglage déjà posé n'est jamais remplacé.
	rt.IPFilter = &router.IPFilterConfig{Mode: "allow", CIDRs: []string{"198.51.100.0/24"}}
	_, p = get(logapi.PathSurfaceProposals + "?route=r-app")
	for _, it := range p.Items {
		if it.Setting == surface.SettingIPFilter {
			t.Error("le filtre d'IP existant ne doit pas être proposé de nouveau")
		}
	}
	if rec, _ := get(logapi.PathSurfaceProposals + "?route=inconnu"); rec.Code != http.StatusNotFound {
		t.Errorf("proxy inconnu : %d", rec.Code)
	}
	if rec, _ := get(logapi.PathSurfaceProposals); rec.Code != http.StatusBadRequest {
		t.Errorf("sans route : %d", rec.Code)
	}
}

func TestSurfaceRecordsOpenAPIViolationsAndNotesRefusedOnes(t *testing.T) {
	s := newSurfaceGateway(t, t.TempDir(), surface.ModeLearn)
	s.threatEngine.SetBehaviorStore(s.behavior)
	s.threatEngine.UpdateConfig(threat.Config{Enabled: true})
	rt, _ := s.table.ByID("r-app")
	rt.OpenAPI = &router.OpenAPIConfig{
		Enabled: true, Mode: "detect", UnknownPaths: "block",
		Spec: json.RawMessage(`{"openapi":"3.1.0","paths":{"/index.html":{"get":{"responses":{"200":{"description":"ok"}}}}}}`),
	}
	s.invalidateDispatchCache()

	// Un chemin hors de la politique que le backend sert pourtant (200) : probablement légitime, aucune note.
	for i := 0; i < 8; i++ {
		if code := requestFrom(s, fmt.Sprintf("198.51.100.%d", i+1), "/app.js"); code != http.StatusOK {
			t.Fatalf("detect ne doit rien refuser : /app.js a répondu %d", code)
		}
	}
	// Une sonde : hors de la politique et refusée par le backend (404).
	requestFrom(s, "192.0.2.77", "/wp-login.php")
	requestFrom(s, "198.51.100.1", "/index.html") // conforme

	rep, _ := s.surface.Report("r-app", surface.ModeLearn)
	byPath := map[string]surface.ViolationInfo{}
	for _, v := range rep.Violations {
		byPath[v.Path] = v
	}
	if v := byPath["/app.js"]; v.Count != 8 || v.Legit != 8 || !v.LikelyLegit || v.Reason != "unknown_path" {
		t.Errorf("/app.js : %+v", v)
	}
	if v := byPath["/wp-login.php"]; v.Count != 1 || v.Legit != 0 {
		t.Errorf("sonde : %+v", v)
	}
	if _, ok := byPath["/index.html"]; ok {
		t.Error("une requête conforme n'est pas une violation")
	}

	hasSignal := func(ip string) bool {
		for _, sg := range s.behavior.Signals(ip) {
			if sg.Name == behavior.SignalSurface {
				return true
			}
		}
		return false
	}
	if !hasSignal("192.0.2.77") {
		t.Error("la sonde refusée par le backend doit peser dans la note d'Ephor")
	}
	if hasSignal("198.51.100.3") {
		t.Error("un chemin servi (200) ne doit pas peser dans la note d'Ephor")
	}
}

func TestSurfaceOpenAPIEndpoint(t *testing.T) {
	s := newSurfaceGateway(t, t.TempDir(), surface.ModeLearn)
	for i := 0; i < 150; i++ {
		requestFrom(s, fmt.Sprintf("198.51.100.%d", i%50+1), "/app.js")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+logapi.PathSurfaceOpenAPI, s.handleSurfaceOpenAPI)
	get := func(target string) (int, surface.OpenAPIResult) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		var res surface.OpenAPIResult
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		return rec.Code, res
	}
	code, res := get(logapi.PathSurfaceOpenAPI + "?route=app.example.test")
	if code != 200 || res.Error == "" {
		t.Fatalf("un chemin vu un seul jour est à faible soutien : %d %+v", code, res)
	}
	code, res = get(logapi.PathSurfaceOpenAPI + "?route=r-app&include_low_support=1")
	if code != 200 || res.Error != "" || res.Paths != 1 || res.Replaces || !strings.Contains(string(res.Config), `"/app.js"`) {
		t.Fatalf("avec les chemins à confirmer : %d %+v", code, res)
	}

	rt, _ := s.table.ByID("r-app")
	rt.OpenAPI = &router.OpenAPIConfig{Enabled: true}
	if _, res = get(logapi.PathSurfaceOpenAPI + "?route=r-app&include_low_support=1"); !res.Replaces {
		t.Error("un contrôle openapi déjà actif doit être signalé")
	}
	if code, _ := get(logapi.PathSurfaceOpenAPI + "?route=inconnu"); code != http.StatusNotFound {
		t.Errorf("proxy inconnu : %d", code)
	}
}

func TestSurfaceBlockReasonsRefuseOnlyTheChosenViolationsEndToEnd(t *testing.T) {
	s := newSurfaceGateway(t, t.TempDir(), surface.ModeLearn)
	rt, _ := s.table.ByID("r-app")
	rt.OpenAPI = &router.OpenAPIConfig{
		Enabled: true, Mode: "detect", UnknownPaths: "block", BlockReasons: []string{"unknown_path"},
		Spec: json.RawMessage(`{"openapi":"3.1.0","paths":{"/index.html":{"get":{"responses":{"200":{"description":"ok"}}}}}}`),
	}
	s.invalidateDispatchCache()

	if code := requestFrom(s, "198.51.100.1", "/index.html"); code != http.StatusOK {
		t.Fatalf("conforme : %d", code)
	}
	if code := requestFrom(s, "198.51.100.1", "/app.js"); code != http.StatusNotFound {
		t.Fatalf("chemin hors politique, refusé par le contrôle : %d, attendu 404 (le fichier existe, le backend l'aurait servi)", code)
	}
	req := httptest.NewRequest(http.MethodPost, "http://app.example.test/index.html", nil)
	req.RemoteAddr = "198.51.100.1:40000"
	s.dispatch(httptest.NewRecorder(), req) // méthode hors politique mais non listée : comptée, pas refusée par le contrôle

	rep, _ := s.surface.Report("r-app", surface.ModeLearn)
	var blocked, total int64
	for _, c := range rep.BlockedTotals {
		blocked += c.Count
	}
	for _, c := range rep.ViolationTotals {
		total += c.Count
	}
	if blocked != 1 || total != 2 {
		t.Errorf("refusées %d sur %d violations ; attendu 1 sur 2", blocked, total)
	}
}

func TestSurfaceForgetEndpointClearsCoveredViolations(t *testing.T) {
	s := newSurfaceGateway(t, t.TempDir(), surface.ModeLearn)
	rt, _ := s.table.ByID("r-app")
	rt.OpenAPI = &router.OpenAPIConfig{
		Enabled: true, Mode: "detect", UnknownPaths: "block",
		Spec: json.RawMessage(`{"openapi":"3.1.0","paths":{"/index.html":{"get":{"responses":{"200":{"description":"ok"}}}}}}`),
	}
	s.invalidateDispatchCache()
	for i := 0; i < 5; i++ {
		requestFrom(s, fmt.Sprintf("198.51.100.%d", i+1), "/app.js")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+logapi.PathSurfaceForget, s.handleSurfaceForget)
	post := func(body string) (int, logapi.SurfaceForgetResponse) {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, logapi.PathSurfaceForget, strings.NewReader(body)))
		var res logapi.SurfaceForgetResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &res)
		return rec.Code, res
	}
	rep, _ := s.surface.Report("r-app", surface.ModeLearn)
	if len(rep.Violations) != 1 || rep.Violations[0].Path != "/app.js" {
		t.Fatalf("violation attendue avant l'oubli : %+v", rep.Violations)
	}
	code, res := post(`{"route":"app.example.test","keys":["unknown_path GET /app.js","unknown_path GET /absente"]}`)
	if code != http.StatusOK || res.Forgotten != 1 {
		t.Fatalf("oubli : %d %+v", code, res)
	}
	if rep, _ = s.surface.Report("r-app", surface.ModeLearn); len(rep.Violations) != 0 || len(rep.ViolationTotals) != 0 {
		t.Errorf("après l'oubli : %+v %v", rep.Violations, rep.ViolationTotals)
	}
	for _, bad := range []string{`{}`, `{"route":"r-app"}`, `not json`} {
		if code, _ := post(bad); code != http.StatusBadRequest {
			t.Errorf("%q : %d", bad, code)
		}
	}
}

func TestSurfaceRecordsWAFRulesTriggeredByCleanClients(t *testing.T) {
	s := newSurfaceGateway(t, t.TempDir(), surface.ModeLearn)
	s.wafEngine = waf.NewEngine(nil, s.log.Logger())
	s.threatEngine.SetBehaviorStore(s.behavior)
	rt, _ := s.table.ByID("r-app")
	rt.WAF = &router.WAFConfig{Enabled: true, Mode: "detect"}
	s.invalidateDispatchCache()

	probe := func(ip, path string) int {
		req := httptest.NewRequest(http.MethodGet, "http://app.example.test"+path, nil)
		req.RemoteAddr = ip + ":40000"
		rec := httptest.NewRecorder()
		s.dispatch(rec, req)
		return rec.Code
	}
	for i := 0; i < 4; i++ {
		for _, ip := range []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"} {
			if code := probe(ip, "/app.js?q=%3Cscript%3Ealert(1)%3C/script%3E"); code != http.StatusOK {
				t.Fatalf("en detect le WAF laisse passer : %d", code)
			}
		}
	}
	probe("198.51.100.1", "/index.html") // une requête sans règle déclenchée

	rep, _ := s.surface.Report("r-app", surface.ModeLearn)
	if len(rep.WAF) == 0 {
		t.Fatalf("aucune règle du WAF dans le profil : %+v", rep)
	}
	var xss *surface.WAFRuleInfo
	for i := range rep.WAF {
		if rep.WAF[i].Category == "xss" {
			xss = &rep.WAF[i]
			break
		}
	}
	if xss == nil || xss.Hits != 12 || xss.Clean != 12 || xss.Served != 12 || xss.Clients != 3 || len(xss.Paths) != 1 || xss.Paths[0].Name != "GET /app.js" {
		t.Fatalf("règle xss : %+v", xss)
	}
	// Les requêtes qui déclenchent une règle n'enseignent rien à la surface (leur IP n'est pas propre), seule /index.html l'a fait.
	if rep.Learned != 1 || rep.Excluded != 12 {
		t.Errorf("apprises %d, exclues %d ; attendu 1 et 12", rep.Learned, rep.Excluded)
	}

	// Une IP dont le score Ephor monte (des 404 en rafale) n'est plus ordinaire : sa règle déclenchée ne compte pas comme faux positif.
	s.threatEngine.UpdateConfig(threat.Config{Enabled: true, IPScore: threat.IPScoreConfig{Enabled: true, BanThreshold: 1000, Errors: threat.ErrorScoreConfig{Enabled: true}}})
	for i := 0; i < 20; i++ {
		probe("203.0.113.9", fmt.Sprintf("/absent-%d", i))
	}
	probe("203.0.113.9", "/app.js?q=%3Cscript%3Ealert(1)%3C/script%3E")
	rep, _ = s.surface.Report("r-app", surface.ModeLearn)
	for _, w := range rep.WAF {
		if w.Category == "xss" && (w.Hits != 13 || w.Clean != 12) {
			t.Errorf("l'IP suspecte d'Ephor ne doit pas compter comme propre : hits %d, propres %d", w.Hits, w.Clean)
		}
	}
}

func TestSurfaceWAFBlockedRequestsAreRecordedAsBlocked(t *testing.T) {
	s := newSurfaceGateway(t, t.TempDir(), surface.ModeLearn)
	s.wafEngine = waf.NewEngine(nil, s.log.Logger())
	rt, _ := s.table.ByID("r-app")
	rt.WAF = &router.WAFConfig{Enabled: true, Mode: "block"}
	s.invalidateDispatchCache()
	for i := 0; i < 3; i++ {
		if code := requestFrom(s, "198.51.100.5", "/app.js?q=%3Cscript%3Ealert(1)%3C/script%3E"); code != http.StatusForbidden {
			t.Fatalf("en block le WAF refuse : %d", code)
		}
	}
	rep, _ := s.surface.Report("r-app", surface.ModeLearn)
	for _, w := range rep.WAF {
		if w.Category == "xss" {
			if w.Blocked != 3 || w.Served != 0 {
				t.Errorf("règle refusée : %+v", w)
			}
			return
		}
	}
	t.Fatalf("règle xss absente : %+v", rep.WAF)
}

func TestSurfaceSuggestionsPayloadListsLearningProxiesWithSuggestions(t *testing.T) {
	s := newSurfaceGateway(t, t.TempDir(), surface.ModeLearn)
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	s.surface = surface.NewCollector(surface.Options{Now: func() time.Time { return now }})
	feed := func() {
		for i := 0; i < 12; i++ {
			req := httptest.NewRequest(http.MethodGet, "http://app.example.test/nouveau/1", nil)
			s.surface.Observe(surface.Observed{
				Route: "r-app", Host: "app.example.test", Request: req, Path: "/nouveau/1", IP: fmt.Sprintf("10.1.0.%d", i%6+1),
				Status: 200, Violation: "unknown_path", Clean: true,
			})
		}
	}
	feed()
	if p := s.surfaceSuggestionsPayload(); len(p.Proxies) != 0 || p.NodeName != "frontal" {
		t.Fatalf("un seul jour : %+v", p)
	}
	now = now.Add(24 * time.Hour)
	feed()
	p := s.surfaceSuggestionsPayload()
	if len(p.Proxies) != 1 || p.Proxies[0].Route != "r-app" || p.Proxies[0].Host != "app.example.test" || len(p.Proxies[0].Suggestions) != 1 {
		t.Fatalf("payload : %+v", p)
	}
	if x := p.Proxies[0].Suggestions[0]; x.Method != "GET" || x.Path != "/nouveau/{int}" || x.Confidence != "high" || x.Key != "unknown_path GET /nouveau/{int}" {
		t.Errorf("suggestion : %+v", x)
	}

	// Un proxy qui n'apprend plus n'envoie plus rien, même s'il garde un profil.
	rt, _ := s.table.ByID("r-app")
	rt.Surface = &router.SurfaceConfig{Mode: surface.ModeOff}
	if p := s.surfaceSuggestionsPayload(); len(p.Proxies) != 0 {
		t.Errorf("proxy en off : %+v", p)
	}
}

func TestSurfaceTypeSiteIsCarriedFromTheRouteConfig(t *testing.T) {
	s := newSurfaceGateway(t, t.TempDir(), surface.ModeLearn)
	rt, _ := s.table.ByID("r-app")
	rt.Surface.Type = surface.TypeSite
	for i := 0; i < 5; i++ {
		requestFrom(s, fmt.Sprintf("198.51.100.%d", i+1), "/app.js")
	}
	rep, _ := s.surface.Report("r-app", surface.ModeLearn)
	if rep.Type != surface.TypeSite {
		t.Fatalf("le type de la configuration doit atteindre le profil : %q", rep.Type)
	}
	rt.Surface.Type = ""
	requestFrom(s, "198.51.100.9", "/app.js")
	if rep, _ = s.surface.Report("r-app", surface.ModeLearn); rep.Type != "" {
		t.Errorf("retirer le type doit le retirer du profil : %q", rep.Type)
	}
	if surface.ValidateType("blog") == nil {
		t.Error("un type inconnu doit être refusé à l'enregistrement")
	}
}
