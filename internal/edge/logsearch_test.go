// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

func getJSON(t *testing.T, h http.HandlerFunc, path string, q url.Values, out any) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, path+"?"+q.Encode(), nil))
	if out != nil && rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("réponse illisible : %v : %s", err, rec.Body.String())
		}
	}
	return rec
}

func seedSearchGateway(t *testing.T) *Server {
	t.Helper()
	s := newLogGateway(t, t.TempDir(), "cle-passerelle")
	base := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 9; i++ {
		s.logStore.Add(logstore.KindAccess, logstore.Entry{
			Ts: base.Add(time.Duration(i) * time.Second), Level: "info", Component: "edge", Domain: "app.example.com",
			Method: "GET", Path: fmt.Sprintf("/p/%d", i), Status: 200, Bytes: 10, LatencyMs: 5, IP: "198.51.100.1",
			UserAgent: "curl/8", RequestID: fmt.Sprintf("req-%d", i),
		})
	}
	pseudo := logstore.Entry{Ts: base.Add(20 * time.Second), Level: "warn", Component: "edge", Domain: "app.example.com",
		Method: "GET", Path: "/secret", Status: 403, IP: "203.0.113.0", RealIP: "203.0.113.42", IPTruncated: true}
	s.logStore.Add(logstore.KindAccess, pseudo)
	s.logStore.Add(logstore.KindSystem, logstore.Entry{Ts: base.Add(10 * time.Second), Level: "error", Component: "edge", Message: "backend down"})
	s.logStore.Flush()
	return s
}

func TestLogSearchReturnsTheAdminShapeAndPagesWithACursor(t *testing.T) {
	s := seedSearchGateway(t)
	var first logapi.SearchResponse
	rec := getJSON(t, s.handleLogSearch, logapi.PathSearch, url.Values{"limit": {"4"}}, &first)
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d : %s", rec.Code, rec.Body.String())
	}
	if len(first.Entries) != 4 || !first.HasMore || first.Next == "" {
		t.Fatalf("première page : %d lignes, has_more=%v, next=%q", len(first.Entries), first.HasMore, first.Next)
	}
	top := first.Entries[0]
	if top.Path != "/secret" || top.Kind != "access" || !top.Pseudonymized || top.IP != "203.0.113.0" || !top.IPTruncated || top.ID <= 0 {
		t.Fatalf("ligne la plus récente = %+v", top)
	}
	if !strings.Contains(top.Message, "403") {
		t.Fatalf("message au format combiné absent : %q", top.Message)
	}

	// Toutes les pages : onze lignes (neuf accès, un refus pseudonymisé, un log système), chacune une fois.
	seen := map[string]bool{}
	cursor := ""
	for pages := 0; pages < 10; pages++ {
		var p logapi.SearchResponse
		getJSON(t, s.handleLogSearch, logapi.PathSearch, url.Values{"limit": {"4"}, "cursor": {cursor}}, &p)
		for _, e := range p.Entries {
			key := e.Kind + "|" + fmt.Sprint(e.ID)
			if seen[key] {
				t.Fatalf("ligne en double : %s", key)
			}
			seen[key] = true
		}
		if !p.HasMore {
			break
		}
		cursor = p.Next
	}
	if len(seen) != 11 {
		t.Fatalf("%d lignes parcourues, attendu 11", len(seen))
	}
}

func TestLogSearchFiltersAndKinds(t *testing.T) {
	s := seedSearchGateway(t)
	count := func(q url.Values) int {
		var p logapi.SearchResponse
		getJSON(t, s.handleLogSearch, logapi.PathSearch, q, &p)
		return len(p.Entries)
	}
	for name, c := range map[string]struct {
		q    url.Values
		want int
	}{
		"système seul":               {url.Values{"kind": {"system"}, "limit": {"100"}}, 1},
		"accès seuls":                {url.Values{"kind": {"access"}, "limit": {"100"}}, 10},
		"classe 4xx":                 {url.Values{"status": {"4xx"}, "limit": {"100"}}, 1},
		"IP (pseudonymisée trouvée)": {url.Values{"ip": {"203.0.113.42"}, "limit": {"100"}}, 1},
		"texte libre":                {url.Values{"search": {"backend"}, "limit": {"100"}}, 1},
		"période":                    {url.Values{"date_from": {"2026-10-21T10:00:05Z"}, "date_to": {"2026-10-21T10:00:07Z"}, "limit": {"100"}}, 3},
	} {
		if got := count(c.q); got != c.want {
			t.Errorf("%s : %d lignes, attendu %d", name, got, c.want)
		}
	}
}

func TestLogSearchRejectsBadParameters(t *testing.T) {
	s := seedSearchGateway(t)
	for name, q := range map[string]url.Values{
		"date illisible":        {"date_from": {"hier"}},
		"kind inconnu":          {"kind": {"autre"}},
		"jeton corrompu":        {"cursor": {"!!!pas-du-base64"}},
		"jeton trop long":       {"cursor": {strings.Repeat("a", 2000)}},
		"jeton de type inconnu": {"cursor": {"eyJhdXRyZSI6eyJ0cyI6IngiLCJpZCI6MX19"}}, // {"autre":{"ts":"x","id":1}}
	} {
		if rec := getJSON(t, s.handleLogSearch, logapi.PathSearch, q, nil); rec.Code != http.StatusBadRequest {
			t.Errorf("%s : code %d, attendu 400", name, rec.Code)
		}
	}
}

// Une recherche ordinaire est plafonnée à 500 lignes ; seul un export (bulk) va plus loin.
func TestLogSearchCapsThePageSizeUnlessBulk(t *testing.T) {
	s := newLogGateway(t, t.TempDir(), "cle-passerelle")
	base := time.Date(2026, 10, 21, 10, 0, 0, 0, time.UTC)
	for i := 0; i < 600; i++ {
		s.logStore.Add(logstore.KindAccess, logstore.Entry{Ts: base.Add(time.Duration(i) * time.Second), Status: 200, Path: "/x", IP: "198.51.100.1"})
	}
	s.logStore.Flush()
	var p logapi.SearchResponse
	getJSON(t, s.handleLogSearch, logapi.PathSearch, url.Values{"limit": {"100000"}}, &p)
	if len(p.Entries) != logapi.MaxLimit || !p.HasMore {
		t.Fatalf("%d lignes, attendu %d et has_more", len(p.Entries), logapi.MaxLimit)
	}
	var b logapi.SearchResponse
	getJSON(t, s.handleLogSearch, logapi.PathSearch, url.Values{"limit": {"100000"}, "bulk": {"1"}}, &b)
	if len(b.Entries) != 600 || b.HasMore {
		t.Fatalf("export : %d lignes, attendu 600 et rien après", len(b.Entries))
	}
}

func TestLogSearchGateRefusesATooBusyGateway(t *testing.T) {
	s := seedSearchGateway(t)
	g := s.searchGate()
	r1, ok1 := g.Acquire(false)
	r2, ok2 := g.Acquire(false)
	if !ok1 || !ok2 {
		t.Fatal("deux recherches simultanées doivent passer")
	}
	if rec := getJSON(t, s.handleLogSearch, logapi.PathSearch, url.Values{}, nil); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("troisième recherche : code %d, attendu 429 avec Retry-After", rec.Code)
	}
	// Un export ne gêne pas les recherches ordinaires, mais il n'y en a qu'un à la fois.
	rb, okb := g.Acquire(true)
	if !okb {
		t.Fatal("un export doit passer")
	}
	if _, ok := g.Acquire(true); ok {
		t.Fatal("un deuxième export simultané doit être refusé")
	}
	r1()
	r2()
	rb()
	if rec := getJSON(t, s.handleLogSearch, logapi.PathSearch, url.Values{}, nil); rec.Code != http.StatusOK {
		t.Fatalf("après libération : code %d", rec.Code)
	}
}

func TestLogHistogramAndFacets(t *testing.T) {
	s := seedSearchGateway(t)
	var h logapi.HistogramResponse
	getJSON(t, s.handleLogHistogram, logapi.PathHistogram, url.Values{"bucket": {"hour"}}, &h)
	if len(h.Points) != 1 || h.Points[0].Total != 11 || h.Points[0].Warn != 1 || h.Points[0].Error != 1 {
		t.Fatalf("histogramme = %+v", h)
	}
	var f logapi.FacetsResponse
	getJSON(t, s.handleLogFacets, logapi.PathFacets, url.Values{"fields": {"level,method"}}, &f)
	if f.Total != 11 || len(f.Facets["level"]) != 3 || f.Facets["method"][0].Value != "GET" {
		t.Fatalf("facettes = %+v", f)
	}
}

func TestLogRevealReturnsTheRealIPOnlyForPseudonymizedLines(t *testing.T) {
	s := seedSearchGateway(t)
	var p logapi.SearchResponse
	getJSON(t, s.handleLogSearch, logapi.PathSearch, url.Values{"limit": {"100"}}, &p)
	var pseudoID, plainID int64
	for _, e := range p.Entries {
		switch {
		case e.Pseudonymized:
			pseudoID = e.ID
		case e.Kind == "access":
			plainID = e.ID
		}
	}
	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.handleLogReveal(rec, httptest.NewRequest(http.MethodPost, logapi.PathReveal, strings.NewReader(body)))
		return rec
	}
	rec := post(fmt.Sprintf(`{"kind":"access","id":%d}`, pseudoID))
	var out logapi.RevealResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != http.StatusOK || out.IP != "203.0.113.42" {
		t.Fatalf("révélation = %d %s", rec.Code, rec.Body.String())
	}
	if rec := post(fmt.Sprintf(`{"kind":"access","id":%d}`, plainID)); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("ligne en clair : code %d, attendu 422", rec.Code)
	}
	if rec := post(`{"kind":"access","id":99999999999}`); rec.Code != http.StatusNotFound {
		t.Fatalf("ligne inconnue : code %d, attendu 404", rec.Code)
	}
	if rec := post(`{"kind":"nope","id":1}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("type inconnu : code %d, attendu 400", rec.Code)
	}
}

// Un jeton d'Agent ne peut pas lire les logs de la passerelle.
func TestAgentTokensCannotSearchTheLogs(t *testing.T) {
	for _, c := range [][2]string{
		{http.MethodGet, logapi.PathSearch}, {http.MethodGet, logapi.PathHistogram},
		{http.MethodGet, logapi.PathFacets}, {http.MethodPost, logapi.PathReveal},
	} {
		if agentTokenMayCall(c[0], c[1]) {
			t.Errorf("%s %s ouvert aux jetons d'Agent", c[0], c[1])
		}
	}
}
