// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package statepub

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestGenerationNeverGoesBackAcrossARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gen")
	p := New("ag", path)
	var last int64
	for i := 0; i < 50; i++ {
		g := p.next()
		if g <= last {
			t.Fatalf("génération %d après %d", g, last)
		}
		last = g
	}
	// Un redémarrage dont l'horloge a reculé repart au-dessus de la dernière génération envoyée.
	restarted := New("ag", path)
	if g := restarted.next(); g <= last {
		t.Fatalf("après redémarrage : %d, attendu au-dessus de %d", g, last)
	}
}

func TestPutOutcomes(t *testing.T) {
	cases := map[int]Result{
		http.StatusOK:                  Sent,
		http.StatusConflict:            Sent,
		http.StatusNotFound:            Unsupported,
		http.StatusMethodNotAllowed:    Unsupported,
		http.StatusBadRequest:          Failed,
		http.StatusInternalServerError: Failed,
	}
	for status, want := range cases {
		var got map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut || r.URL.Path != Path || r.Header.Get("Authorization") != "Bearer tok" {
				t.Errorf("requête inattendue : %s %s %q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
			}
			_ = json.NewDecoder(r.Body).Decode(&got)
			w.WriteHeader(status)
		}))
		res, err := New("ag", "").Put(t.Context(), srv.URL+"/", "tok", "docker", "", nil)
		srv.Close()
		if res != want {
			t.Errorf("statut %d : %v, attendu %v (err %v)", status, res, want, err)
		}
		if stale := errors.Is(err, ErrStale); stale != (status == http.StatusConflict) {
			t.Errorf("statut %d : ErrStale=%v (err %v)", status, stale, err)
		}
		if got["agent_name"] != "ag" || got["source"] != "docker" || got["generation"] == nil {
			t.Errorf("statut %d : corps %v", status, got)
		}
		if routes, ok := got["routes"].([]any); !ok || len(routes) != 0 {
			t.Errorf("un état vide doit partir en liste vide, pas en null : %v", got["routes"])
		}
	}
}

// Un 401 veut dire que la passerelle ne reconnaît plus le jeton (son magasin de jetons a été remis à zéro). L'envoi se
// réappaire une fois et repart avec le jeton neuf.
func TestPutRepairsATokenTheGatewayForgot(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		seen = append(seen, tok)
		if tok != "neuf" {
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	p := New("ag", "")
	var stale []string
	p.SetOnUnauthorized(func(_ context.Context, s string) string {
		stale = append(stale, s)
		return "neuf"
	})

	res, err := p.Put(context.Background(), srv.URL, "ancien", "portainer", "1", nil)
	if res != Sent || err != nil {
		t.Fatalf("Put = %v, %v", res, err)
	}
	if !reflect.DeepEqual(seen, []string{"ancien", "neuf"}) || !reflect.DeepEqual(stale, []string{"ancien"}) {
		t.Errorf("jetons présentés %v, jeton périmé donné au réappairage %v", seen, stale)
	}
}

func TestPutGivesUpWhenTheRepairCannotHelp(t *testing.T) {
	cases := map[string]struct {
		hook         func(context.Context, string) string
		wantRequests int
	}{
		"pas de réappairage":           {nil, 1},
		"réappairage impossible":       {func(context.Context, string) string { return "" }, 1},
		"même jeton rendu":             {func(_ context.Context, s string) string { return s }, 1},
		"jeton neuf refusé à son tour": {func(context.Context, string) string { return "autre" }, 2},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			requests, calls := 0, 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			}))
			t.Cleanup(srv.Close)

			p := New("ag", "")
			if c.hook != nil {
				p.SetOnUnauthorized(func(ctx context.Context, s string) string {
					calls++
					return c.hook(ctx, s)
				})
			}
			res, err := p.Put(context.Background(), srv.URL, "ancien", "docker", "", nil)
			if res != Failed || err == nil || !strings.Contains(err.Error(), "401") {
				t.Fatalf("Put = %v, %v", res, err)
			}
			if requests != c.wantRequests || calls > 1 {
				t.Errorf("%d requêtes (attendu %d), réappairage appelé %d fois (au plus une)", requests, c.wantRequests, calls)
			}
		})
	}
}

func TestPutDoesNotRepairWhenAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(srv.Close)
	p := New("ag", "")
	p.SetOnUnauthorized(func(context.Context, string) string {
		t.Error("le réappairage ne sert qu'après un 401")
		return ""
	})
	if res, err := p.Put(context.Background(), srv.URL, "bon", "docker", "", nil); res != Sent || err != nil {
		t.Fatalf("Put = %v, %v", res, err)
	}
}
