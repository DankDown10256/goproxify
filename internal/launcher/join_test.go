// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package launcher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vincamok/goproxify/internal/deploy"
)

const testJoinToken = "0123456789abcdef0123456789abcdef"

// fakeAdmin est un Admin en TLS (certificat auto-signé) qui sert la description d'un hôte pour testJoinToken.
type fakeAdmin struct {
	srv      *httptest.Server
	requests atomic.Int32
	fp       string
	handler  http.HandlerFunc // remplace la réponse normale si posé
}

func newFakeAdmin(t *testing.T) *fakeAdmin {
	t.Helper()
	a := &fakeAdmin{}
	spec, err := twoHostTopology(t).HostSpec("nas", testEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(spec)
	a.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.requests.Add(1)
		if a.handler != nil {
			a.handler(w, r)
			return
		}
		if r.URL.Path != "/api/v1/join/"+testJoinToken {
			http.Error(w, "ticket inconnu ou expiré", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(a.srv.Close)
	sum := sha256.Sum256(a.srv.Certificate().Raw)
	a.fp = hex.EncodeToString(sum[:])
	return a
}

func (a *fakeAdmin) specURL() string { return a.srv.URL + "/api/v1/join/" + testJoinToken }

func TestNormalizeFingerprint(t *testing.T) {
	good := strings.Repeat("ab", 32)
	for in, want := range map[string]string{
		"": "", good: good, strings.ToUpper(good): good,
		strings.TrimSuffix(strings.Repeat("AB:", 32), ":"): good,
	} {
		if got, err := NormalizeFingerprint(in); err != nil || got != want {
			t.Errorf("NormalizeFingerprint(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"abc", strings.Repeat("zz", 32), strings.Repeat("ab", 33)} {
		if _, err := NormalizeFingerprint(bad); err == nil {
			t.Errorf("NormalizeFingerprint(%q) doit échouer", bad)
		}
	}
}

func TestFetchSpecPinsTheAdminCertificate(t *testing.T) {
	a := newFakeAdmin(t)

	spec, err := FetchSpec(context.Background(), a.specURL(), a.fp)
	if err != nil {
		t.Fatalf("avec la bonne empreinte : %v", err)
	}
	if spec.Name != "nas" || len(spec.Containers) != 1 {
		t.Errorf("description = %+v", spec)
	}
	// L'empreinte se donne telle qu'on la lit : majuscules et deux-points.
	var grouped []string
	for i := 0; i < len(a.fp); i += 2 {
		grouped = append(grouped, strings.ToUpper(a.fp[i:i+2]))
	}
	if _, err := FetchSpec(context.Background(), a.specURL(), strings.Join(grouped, ":")); err != nil {
		t.Errorf("empreinte groupée : %v", err)
	}

	a.requests.Store(0)
	_, err = FetchSpec(context.Background(), a.specURL(), strings.Repeat("00", 32))
	if err == nil || !strings.Contains(err.Error(), "empreinte") {
		t.Fatalf("mauvaise empreinte : %v", err)
	}
	if n := a.requests.Load(); n != 0 {
		t.Errorf("le jeton ne doit pas partir vers un Admin dont le certificat n'est pas le bon (%d requêtes reçues)", n)
	}

	// Sans empreinte, un certificat auto-signé n'est pas accepté.
	if _, err := FetchSpec(context.Background(), a.specURL(), ""); err == nil {
		t.Error("sans empreinte, un certificat auto-signé doit être refusé")
	}
}

func TestFetchSpecRefusals(t *testing.T) {
	a := newFakeAdmin(t)
	ctx := context.Background()

	if _, err := FetchSpec(ctx, strings.Replace(a.specURL(), "https://", "http://", 1), a.fp); err == nil {
		t.Error("http doit être refusé : la réponse porte des clés")
	}
	if _, err := FetchSpec(ctx, a.srv.URL+"/api/v1/join/autre", a.fp); err == nil || !strings.Contains(err.Error(), "expiré") {
		t.Errorf("ticket inconnu : %v", err)
	}
	if _, err := FetchSpec(ctx, a.specURL(), "pas-une-empreinte"); err == nil {
		t.Error("empreinte invalide")
	}

	cases := map[string]http.HandlerFunc{
		"erreur du serveur": func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boum", http.StatusInternalServerError) },
		"redirection non suivie": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://autre.example/", http.StatusFound)
		},
		"JSON illisible":       func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>")) },
		"description invalide": func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"version":9,"containers":[]}`)) },
		"trop volumineuse": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"version":1,"name":"` + strings.Repeat("a", maxSpecSize+10) + `"}`))
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			a.handler = h
			if _, err := FetchSpec(ctx, a.specURL(), a.fp); err == nil {
				t.Error("la réponse doit être refusée")
			}
		})
	}
}

func TestJoinAppliesTheSpecFetchedFromTheAdmin(t *testing.T) {
	a := newFakeAdmin(t)
	api := newFakeAPI()
	var steps []string

	rep, err := Join(context.Background(), api, a.specURL(), a.fp, func(e deploy.Event) { steps = append(steps, e.Step+":"+e.Name) })
	if err != nil {
		t.Fatal(err)
	}
	if rep.Host != "nas" || len(rep.Containers) != 1 || rep.Containers[0] != "goproxify-agent" {
		t.Errorf("rapport = %+v", rep)
	}
	if len(api.created) != 1 || len(api.started) != 1 {
		t.Errorf("créés %v, démarrés %v", api.created, api.started)
	}
	if len(steps) == 0 {
		t.Error("l'avancement doit être rapporté")
	}

	// Un ticket expiré n'installe rien.
	api2 := newFakeAPI()
	a.handler = func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", http.StatusNotFound) }
	if _, err := Join(context.Background(), api2, a.specURL(), a.fp, nil); err == nil || len(api2.created) != 0 {
		t.Errorf("ticket expiré : %v, créés %v", err, api2.created)
	}
}
