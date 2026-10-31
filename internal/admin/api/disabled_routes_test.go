// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/auth"
)

type disabledRoutesPusher struct{ n atomic.Int32 }

func (p *disabledRoutesPusher) PushDisabledRoutes(context.Context) { p.n.Add(1) }

func putEnabled(t *testing.T, h *DiscoveredContainersHandler, user, body string) *httptest.ResponseRecorder {
	t.Helper()
	tok, err := auth.SignJWT(user, "secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, "/api/v1/discovered-containers/enabled", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	auth.RequireJWT("secret")(h).ServeHTTP(rec, req)
	return rec
}

func adminUser(t *testing.T, h *DiscoveredContainersHandler) {
	t.Helper()
	if _, err := h.DB.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('ad','ad@x.fr','x','admin')`); err != nil {
		t.Fatal(err)
	}
}

// Désactiver une route annoncée l'enregistre côté Admin et la pousse aux passerelles ; la réactiver la retire de la liste.
func TestDisablingAnAnnouncedHostIsStoredAndPushed(t *testing.T) {
	edge := fakeDiscoveryEdge(t, bareContainer, nil)
	h := discoveryHandler(t, map[string]string{"edge-a": edge.URL})
	adminUser(t, h)
	push := &disabledRoutesPusher{}
	h.Pusher = push

	if rec := putEnabled(t, h, "ad", `{"host":"APP.example.fr","enabled":false}`); rec.Code != http.StatusNoContent {
		t.Fatalf("désactivation : %d %s", rec.Code, rec.Body)
	}
	if got := LoadDisabledRoutes(h.DB); len(got) != 1 || got[0] != "app.example.fr" {
		t.Fatalf("hôte retenu en minuscules : %v", got)
	}
	waitPushes(t, push, 1)

	if rec := putEnabled(t, h, "ad", `{"host":"app.example.fr","enabled":true}`); rec.Code != http.StatusNoContent {
		t.Fatalf("réactivation : %d %s", rec.Code, rec.Body)
	}
	if got := LoadDisabledRoutes(h.DB); len(got) != 0 {
		t.Fatalf("plus aucun hôte désactivé : %v", got)
	}
	waitPushes(t, push, 2)
}

func waitPushes(t *testing.T, p *disabledRoutesPusher, want int32) {
	t.Helper()
	for i := 0; i < 200 && p.n.Load() < want; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if p.n.Load() < want {
		t.Fatalf("poussées : %d, attendu %d", p.n.Load(), want)
	}
}

// Un hôte que personne n'annonce ne se désactive pas (faute de frappe) ; le réactiver reste permis, pour nettoyer.
func TestDisablingAnUnknownHostIsRefused(t *testing.T) {
	edge := fakeDiscoveryEdge(t, bareContainer, nil)
	h := discoveryHandler(t, map[string]string{"edge-a": edge.URL})
	adminUser(t, h)

	if rec := putEnabled(t, h, "ad", `{"host":"inconnu.example.fr","enabled":false}`); rec.Code != http.StatusNotFound {
		t.Fatalf("hôte inconnu : %d", rec.Code)
	}
	if got := LoadDisabledRoutes(h.DB); len(got) != 0 {
		t.Fatalf("rien n'est enregistré : %v", got)
	}
	if rec := putEnabled(t, h, "ad", `{"host":"inconnu.example.fr","enabled":true}`); rec.Code != http.StatusNoContent {
		t.Fatalf("réactiver un hôte quelconque : %d", rec.Code)
	}
	if rec := putEnabled(t, h, "ad", `{"host":"app.example.fr"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("enabled requis : %d", rec.Code)
	}
}

// Un utilisateur qui n'a aucun droit d'écriture sur les proxies ne désactive rien.
func TestDisablingNeedsWriteAccess(t *testing.T) {
	edge := fakeDiscoveryEdge(t, bareContainer, nil)
	h := discoveryHandler(t, map[string]string{"edge-a": edge.URL})
	if _, err := h.DB.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('ro','ro@x.fr','x','viewer')`); err != nil {
		t.Fatal(err)
	}
	if rec := putEnabled(t, h, "ro", `{"host":"app.example.fr","enabled":false}`); rec.Code != http.StatusForbidden {
		t.Fatalf("lecteur : %d", rec.Code)
	}
	if got := LoadDisabledRoutes(h.DB); len(got) != 0 {
		t.Fatalf("rien n'est enregistré : %v", got)
	}
}

// La liste montre les routes désactivées que la passerelle annonce, et garde visible celle qu'aucune passerelle
// n'annonce plus (Agent absent depuis un redémarrage) pour qu'on puisse la réactiver.
func TestListKeepsDisabledHostsVisible(t *testing.T) {
	const disabledByEdge = `[{"id":"docker-host:app.example.fr","host":"app.example.fr","backends":["http://10.0.0.5:80"],"source":"docker","agent_name":"ag","disabled":true}]`
	edge := fakeDiscoveryEdge(t, disabledByEdge, nil)
	h := discoveryHandler(t, map[string]string{"edge-a": edge.URL})
	if err := saveDisabledRoutes(h.DB, []string{"app.example.fr", "absent.example.fr"}); err != nil {
		t.Fatal(err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/discovered-containers", nil))
	var list []DiscoveredContainer
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("une entrée annoncée et une entrée de repli : %+v", list)
	}
	for _, c := range list {
		if !c.Disabled {
			t.Fatalf("toutes sont désactivées : %+v", c)
		}
	}
}

func TestDisabledHostsAreNormalizedAndSorted(t *testing.T) {
	h := discoveryHandler(t, nil)
	if err := saveDisabledRoutes(h.DB, []string{"B.example.fr.", " a.example.fr ", ""}); err != nil {
		t.Fatal(err)
	}
	got := LoadDisabledRoutes(h.DB)
	if len(got) != 2 || got[0] != "a.example.fr" || got[1] != "b.example.fr" {
		t.Fatalf("hôtes normalisés et triés : %v", got)
	}
}
