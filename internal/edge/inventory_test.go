// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/appinv"
	"github.com/vincamok/goproxify/internal/edge/fingerprint"
	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/middleware"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
)

func announceImage(t *testing.T, s *Server, cid, host, backend, image string) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{
		"id": "docker:" + cid[:12] + ":" + host, "host": host, "backends": []string{backend},
		"container_id": cid, "agent_name": "ag", "image": image,
	})
	rr := httptest.NewRecorder()
	s.handleAgentContainerStart(rr, httptest.NewRequest(http.MethodPost, "/internal/v1/agent/containers", bytes.NewReader(b)))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("annonce : %d %s", rr.Code, rr.Body.String())
	}
}

func inventory(t *testing.T, s *Server, query string) []logapi.InventoryEntry {
	t.Helper()
	rr := httptest.NewRecorder()
	s.handleInventory(rr, httptest.NewRequest(http.MethodGet, logapi.PathInventory+query, nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("inventaire : %d", rr.Code)
	}
	var out logapi.InventoryResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out.Entries
}

func TestInventoryComesFromTheImageTheAgentAnnounced(t *testing.T) {
	s := testEdgeServer()
	announceImage(t, s, "aaaaaaaaaaaa1111", "blog.example.fr", "http://10.0.0.1:80", "wordpress:6.4.2-apache")
	announceImage(t, s, "bbbbbbbbbbbb2222", "blog.example.fr", "http://10.0.0.2:80", "wordpress:6.4.2-apache")
	announceImage(t, s, "cccccccccccc3333", "grafana.example.fr", "http://10.0.0.3:3000", "grafana/grafana:latest")
	announceImage(t, s, "dddddddddddd4444", "app.example.fr", "http://10.0.0.4:8080", "registry.local:5000/team/app:2.0.1")
	announceImage(t, s, "eeeeeeeeeeee5555", "old.example.fr", "http://10.0.0.5:80", "")

	got := inventory(t, s, "")
	byHost := map[string][]logapi.InventoryEntry{}
	for _, e := range got {
		byHost[e.Host] = append(byHost[e.Host], e)
	}
	if len(byHost["blog.example.fr"]) != 2 {
		t.Fatalf("un backend par conteneur attendu : %+v", byHost["blog.example.fr"])
	}
	wp := byHost["blog.example.fr"][0]
	if wp.Product != "wordpress" || wp.Version != "6.4.2" || wp.CPE != "wordpress:wordpress" || wp.Source != "image" || wp.Evidence != "wordpress:6.4.2-apache" || wp.Container != "aaaaaaaaaaaa1111" {
		t.Errorf("WordPress : %+v", wp)
	}
	gf := byHost["grafana.example.fr"][0]
	if gf.Product != "grafana" || gf.Version != "" {
		t.Errorf("l'étiquette latest ne donne pas de version : %+v", gf)
	}
	if app := byHost["app.example.fr"]; len(app) != 1 || app[0].Product != "" || app[0].Evidence == "" {
		t.Errorf("une image inconnue est listée sans produit : %+v", app)
	}
	if len(byHost["old.example.fr"]) != 0 {
		t.Errorf("une passerelle ou un Agent qui n'annonce pas d'image n'invente rien : %+v", byHost["old.example.fr"])
	}

	if one := inventory(t, s, "?route=grafana.example.fr"); len(one) != 1 || one[0].Product != "grafana" {
		t.Errorf("filtre par proxy : %+v", one)
	}
}

func TestInventorySurvivesReannounceAndLosesStoppedContainers(t *testing.T) {
	s := testEdgeServer()
	announceImage(t, s, "aaaaaaaaaaaa1111", "blog.example.fr", "http://10.0.0.1:80", "wordpress:6.4.2")
	announceImage(t, s, "aaaaaaaaaaaa1111", "blog.example.fr", "http://10.0.0.1:80", "wordpress:6.5.0")
	got := inventory(t, s, "")
	if len(got) != 1 || got[0].Version != "6.5.0" {
		t.Fatalf("la réannonce remplace l'image (mise à jour du conteneur) : %+v", got)
	}
	announceImage(t, s, "bbbbbbbbbbbb2222", "blog.example.fr", "http://10.0.0.2:80", "wordpress:6.5.0")
	stop := `{"container_id":"aaaaaaaaaaaa1111","name":"c1"}`
	rr := httptest.NewRecorder()
	s.handleAgentContainerStop(rr, httptest.NewRequest(http.MethodDelete, "/internal/v1/agent/containers", bytes.NewBufferString(stop)))
	got = inventory(t, s, "")
	if len(got) != 1 || got[0].Container != "bbbbbbbbbbbb2222" {
		t.Fatalf("un conteneur arrêté sort de l'inventaire : %+v", got)
	}
}

const wpHome = `<html><head><meta name="generator" content="WordPress 6.4.2" /></head><body>blog</body></html>`

func TestFingerprintSeesWhatHideServerRemovesFromTheClient(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.3")
		w.Header().Set("X-Powered-By", "PHP/8.2.12")
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		_, _ = io.WriteString(w, wpHome)
	}))
	defer backend.Close()

	rt := &router.Route{ID: "r1", Host: "blog.test", Backends: []router.Backend{{URL: backend.URL}}}
	store := fingerprint.NewStore()
	ph := proxy.NewHandler(rt, proxy.NewBackendHealth(slog.Default()), proxy.NewAgentMetricsStore(), proxy.NewPeerRegistry(), slog.Default())
	ph.SetResponseObserver(store)
	front := httptest.NewServer(middleware.SecurityHeaders(&router.HeadersConfig{HideServer: true})(ph))
	defer front.Close()

	resp, err := http.Get(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.Header.Get("Server") != "" || resp.Header.Get("X-Powered-By") != "" {
		t.Fatalf("hide_server doit toujours masquer ces en-têtes au client : %v", resp.Header)
	}
	if string(body) != wpHome {
		t.Fatalf("la page arrive intacte : %q", body)
	}
	got := map[string]string{}
	for _, o := range store.Entries("r1") {
		got[o.Product+"|"+o.Source] = o.Version
		if o.Backend != backend.URL {
			t.Errorf("l'observation porte le backend : %+v", o)
		}
	}
	if got["nginx|headers"] != "1.25.3" || got["php|headers"] != "8.2.12" || got["wordpress|html"] != "6.4.2" {
		t.Fatalf("la passerelle a vu ce que le client ne voit plus : %v", got)
	}
}

func TestInventoryMergesImageAndResponses(t *testing.T) {
	rt := &router.Route{ID: "r1", Host: "blog.test", Backends: []router.Backend{
		{URL: "http://10.0.0.1:80", ContainerID: "c1", Image: "grafana/grafana:latest"},
		{URL: "http://10.0.0.2:80", ContainerID: "c2", Image: "nginx:1.25.3"},
		{URL: "http://10.0.0.3:80", ContainerID: "c3", Image: "wordpress:6.4.2"},
	}}
	obs := func(backend, product, cpe, version, source, evidence string) fingerprint.Obs {
		return fingerprint.Obs{Backend: backend, Product: product, CPE: cpe, Version: version, Source: source, Evidence: evidence}
	}
	got := inventoryEntries(rt, []fingerprint.Obs{
		obs("http://10.0.0.1:80", "grafana", "grafana:grafana", "10.2.0", appinv.SourceHeaders, "X-Generator: Grafana 10.2.0"), // l'image n'a pas de version
		obs("http://10.0.0.2:80", "nginx", "nginx:nginx", "1.24.0", appinv.SourceHeaders, "Server: nginx/1.24.0"),              // désaccord
		obs("http://10.0.0.3:80", "wordpress", "wordpress:wordpress", "6.4.2", appinv.SourceHTML, "<meta>"),                    // même version
		obs("http://10.0.0.4:80", "php", "php:php", "8.2.12", appinv.SourceHeaders, "X-Powered-By: PHP/8.2.12"),                // vu seulement dans les réponses
	})
	by := map[string]logapi.InventoryEntry{}
	for _, e := range got {
		by[e.Backend+"|"+e.Product] = e
	}
	if g := by["http://10.0.0.1:80|grafana"]; g.Version != "10.2.0" || g.Source != appinv.SourceHeaders || g.Container != "c1" {
		t.Errorf("la version manquante à l'image vient des réponses : %+v", g)
	}
	if n := by["http://10.0.0.2:80|nginx"]; n.Version != "1.25.3" || n.Source != appinv.SourceImage || n.Note == "" {
		t.Errorf("en cas de désaccord l'image l'emporte et la note le dit : %+v", n)
	}
	if w := by["http://10.0.0.3:80|wordpress"]; w.Source != appinv.SourceImage || w.Note != "" {
		t.Errorf("même version : l'image, sans note : %+v", w)
	}
	if p := by["http://10.0.0.4:80|php"]; p.Version != "8.2.12" || p.Host != "blog.test" {
		t.Errorf("un backend sans image est connu par ses réponses : %+v", p)
	}
	if len(got) != 4 {
		t.Errorf("une entrée par (backend, produit) : %+v", got)
	}
}
