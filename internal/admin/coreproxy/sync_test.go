// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package coreproxy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func fakeCore(t *testing.T, ids []string) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	published := []string{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/v1/proxies", func(w http.ResponseWriter, r *http.Request) {
		prod := []map[string]any{}
		for _, id := range ids {
			prod = append(prod, map[string]any{
				"id": id, "host": id + ".example.fr", "enabled": true, "status": "production",
				"config": map[string]any{"id": id, "host": id + ".example.fr"},
			})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"production": prod})
	})
	mux.HandleFunc("POST /internal/v1/proxies/revisions", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		published = append(published, body["id"].(string))
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"id": body["id"], "revision": "r1", "status": "pending"})
	})
	mux.HandleFunc("POST /internal/v1/proxies/{id}/revisions/{rev}/dry-run", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": r.PathValue("id"), "status": "validated"})
	})
	mux.HandleFunc("POST /internal/v1/proxies/{id}/revisions/{rev}/promote", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": r.PathValue("id"), "status": "production"})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &published
}

func TestSyncMissingPublishesOnlyAbsentProxies(t *testing.T) {
	rejoining, published := fakeCore(t, []string{"p1"})
	peerA, _ := fakeCore(t, []string{"p1", "p2", "p3"})
	peerB, _ := fakeCore(t, []string{"p1", "p2"})

	c := NewClient()
	target := Target{NodeName: "core-c", Endpoint: rejoining.URL}
	peers := []Target{
		target,
		{NodeName: "core-a", Endpoint: peerA.URL},
		{NodeName: "core-b", Endpoint: peerB.URL},
	}
	n, err := c.SyncMissing(context.Background(), target, peers)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("synced=%d, want 2", n)
	}
	got := map[string]int{}
	for _, id := range *published {
		got[id]++
	}
	if got["p2"] != 1 || got["p3"] != 1 || got["p1"] != 0 || len(got) != 2 {
		t.Fatalf("published=%v (p2 et p3 exactement une fois, jamais p1)", *published)
	}
}

func TestSyncMissingNoopWhenUpToDate(t *testing.T) {
	rejoining, published := fakeCore(t, []string{"p1", "p2"})
	peer, _ := fakeCore(t, []string{"p1", "p2"})
	c := NewClient()
	target := Target{Endpoint: rejoining.URL}
	n, err := c.SyncMissing(context.Background(), target, []Target{{Endpoint: peer.URL}})
	if err != nil || n != 0 || len(*published) != 0 {
		t.Fatalf("n=%d err=%v published=%v", n, err, *published)
	}
}

func TestSyncMissingSurvivesUnreachablePeer(t *testing.T) {
	rejoining, published := fakeCore(t, nil)
	good, _ := fakeCore(t, []string{"p1"})
	dead := httptest.NewServer(http.NotFoundHandler())
	dead.Close()
	c := NewClient()
	target := Target{Endpoint: rejoining.URL}
	n, err := c.SyncMissing(context.Background(), target, []Target{{Endpoint: dead.URL}, {Endpoint: good.URL}})
	if n != 1 || len(*published) != 1 {
		t.Fatalf("n=%d published=%v", n, *published)
	}
	if err == nil {
		t.Fatal("l'erreur du pair injoignable doit être remontée")
	}
}
