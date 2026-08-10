// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package cache_test

import (
	"os"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/core/cache"
	"github.com/vincamok/goproxify/internal/core/router"
)

func TestCacheSaveLoad(t *testing.T) {
	f, err := os.CreateTemp("", "gpx-cache-*.gpx")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	store := cache.New(f.Name(), "test-secret")

	snap := &cache.Snapshot{
		SavedAt: time.Now(),
		Routes: []*router.Route{
			{ID: "r1", Host: "app.example.fr", Type: router.RouteHTTP},
			{ID: "r2", Host: "api.example.fr", Type: router.RouteHTTP},
		},
	}

	if err := store.Save(snap); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded == nil {
		t.Fatal("snapshot nil après chargement")
	}
	if len(loaded.Routes) != 2 {
		t.Fatalf("attendu 2 routes, obtenu %d", len(loaded.Routes))
	}
	if loaded.Routes[0].ID != "r1" {
		t.Fatalf("route[0].ID attendu r1, obtenu %s", loaded.Routes[0].ID)
	}
}

func TestCacheWrongSecret(t *testing.T) {
	f, err := os.CreateTemp("", "gpx-cache-*.gpx")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	store := cache.New(f.Name(), "secret-A")
	snap := &cache.Snapshot{SavedAt: time.Now(), Routes: []*router.Route{{ID: "r1"}}}
	if err := store.Save(snap); err != nil {
		t.Fatal(err)
	}

	storeB := cache.New(f.Name(), "secret-B")
	_, err = storeB.Load()
	if err == nil {
		t.Fatal("attendait une erreur de déchiffrement avec un mauvais secret")
	}
}

func TestCacheLoadWithFallbacks(t *testing.T) {
	f, err := os.CreateTemp("", "gpx-cache-*.gpx")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	// Ancien cache chiffré avec clé vide (comportement compose historique).
	old := cache.New(f.Name(), "")
	if err := old.Save(&cache.Snapshot{
		SavedAt: time.Now(),
		Routes:  []*router.Route{{ID: "legacy", Host: "app.example.fr"}},
	}); err != nil {
		t.Fatal(err)
	}

	// Nouveau store avec PAIRING_SECRET simulé.
	neu := cache.New(f.Name(), "pairing-secret")
	snap, err := neu.LoadWithFallbacks("")
	if err != nil {
		t.Fatalf("LoadWithFallbacks: %v", err)
	}
	if snap == nil || len(snap.Routes) != 1 || snap.Routes[0].ID != "legacy" {
		t.Fatalf("snapshot inattendu: %+v", snap)
	}

	// Rechargé sans fallback : réécrit avec la nouvelle clé.
	snap2, err := neu.Load()
	if err != nil || snap2 == nil || snap2.Routes[0].ID != "legacy" {
		t.Fatalf("relecture avec nouvelle clé: snap=%v err=%v", snap2, err)
	}
}

func TestResolveSecret(t *testing.T) {
	t.Setenv("GPX_CONTROL_PLANE_AUTH_TOKEN", "")
	t.Setenv("GPX_CONTROLPLANE_AUTH_TOKEN", "")
	t.Setenv("GPX_PAIRING_SECRET", "pair-xyz")
	if got := cache.ResolveSecret(""); got != "pair-xyz" {
		t.Fatalf("attendu pair-xyz, obtenu %q", got)
	}
	if got := cache.ResolveSecret("explicit"); got != "explicit" {
		t.Fatalf("authToken explicite ignoré: %q", got)
	}
}

func TestCacheClear(t *testing.T) {
	f, err := os.CreateTemp("", "gpx-cache-*.gpx")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	store := cache.New(f.Name(), "s")
	store.Save(&cache.Snapshot{SavedAt: time.Now()}) //nolint:errcheck

	if err := store.Clear(); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil || loaded != nil {
		t.Fatal("cache toujours présent après Clear")
	}
}

func TestCacheExportJSON(t *testing.T) {
	f, err := os.CreateTemp("", "gpx-cache-*.gpx")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())

	out, err := os.CreateTemp("", "gpx-export-*.json")
	if err != nil {
		t.Fatal(err)
	}
	out.Close()
	defer os.Remove(out.Name())

	store := cache.New(f.Name(), "s")
	store.Save(&cache.Snapshot{ //nolint:errcheck
		SavedAt: time.Now(),
		Routes:  []*router.Route{{ID: "r1", Host: "x.fr"}},
	})

	if err := store.ExportJSON(out.Name()); err != nil {
		t.Fatalf("ExportJSON: %v", err)
	}
	data, _ := os.ReadFile(out.Name())
	if len(data) == 0 {
		t.Fatal("export JSON vide")
	}
}
