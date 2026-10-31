// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"path/filepath"
	"testing"
)

// Le fournisseur par défaut peut être un type, ou l'identifiant d'un fournisseur nommé : l'écran Infrastructure enregistre
// l'identifiant, ce qui rendait le fournisseur « inconnu ».
func TestDefaultProviderConfigAcceptsATypeOrANamedProviderID(t *testing.T) {
	store := NewProviderStore(filepath.Join(t.TempDir(), "acme-providers.yaml"))
	id, err := store.Create("OVH principal", "ovh", map[string]string{"zone": "vincz.fr", "app_key": "k", "app_secret": "s", "consumer_key": "c"})
	if err != nil {
		t.Fatal(err)
	}

	named := DefaultProviderConfig(id, nil, store)
	if named.Type != "ovh" || named.Params["zone"] != "vincz.fr" {
		t.Fatalf("un identifiant nommé apporte son type et ses paramètres : %+v", named)
	}
	if _, err := NewProvider(named); err != nil {
		t.Fatalf("le fournisseur doit être instanciable : %v", err)
	}

	byType := DefaultProviderConfig("ovh", map[string]string{"zone": "autre.fr"}, store)
	if byType.Type != "ovh" || byType.Params["zone"] != "autre.fr" {
		t.Fatalf("un type garde le comportement d'origine : %+v", byType)
	}
	if got := DefaultProviderConfig("cloudflare", nil, nil); got.Type != "cloudflare" {
		t.Fatalf("sans magasin, un type reste un type : %+v", got)
	}
	if _, err := NewProvider(DefaultProviderConfig("17724365410d3870", nil, store)); err == nil {
		t.Fatal("un identifiant qui n'existe pas reste inconnu")
	}
}

// Le fichier des fournisseurs vit dans state/, dossier repris par la section secrets d'une sauvegarde : il se crée avec lui.
func TestProviderStoreCreatesItsFolder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "acme-providers.yaml")
	store := NewProviderStore(path)
	if _, err := store.Create("OVH", "ovh", map[string]string{"zone": "a.fr"}); err != nil {
		t.Fatal(err)
	}
	if list, err := store.List(); err != nil || len(list) != 1 {
		t.Fatalf("fournisseur non relu : %v %v", list, err)
	}
}
