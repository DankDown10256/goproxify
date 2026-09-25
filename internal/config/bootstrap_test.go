// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// coreIdentity lit juste la section identity d'un core.json pour les assertions.
func coreIdentity(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	identity, _ := doc["identity"].(map[string]any)
	if identity == nil {
		t.Fatalf("section identity absente de %s", path)
	}
	return identity
}

// TestBootstrapCoreIdempotent vérifie que BootstrapCore ne touche plus au
// fichier une fois qu'il existe — c'est la garantie de stabilité de
// l'identité (node_name, token_id) entre deux démarrages du même
// conteneur sur le même volume.
func TestBootstrapCoreIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "core.json")

	t.Setenv("GPX_IDENTITY_CORE_NODE_NAME", "frontal")
	if err := BootstrapCore(path); err != nil {
		t.Fatalf("premier bootstrap : %v", err)
	}
	id1 := coreIdentity(t, path)
	tokenID1, _ := id1["token_id"].(string)
	if tokenID1 == "" {
		t.Fatal("token_id vide après le premier bootstrap")
	}
	if id1["node_name"] != "frontal" {
		t.Fatalf("node_name = %v, attendu frontal", id1["node_name"])
	}

	// Deuxième "démarrage" avec une variable d'environnement différente —
	// reproduit un redéploiement Portainer où CORE_NODE_NAME a changé.
	t.Setenv("GPX_IDENTITY_CORE_NODE_NAME", "goproxify-core")
	if err := BootstrapCore(path); err != nil {
		t.Fatalf("second bootstrap : %v", err)
	}
	id2 := coreIdentity(t, path)
	if id2["token_id"] != tokenID1 {
		t.Fatalf("token_id a changé entre deux démarrages : %v -> %v", tokenID1, id2["token_id"])
	}
	if id2["node_name"] != "frontal" {
		t.Fatalf("node_name a changé alors que le fichier existait déjà : %v (attendu frontal, inchangé malgré la nouvelle env var)", id2["node_name"])
	}
}

// TestLoadCoreNodeNameStableAcrossEnvChange vérifie que LoadCore ignore
// GPX_IDENTITY_CORE_NODE_NAME une fois identity.node_name déjà présent
// dans le fichier — c'est la valeur écrite au tout premier bootstrap qui
// fait foi, pas la variable d'environnement du redémarrage courant.
func TestLoadCoreNodeNameStableAcrossEnvChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "core.json")

	t.Setenv("GPX_IDENTITY_CORE_NODE_NAME", "frontal")
	if err := BootstrapCore(path); err != nil {
		t.Fatal(err)
	}

	// Le redémarrage suivant arrive avec une valeur différente de la variable.
	t.Setenv("GPX_IDENTITY_CORE_NODE_NAME", "proxify-core")
	cfg, err := LoadCore(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Identity.NodeName != "frontal" {
		t.Fatalf("node_name chargé = %q, attendu frontal (celui du fichier, pas de la nouvelle env var)", cfg.Identity.NodeName)
	}
}

// TestBootstrapAdminSQLiteDSNMatchesHistoricalPath verrouille le chemin de la
// base SQLite générée par BootstrapAdmin : il doit rester exactement celui du
// template services/admin/config.json qui équipait les images jusqu'à
// d25555a (/etc/goproxify/database/goproxify.db). Une régression ici ferait
// pointer un déploiement existant vers une base neuve et vide au premier
// vrai bootstrap, laissant toutes les données (domaines, certs, config ACME,
// utilisateurs…) orphelines sur le volume sans qu'elles soient supprimées ni
// visibles dans l'UI — symptôme observé : "Domaines & certificats" vide.
func TestBootstrapAdminSQLiteDSNMatchesHistoricalPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GPX_STORAGE_BASE_PATH", dir)
	path := filepath.Join(dir, "admin.json")
	if err := BootstrapAdmin(path); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAdmin(path)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "database", "goproxify.db")
	if cfg.Storage.SQLiteDSN != want {
		t.Fatalf("sqlite_dsn = %q, attendu %q (chemin historique)", cfg.Storage.SQLiteDSN, want)
	}
}

// TestBootstrapCoreLogPathsMatchHistoricalPaths verrouille les chemins de
// logs générés par BootstrapCore face au même risque de divergence
// silencieuse (fichiers différents du nom historique, logs éparpillés entre
// ancien et nouveau fichier sur le même volume).
func TestBootstrapCoreLogPathsMatchHistoricalPaths(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GPX_STORAGE_BASE_PATH", dir)
	path := filepath.Join(dir, "core.json")
	if err := BootstrapCore(path); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadCore(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "logs", "core_access.log"); cfg.Engine.AccessLogPath != want {
		t.Fatalf("access_log_path = %q, attendu %q", cfg.Engine.AccessLogPath, want)
	}
	if want := filepath.Join(dir, "logs", "core_system.log"); cfg.Engine.SystemLogPath != want {
		t.Fatalf("system_log_path = %q, attendu %q", cfg.Engine.SystemLogPath, want)
	}
}

// TestBootstrapCoreTokenIDStableAcrossManyRestarts simule plusieurs
// redémarrages consécutifs (le scénario réel : le conteneur redémarre
// plusieurs fois) et vérifie que token_id et node_name ne bougent jamais
// une fois le fichier créé.
func TestBootstrapCoreTokenIDStableAcrossManyRestarts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "core.json")

	t.Setenv("GPX_IDENTITY_CORE_NODE_NAME", "frontal")
	if err := BootstrapCore(path); err != nil {
		t.Fatal(err)
	}
	want := coreIdentity(t, path)

	for i := 0; i < 5; i++ {
		if err := BootstrapCore(path); err != nil {
			t.Fatalf("redémarrage %d : %v", i, err)
		}
		got := coreIdentity(t, path)
		if got["token_id"] != want["token_id"] || got["node_name"] != want["node_name"] {
			t.Fatalf("redémarrage %d : identité changée, got=%v want=%v", i, got, want)
		}
	}
}
