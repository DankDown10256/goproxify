// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAgentLegacyCoreKeys(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.json")
	legacy := `{"control_plane":{"core_endpoint":"http://goproxify-core:8000"},"network_management":{"core_container_name":"goproxify-core"}}`
	if err := os.WriteFile(p, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAgent(p)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ControlPlane.EdgeEndpoint != "http://goproxify-core:8000" || cfg.NetworkManagement.EdgeContainerName != "goproxify-core" {
		t.Fatalf("clés core_* non reprises : %+v %+v", cfg.ControlPlane, cfg.NetworkManagement)
	}
}

func TestAliasLegacyEnv(t *testing.T) {
	t.Setenv("GPX_CORE_TOKEN", "abc")
	t.Setenv("GPX_EDGE_TOKEN", "")
	t.Setenv("GPX_IDENTITY_CORE_NODE_NAME", "old")
	t.Setenv("GPX_IDENTITY_EDGE_NODE_NAME", "new")
	AliasLegacyEnv()
	if got := os.Getenv("GPX_EDGE_TOKEN"); got != "abc" {
		t.Fatalf("GPX_EDGE_TOKEN = %q", got)
	}
	if got := os.Getenv("GPX_IDENTITY_EDGE_NODE_NAME"); got != "new" {
		t.Fatalf("la variable EDGE existante ne doit pas être écrasée : %q", got)
	}
}

func TestMigrateLegacyEdgeFiles(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "core.json"), []byte("{}"), 0o600)
	os.WriteFile(filepath.Join(dir, "core-cache.gpx"), []byte("x"), 0o600)
	os.WriteFile(filepath.Join(dir, "edge-cache.gpx"), []byte("keep"), 0o600)
	MigrateLegacyEdgeFiles(dir)
	if _, err := os.Stat(filepath.Join(dir, "edge.json")); err != nil {
		t.Fatal("edge.json attendu")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "edge-cache.gpx")); string(b) != "keep" {
		t.Fatal("un fichier edge existant ne doit pas être écrasé")
	}
}
