// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeEdgeJSON(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "edge.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadEdgeUnknownHostAction(t *testing.T) {
	t.Setenv("GPX_NETWORK_UNKNOWN_HOST_ACTION", "")

	cfg, err := LoadEdge(writeEdgeJSON(t, `{"network":{"http_port":80}}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Network.UnknownHostAction != "" {
		t.Fatalf("absent : %q, attendu vide (réponse neutre par défaut)", cfg.Network.UnknownHostAction)
	}

	t.Setenv("GPX_NETWORK_UNKNOWN_HOST_ACTION", "close")
	cfg, err = LoadEdge(writeEdgeJSON(t, `{"network":{"http_port":80}}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Network.UnknownHostAction != "close" {
		t.Fatalf("variable d'environnement : %q, attendu close", cfg.Network.UnknownHostAction)
	}

	cfg, err = LoadEdge(writeEdgeJSON(t, `{"network":{"unknown_host_action":"neutral"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Network.UnknownHostAction != "neutral" {
		t.Fatalf("le JSON prime sur la variable d'environnement : %q", cfg.Network.UnknownHostAction)
	}
}
