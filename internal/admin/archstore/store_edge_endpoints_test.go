// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package archstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestEdgeEndpointsKeepsOnlyReachableEdges(t *testing.T) {
	s := New(t.TempDir())
	for _, n := range []NodeEntry{
		{ID: "c1", Role: "edge", Name: "frontal", Endpoint: "http://goproxify-edge:8000"},
		{ID: "c2", Role: "edge", Name: "backup", Endpoint: "http://192.0.2.20:8000"},
		{ID: "c3", Role: "edge", Name: "declared-only"},
		{ID: "a1", Role: "agent", Name: "agent-1", Endpoint: "http://agent:9000"},
	} {
		if err := s.Upsert(n); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.EdgeEndpoints()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "frontal" || got[1].Name != "backup" {
		t.Fatalf("attendu frontal et backup, reçu %+v", got)
	}
}

func TestEdgeEndpointsEmptyWithoutFile(t *testing.T) {
	got, err := New(t.TempDir()).EdgeEndpoints()
	if err != nil || len(got) != 0 {
		t.Fatalf("got %v err %v", got, err)
	}
}

func TestStoreReadsHandWrittenArchitectureJSON(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if filepath.Base(s.Path()) != "architecture.json" {
		t.Fatalf("fichier %q, attendu architecture.json", s.Path())
	}
	raw := `{
  "schema_version": 1,
  "nodes": [
    {"id": "c2", "role": "edge", "name": "backup", "endpoint": "http://192.0.2.20:8000"},
    {"id": "d1", "role": "edge", "name": "declared", "config": {"host": "192.0.2.30", "ha": true}}
  ]
}`
	if err := os.WriteFile(s.Path(), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	eps, err := s.EdgeEndpoints()
	if err != nil || len(eps) != 1 || eps[0].Name != "backup" {
		t.Fatalf("endpoints %+v err %v", eps, err)
	}
	// une écriture ne doit pas déformer la config du wizard (objet JSON, pas chaîne échappée)
	if err := s.Upsert(NodeEntry{ID: "c3", Role: "edge", Name: "extra", Endpoint: "http://192.0.2.40:8000"}); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(s.Path())
	var back struct {
		Nodes []struct {
			Name   string          `json:"name"`
			Config json.RawMessage `json:"config"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(data, &back); err != nil || len(back.Nodes) != 3 {
		t.Fatalf("relecture: %v %s", err, data)
	}
	if got := string(back.Nodes[1].Config); got == "" || got[0] != '{' {
		t.Fatalf("config du wizard doit rester un objet JSON, reçu %q", got)
	}
}
