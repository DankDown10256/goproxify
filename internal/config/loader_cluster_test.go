// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseClusterPeersCSV(t *testing.T) {
	cases := []struct {
		in   string
		want map[string]string
	}{
		{
			"core-2:8002,core-3:8002",
			map[string]string{"core-2": "http://core-2:8002", "core-3": "http://core-3:8002"},
		},
		{
			"core-2=http://10.0.0.2:8002",
			map[string]string{"core-2": "http://10.0.0.2:8002"},
		},
		{"", map[string]string{}},
	}
	for _, tc := range cases {
		got := parseClusterPeersCSV(tc.in)
		if len(got) != len(tc.want) {
			t.Fatalf("%q: got %#v want %#v", tc.in, got, tc.want)
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Fatalf("%q[%s]=%q want %q", tc.in, k, got[k], v)
			}
		}
	}
}

func TestApplyClusterPeersEnv(t *testing.T) {
	t.Setenv("GPX_CLUSTER_PEERS", "peer-a:8002,peer-b:8002")
	cfg := &CoreConfig{}
	applyClusterPeersEnv(cfg)
	if cfg.Cluster.Peers["peer-a"] != "http://peer-a:8002" {
		t.Fatalf("peers %#v", cfg.Cluster.Peers)
	}
	// local wins
	cfg.Cluster.Peers = map[string]string{"keep": "http://x:1"}
	applyClusterPeersEnv(cfg)
	if len(cfg.Cluster.Peers) != 1 || cfg.Cluster.Peers["keep"] == "" {
		t.Fatalf("should keep local peers %#v", cfg.Cluster.Peers)
	}
}

func TestLoadCoreClusterEnv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "core.json")
	if err := os.WriteFile(path, []byte(`{"identity":{"node_name":"from-json"},"cluster":{}}`), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GPX_CLUSTER_ENABLED", "true")
	t.Setenv("GPX_CLUSTER_GROUP", "ha-1")
	t.Setenv("GPX_CLUSTER_NODE_ID", "core-a")
	t.Setenv("GPX_CLUSTER_RAFT_PORT", "8002")
	t.Setenv("GPX_CLUSTER_PEERS", "core-b:8002")
	t.Setenv("GPX_IDENTITY_CORE_NODE_NAME", "core-a-env")

	cfg, err := LoadCore(path)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Cluster.Enabled {
		t.Fatal("cluster.enabled")
	}
	if cfg.Cluster.GroupName != "ha-1" {
		t.Fatalf("group %q", cfg.Cluster.GroupName)
	}
	if cfg.Cluster.NodeID != "core-a" {
		t.Fatalf("node_id %q", cfg.Cluster.NodeID)
	}
	if cfg.Cluster.RaftPort != 8002 {
		t.Fatalf("raft_port %d", cfg.Cluster.RaftPort)
	}
	if cfg.Cluster.Peers["core-b"] != "http://core-b:8002" {
		t.Fatalf("peers %#v", cfg.Cluster.Peers)
	}
	if cfg.Identity.NodeName != "core-a-env" {
		t.Fatalf("identity %q", cfg.Identity.NodeName)
	}
}
