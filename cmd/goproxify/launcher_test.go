// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLauncherTopologyFromFlags(t *testing.T) {
	topo, err := launcherTopology("", true, true, true, "192.168.1.10", "", "",
		[]string{"192.168.1.50=agent", "nas=192.168.1.60:edge,agent@ha-1"})
	if err != nil {
		t.Fatal(err)
	}
	if topo.Local != "host-192-168-1-10" || len(topo.Hosts) != 3 {
		t.Fatalf("topologie = %+v", topo)
	}
	if !reflect.DeepEqual(topo.Hosts[0].Roles, []string{"admin", "edge", "agent"}) {
		t.Errorf("rôles locaux = %v", topo.Hosts[0].Roles)
	}
	if topo.Hosts[2].Name != "nas" || topo.Hosts[2].Group != "ha-1" {
		t.Errorf("hôte = %+v", topo.Hosts[2])
	}
	if err := topo.Validate(); err != nil {
		t.Errorf("la topologie doit être valide : %v", err)
	}
}

func TestLauncherTopologyAloneDefaultsToLocalhost(t *testing.T) {
	topo, err := launcherTopology("", true, true, false, "", "solo", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if topo.Hosts[0].Addr != "localhost" || topo.Local != "solo" {
		t.Errorf("topologie = %+v", topo)
	}
}

func TestLauncherTopologyErrors(t *testing.T) {
	if _, err := launcherTopology("", false, false, false, "", "", "", nil); err == nil {
		t.Error("sans rôle local, la commande doit être refusée")
	}
	if _, err := launcherTopology("", true, true, false, "", "", "", []string{"192.168.1.50"}); err == nil {
		t.Error("--host sans --addr doit être refusé : les autres hôtes ne sauraient pas joindre celui-ci")
	}
	if _, err := launcherTopology("", true, true, false, "192.168.1.10", "", "", []string{"a:b:c"}); err == nil {
		t.Error("un --host invalide doit être refusé")
	}
}

func TestLauncherTopologyFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "topology.json")
	_ = os.WriteFile(path, []byte(`{"local":"main","hosts":[
	  {"name":"main","addr":"192.168.1.10","roles":["admin","edge"]},
	  {"name":"nas","addr":"192.168.1.50","roles":["agent"]}]}`), 0o600)

	topo, err := launcherTopology(path, false, false, false, "", "", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := topo.Validate(); err != nil || len(topo.Hosts) != 2 {
		t.Errorf("topologie = %+v, %v", topo, err)
	}
	if _, err := launcherTopology(path, true, false, false, "", "", "", nil); err == nil {
		t.Error("--topology avec des indicateurs doit être refusé")
	}
}
