// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type listedContainer struct {
	ID        string   `json:"id"`
	Host      string   `json:"host"`
	Backends  []string `json:"backends"`
	Source    string   `json:"source"`
	AgentName string   `json:"agent_name"`
	Inactive  bool     `json:"inactive"`
	Disabled  bool     `json:"disabled"`
	State    string   `json:"state"`
	Name      string   `json:"name"`
}

func listContainers(t *testing.T, n *stateNode, query string) []listedContainer {
	t.Helper()
	rec := httptest.NewRecorder()
	n.srv.handleListAgentContainers(rec, httptest.NewRequest(http.MethodGet, "/internal/v1/agent/containers"+query, nil))
	var out []listedContainer
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func inactive(cid, host, state string) map[string]any {
	return map[string]any{"id": "portainer:1:" + cid[:12] + ":" + host, "host": host, "container_id": cid, "name": host, "state": state}
}

func stateWithInactive(source, scope string, gen int64, routes []map[string]any, inactives ...map[string]any) map[string]any {
	st := map[string]any{"agent_name": "ag", "source": source, "scope": scope, "generation": gen, "routes": routes}
	if len(inactives) > 0 {
		st["inactive"] = inactives
	}
	return st
}

func find(list []listedContainer, host string) (listedContainer, bool) {
	for _, c := range list {
		if c.Host == host {
			return c, true
		}
	}
	return listedContainer{}, false
}

// Un conteneur arrêté apparaît dans la liste comme inactif, sans route ni backend : il ne sert aucun trafic.
func TestInactiveContainerIsListedButNeverRouted(t *testing.T) {
	n := newStateNode(t, "frontal", groupKey, []string{"frontal", "backup"})
	const x, y = "xxxxxxxxxxxx1111", "yyyyyyyyyyyy2222"
	code := putAgentState(t, n, stateWithInactive("portainer", "1", 1,
		[]map[string]any{portainerRoute("1", x, "x.example.fr", "http://10.1.0.1:80")},
		inactive(y, "y.example.fr", "exited")))
	if code != http.StatusOK {
		t.Fatalf("état refusé : %d", code)
	}
	if hasHost(n, "y.example.fr") {
		t.Fatal("un conteneur inactif ne crée aucune route")
	}
	list := listContainers(t, n, "")
	x1, okX := find(list, "x.example.fr")
	y1, okY := find(list, "y.example.fr")
	if !okX || x1.Inactive || len(x1.Backends) != 1 {
		t.Fatalf("x tourne : %+v", x1)
	}
	if !okY || !y1.Inactive || y1.State != "exited" || len(y1.Backends) != 0 || y1.Source != "portainer" || y1.AgentName != "ag" {
		t.Fatalf("y est inactif, arrêté, sans backend : %+v", y1)
	}
}

// Quand un conteneur démarre, sa route apparaît et l'entrée inactive disparaît ; l'inverse à l'arrêt.
func TestContainerMovesBetweenActiveAndInactive(t *testing.T) {
	n := newStateNode(t, "frontal", groupKey, []string{"frontal", "backup"})
	const y = "yyyyyyyyyyyy2222"
	putAgentState(t, n, stateWithInactive("portainer", "1", 1, nil, inactive(y, "y.example.fr", "exited")))
	if c, ok := find(listContainers(t, n, ""), "y.example.fr"); !ok || !c.Inactive {
		t.Fatalf("arrêté : %+v", c)
	}

	putAgentState(t, n, stateWithInactive("portainer", "1", 2, []map[string]any{portainerRoute("1", y, "y.example.fr", "http://10.1.0.2:80")}))
	c, ok := find(listContainers(t, n, ""), "y.example.fr")
	if !ok || c.Inactive || !hasHost(n, "y.example.fr") {
		t.Fatalf("démarré : %+v, route servie %v", c, hasHost(n, "y.example.fr"))
	}

	putAgentState(t, n, stateWithInactive("portainer", "1", 3, nil, inactive(y, "y.example.fr", "exited")))
	c, ok = find(listContainers(t, n, ""), "y.example.fr")
	if !ok || !c.Inactive || hasHost(n, "y.example.fr") {
		t.Fatalf("arrêté de nouveau : %+v, route servie %v", c, hasHost(n, "y.example.fr"))
	}
}

// Un conteneur arrêté dont l'hôte est servi par un conteneur qui tourne est masqué (ancien déploiement).
func TestInactiveContainerIsHiddenWhenAnActiveOneServesTheHost(t *testing.T) {
	n := newStateNode(t, "frontal", groupKey, []string{"frontal", "backup"})
	const old, cur = "oooooooooooo0000", "cccccccccccc1111"
	putAgentState(t, n, stateWithInactive("portainer", "1", 1,
		[]map[string]any{portainerRoute("1", cur, "app.example.fr", "http://10.1.0.3:80")},
		inactive(old, "app.example.fr", "exited"), inactive("zzzzzzzzzzzz9999", "autre.example.fr", "paused")))
	list := listContainers(t, n, "")
	n1 := 0
	for _, c := range list {
		if c.Host == "app.example.fr" {
			n1++
			if c.Inactive {
				t.Fatal("l'ancien conteneur arrêté est masqué")
			}
		}
	}
	if n1 != 1 {
		t.Fatalf("une seule entrée pour app.example.fr : %d", n1)
	}
	if c, ok := find(list, "autre.example.fr"); !ok || !c.Inactive || c.State != "paused" {
		t.Fatalf("un autre hôte arrêté reste listé : %+v", c)
	}
}

// Le filtre par Agent s'applique aussi aux inactifs ; les entrées sans hôte ou sans conteneur sont écartées.
func TestInactiveListFiltersByAgentAndDropsBrokenEntries(t *testing.T) {
	n := newStateNode(t, "frontal", groupKey, []string{"frontal", "backup"})
	putAgentState(t, n, stateWithInactive("portainer", "1", 1, nil,
		inactive("aaaaaaaaaaaa1111", "a.example.fr", "exited"),
		map[string]any{"id": "x", "host": "", "container_id": "bbbbbbbbbbbb2222"},
		map[string]any{"id": "y", "host": "c.example.fr", "container_id": ""}))
	if got := listContainers(t, n, ""); len(got) != 1 || got[0].Host != "a.example.fr" {
		t.Fatalf("les entrées incomplètes sont écartées : %+v", got)
	}
	if got := listContainers(t, n, "?agent=autre"); len(got) != 0 {
		t.Fatalf("le filtre par Agent : %+v", got)
	}
}

// Les conteneurs inactifs se répliquent avec l'état : l'autre membre les affiche aussi, et un changement d'état d'un
// conteneur arrêté à en pause est un changement de contenu.
func TestInactiveContainersAreReplicatedAndChangeTheDigest(t *testing.T) {
	members := []string{"frontal", "backup"}
	a, b := newStateNode(t, "frontal", groupKey, members), newStateNode(t, "backup", groupKey, members)
	link(a.haNode, b.haNode)
	const y = "yyyyyyyyyyyy2222"
	putAgentState(t, a, stateWithInactive("portainer", "1", 1, nil, inactive(y, "y.example.fr", "exited")))
	waitFor(t, "le pair affiche le conteneur arrêté", func() bool {
		c, ok := find(listContainers(t, b, ""), "y.example.fr")
		return ok && c.Inactive && c.State == "exited"
	})
	if hasHost(b, "y.example.fr") {
		t.Fatal("le pair ne crée pas de route non plus")
	}

	before := a.srv.agentStates.digest()
	putAgentState(t, a, stateWithInactive("portainer", "1", 2, nil, inactive(y, "y.example.fr", "paused")))
	if a.srv.agentStates.digest() == before {
		t.Fatal("un conteneur qui passe d'arrêté à en pause change le contenu")
	}
	waitFor(t, "le pair apprend la pause", func() bool {
		c, ok := find(listContainers(t, b, ""), "y.example.fr")
		return ok && c.State == "paused"
	})
}

// Les inactifs de Kubernetes et des annuaires suivent les mêmes règles que ceux de Docker et de Portainer : listés avec
// leur état, sans route.
func TestInactiveEntriesOfK8sAndDirectoriesAreListedWithoutRoute(t *testing.T) {
	n := newStateNode(t, "frontal", groupKey, []string{"frontal", "backup"})
	for i, src := range []string{"k8s", "consul", "ecs"} {
		st := stateWithInactive(src, "", int64(i+1), nil, map[string]any{
			"id": src + ":1", "host": src + ".example.fr", "container_id": "k8s:ns/" + src, "name": "ns/" + src, "state": "no-endpoints",
		})
		if code := putAgentState(t, n, st); code != http.StatusOK {
			t.Fatalf("%s : état refusé %d", src, code)
		}
		if hasHost(n, src+".example.fr") {
			t.Fatalf("%s : aucune route pour un inactif", src)
		}
		c, ok := find(listContainers(t, n, ""), src+".example.fr")
		if !ok || !c.Inactive || c.Source != src || c.State != "no-endpoints" {
			t.Fatalf("%s : %+v", src, c)
		}
	}
}
