// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"net/http"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

func disabledPush(hosts ...string) edgews.DisabledRoutes {
	return edgews.DisabledRoutes{Hosts: hosts}
}

// Désactiver un hôte retire sa route de la table ; les autres routes de la même source continuent de servir.
func TestDisabledRouteLeavesTheTableButStaysListed(t *testing.T) {
	n := pushedNode(t, "frontal", []string{"frontal", "backup"})
	const x, y = "xxxxxxxxxxxx1111", "yyyyyyyyyyyy2222"
	putAgentState(t, n, state("docker", "", 1,
		dockerRoute("x.example.fr", x, "http://10.0.0.1:80"),
		dockerRoute("y.example.fr", y, "http://10.0.0.2:80")))
	if !hasHost(n, "x.example.fr") {
		t.Fatal("x sert avant la désactivation")
	}

	adminPush(t, n, edgews.TypePushDisabledRoutes, disabledPush("X.example.fr"))
	if hasHost(n, "x.example.fr") {
		t.Fatal("x désactivé ne doit plus être routé")
	}
	if !hasHost(n, "y.example.fr") {
		t.Fatal("y reste servi")
	}
	c, ok := find(listContainers(t, n, ""), "x.example.fr")
	if !ok || !c.Disabled || c.Inactive || len(c.Backends) != 1 || c.Source != "docker" || c.AgentName != "ag" {
		t.Fatalf("x désactivé reste listé : %+v", c)
	}
}

// L'Agent renvoie son état à chaque scan : une route désactivée n'y revient pas dans la table, et ce n'est pas une erreur.
func TestDisabledRouteStaysOffWhenTheAgentAnnouncesItAgain(t *testing.T) {
	n := pushedNode(t, "frontal", []string{"frontal", "backup"})
	const x = "xxxxxxxxxxxx1111"
	putAgentState(t, n, state("docker", "", 1, dockerRoute("x.example.fr", x, "http://10.0.0.1:80")))
	adminPush(t, n, edgews.TypePushDisabledRoutes, disabledPush("x.example.fr"))

	code, res := putState(t, n.srv, state("docker", "", 2, dockerRoute("x.example.fr", x, "http://10.0.0.1:80")))
	if code != http.StatusOK || res.Rejected != 0 {
		t.Fatalf("l'état est accepté sans refus : %d %+v", code, res)
	}
	if hasHost(n, "x.example.fr") {
		t.Fatal("la route désactivée ne revient pas avec l'état de l'Agent")
	}
	// Un démarrage de conteneur annoncé seul ne la ramène pas non plus.
	if st, _ := n.srv.applyAgentRoute(&agentContainerPayload{ID: "docker:" + x[:12] + ":x.example.fr", Host: "x.example.fr", Backends: []string{"http://10.0.0.1:80"}, Source: "docker", ContainerID: x, AgentName: "ag"}); st != http.StatusNoContent {
		t.Fatalf("démarrage ignoré sans erreur : %d", st)
	}
	if hasHost(n, "x.example.fr") {
		t.Fatal("un démarrage isolé ne réactive pas la route")
	}
}

// Réactiver rend la route tout de suite, depuis le dernier état de l'Agent, sans attendre son prochain scan.
func TestEnablingRestoresTheRouteFromTheLastAgentState(t *testing.T) {
	n := pushedNode(t, "frontal", []string{"frontal", "backup"})
	const x, p = "xxxxxxxxxxxx1111", "pppppppppppp3333"
	putAgentState(t, n, state("docker", "", 1, dockerRoute("x.example.fr", x, "http://10.0.0.1:80")))
	putAgentState(t, n, state("portainer", "1", 1, portainerRoute("1", p, "p.example.fr", "http://10.0.0.9:80")))
	adminPush(t, n, edgews.TypePushDisabledRoutes, disabledPush("x.example.fr", "p.example.fr"))
	if hasHost(n, "x.example.fr") || hasHost(n, "p.example.fr") {
		t.Fatal("les deux sont désactivés")
	}

	adminPush(t, n, edgews.TypePushDisabledRoutes, disabledPush("p.example.fr"))
	if !hasHost(n, "x.example.fr") {
		t.Fatal("x réactivé sert de nouveau")
	}
	if hasHost(n, "p.example.fr") {
		t.Fatal("p reste désactivé")
	}
	if c, ok := find(listContainers(t, n, ""), "x.example.fr"); !ok || c.Disabled {
		t.Fatalf("x n'est plus désactivé : %+v", c)
	}

	adminPush(t, n, edgews.TypePushDisabledRoutes, disabledPush())
	if !hasHost(n, "p.example.fr") {
		t.Fatal("p réactivé sert de nouveau, route Portainer comprise")
	}
}

// Un pool de plusieurs conteneurs derrière un même hôte se désactive et se réactive d'un bloc.
func TestDisablingAPoolHostRemovesAllItsBackends(t *testing.T) {
	n := pushedNode(t, "frontal", []string{"frontal", "backup"})
	const a, b = "aaaaaaaaaaaa1111", "bbbbbbbbbbbb2222"
	putAgentState(t, n, state("docker", "", 1,
		dockerRoute("pool.example.fr", a, "http://10.0.0.1:80"),
		dockerRoute("pool.example.fr", b, "http://10.0.0.2:80")))
	adminPush(t, n, edgews.TypePushDisabledRoutes, disabledPush("pool.example.fr"))
	if hasHost(n, "pool.example.fr") {
		t.Fatal("tout le pool est retiré")
	}
	list := listContainers(t, n, "")
	if len(list) != 1 || !list[0].Disabled || len(list[0].Backends) != 2 {
		t.Fatalf("une entrée désactivée pour l'hôte, avec ses deux backends : %+v", list)
	}
	adminPush(t, n, edgews.TypePushDisabledRoutes, disabledPush())
	if got := backendIDs(t, n.srv, "pool.example.fr"); len(got) != 2 {
		t.Fatalf("les deux backends reviennent : %v", got)
	}
}

// Un proxy configuré n'est jamais touché : seule la route issue des labels est retirée.
func TestDisablingNeverTouchesConfiguredProxies(t *testing.T) {
	n := pushedNode(t, "frontal", []string{"frontal", "backup"})
	const x = "xxxxxxxxxxxx1111"
	putAgentState(t, n, state("docker", "", 1, dockerRoute("x.example.fr", x, "http://10.0.0.1:80")))
	n.srv.table.Upsert(&router.Route{ID: "proxy-1", Host: "conf.example.fr", Backends: []router.Backend{{URL: "http://10.0.0.5:80"}}})
	adminPush(t, n, edgews.TypePushDisabledRoutes, disabledPush("x.example.fr", "conf.example.fr"))
	if !hasHost(n, "conf.example.fr") {
		t.Fatal("le proxy configuré garde son hôte")
	}
}

// Un membre qui redémarre pendant la coupure de l'Admin retrouve ses désactivations : le journal est leur copie locale,
// et la route que le cache avait gardée est retirée.
func TestDisabledRoutesSurviveARestart(t *testing.T) {
	n := pushedNode(t, "frontal", []string{"frontal", "backup"})
	const x = "xxxxxxxxxxxx1111"
	putAgentState(t, n, state("docker", "", 1, dockerRoute("x.example.fr", x, "http://10.0.0.1:80")))
	adminPush(t, n, edgews.TypePushDisabledRoutes, disabledPush("x.example.fr"))

	restarted := &Server{cfg: n.srv.cfg, log: n.srv.log, cache: n.srv.cache, table: n.srv.table, certStore: n.srv.certStore, snippetStore: n.srv.snippetStore, providerStore: n.srv.providerStore, ech: n.srv.ech}
	restarted.table.Upsert(&router.Route{ID: "docker-host:x.example.fr", Host: "x.example.fr", Backends: []router.Backend{{URL: "http://10.0.0.1:80"}}})
	restarted.loadPushedJournalFromDisk()
	if !restarted.disabledRoutes.has("x.example.fr") {
		t.Fatal("la désactivation est retrouvée")
	}
	if _, ok := restarted.table.ByHost("x.example.fr"); ok {
		t.Fatal("la route revenue du cache est retirée")
	}
}

// Le pair en retard reçoit la désactivation par le journal du groupe, sans l'Admin.
func TestDisabledRoutesAreReplicatedToAPeer(t *testing.T) {
	members := []string{"frontal", "backup"}
	a, b := pushedNode(t, "frontal", members), pushedNode(t, "backup", members)
	link(a.haNode, b.haNode)
	const x = "xxxxxxxxxxxx1111"
	for _, n := range []*stateNode{a, b} {
		putAgentState(t, n, state("docker", "", 1, dockerRoute("x.example.fr", x, "http://10.0.0.1:80")))
	}
	adminPush(t, a, edgews.TypePushDisabledRoutes, disabledPush("x.example.fr"))
	if !hasHost(b, "x.example.fr") {
		t.Fatal("b n'a rien reçu de l'Admin : il sert encore")
	}
	pullPushed(t, a, b)
	if hasHost(b, "x.example.fr") {
		t.Fatal("b a rattrapé la désactivation auprès de a")
	}
}
