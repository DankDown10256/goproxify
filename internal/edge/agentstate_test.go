// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func putState(t *testing.T, s *Server, st map[string]any) (int, agentStateResult) {
	t.Helper()
	b, _ := json.Marshal(st)
	req := httptest.NewRequest(http.MethodPut, "/internal/v1/agent/state", bytes.NewReader(b))
	rr := httptest.NewRecorder()
	s.handleAgentState(rr, req)
	var res agentStateResult
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
	}
	return rr.Code, res
}

func dockerRoute(host, cid, backend string) map[string]any {
	return map[string]any{
		"id": "docker:" + cid[:12] + ":" + host, "host": host, "backends": []string{backend},
		"source": "docker", "container_id": cid, "agent_name": "ag",
	}
}

func portainerRoute(endpoint, cid, host, backend string) map[string]any {
	return map[string]any{
		"id": "portainer:" + endpoint + ":" + cid[:12] + ":" + host, "host": host, "backends": []string{backend},
		"source": "portainer", "container_id": cid, "agent_name": "ag", "endpoint_id": 1,
	}
}

func state(source, scope string, gen int64, routes ...map[string]any) map[string]any {
	return map[string]any{"agent_name": "ag", "source": source, "scope": scope, "generation": gen, "routes": routes}
}

func TestAgentStatePrunesDockerBackendsNoLongerDeclared(t *testing.T) {
	s := testEdgeServer()
	const a, b, c = "aaaaaaaaaaaa1111", "bbbbbbbbbbbb2222", "cccccccccccc3333"
	for _, r := range []map[string]any{
		dockerRoute("app.example.fr", a, "http://10.0.0.1:80"),
		dockerRoute("app.example.fr", b, "http://10.0.0.2:80"),
		dockerRoute("gone.example.fr", c, "http://10.0.0.3:80"),
	} {
		body, _ := json.Marshal(r)
		rr := httptest.NewRecorder()
		s.handleAgentContainerStart(rr, httptest.NewRequest(http.MethodPost, "/internal/v1/agent/containers", bytes.NewReader(body)))
		if rr.Code != http.StatusNoContent {
			t.Fatalf("seed %v: %d", r["host"], rr.Code)
		}
	}

	code, res := putState(t, s, state("docker", "", 1, dockerRoute("app.example.fr", a, "http://10.0.0.1:80")))
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if res.Applied != 1 || res.Pruned != 2 {
		t.Fatalf("résultat %+v, attendu 1 appliquée et 2 retirées", res)
	}
	rt, ok := s.table.ByHost("app.example.fr")
	if !ok || len(rt.Backends) != 1 || rt.Backends[0].ContainerID != a {
		t.Fatalf("le pool doit ne garder que %s, obtenu %+v", a, rt)
	}
	if _, ok := s.table.ByHost("gone.example.fr"); ok {
		t.Fatal("la route sans conteneur déclaré doit disparaître")
	}
}

func TestAgentStateKeepsOtherAgentsAndOtherSources(t *testing.T) {
	s := testEdgeServer()
	s.table.Upsert(&router.Route{
		ID: "docker-host:mixed.example.fr", Host: "mixed.example.fr", AgentName: "ag",
		Backends: []router.Backend{
			{URL: "http://10.0.0.1:80", ContainerID: "aaaaaaaaaaaa1111", AgentName: "ag"},
			{URL: "http://10.0.0.9:80", ContainerID: "other-agent-container", AgentName: "other"},
			{URL: "http://10.0.0.8:80", ContainerID: "abcd@consul", AgentName: "ag"},
			{URL: "http://10.0.0.7:80", ContainerID: "k8s:svc", AgentName: "ag"},
			{URL: "http://10.0.0.6:80", ContainerID: "peer-owned", AgentName: "ag", OwnerEdgeEndpoint: "http://peer:8000"},
		},
	})
	s.table.Upsert(&router.Route{ID: "portainer:1:abcdef012345:p.example.fr", Host: "p.example.fr", AgentName: "ag",
		Backends: []router.Backend{{URL: "http://10.0.0.5:80"}}})

	code, res := putState(t, s, state("docker", "", 1, dockerRoute("other.example.fr", "dddddddddddd4444", "http://10.0.0.4:80")))
	if code != http.StatusOK || res.Pruned != 1 {
		t.Fatalf("seule la part Docker de l'Agent est retirée : status %d, %+v", code, res)
	}
	rt, ok := s.table.ByHost("mixed.example.fr")
	if !ok || len(rt.Backends) != 4 {
		t.Fatalf("backends d'un autre Agent, d'un annuaire, de Kubernetes ou d'un pair gardés : %+v", rt)
	}
	for _, b := range rt.Backends {
		if b.ContainerID == "aaaaaaaaaaaa1111" {
			t.Fatal("le backend Docker de l'Agent, non déclaré, doit être retiré")
		}
	}
	if _, ok := s.table.ByID("portainer:1:abcdef012345:p.example.fr"); !ok {
		t.Fatal("l'état Docker ne touche pas une route Portainer")
	}
}

func TestAgentStatePortainerScopeAndRejectedRoute(t *testing.T) {
	s := testEdgeServer()
	const x, y, z = "xxxxxxxxxxxx1111", "yyyyyyyyyyyy2222", "zzzzzzzzzzzz3333"
	seed := state("portainer", "1", 1,
		portainerRoute("1", x, "x.example.fr", "http://10.1.0.1:80"),
		portainerRoute("1", y, "y.example.fr", "http://10.1.0.2:80"))
	if code, _ := putState(t, s, seed); code != http.StatusOK {
		t.Fatalf("seed %d", code)
	}
	if code, _ := putState(t, s, state("portainer", "2", 1, portainerRoute("2", z, "z.example.fr", "http://10.2.0.1:80"))); code != http.StatusOK {
		t.Fatal("seed endpoint 2")
	}

	// L'endpoint 1 ne déclare plus que x : y disparaît, l'endpoint 2 n'est pas touché.
	code, res := putState(t, s, state("portainer", "1", 2, portainerRoute("1", x, "x.example.fr", "http://10.1.0.1:80")))
	if code != http.StatusOK || res.Pruned != 1 {
		t.Fatalf("status %d, %+v", code, res)
	}
	if _, ok := s.table.ByID("portainer:1:" + y[:12] + ":y.example.fr"); ok {
		t.Fatal("la route de y devait être retirée")
	}
	if _, ok := s.table.ByID("portainer:2:" + z[:12] + ":z.example.fr"); !ok {
		t.Fatal("l'état de l'endpoint 1 ne doit pas toucher l'endpoint 2")
	}

	// Une route refusée reste déclarée : la route existante n'est pas retirée.
	bad := portainerRoute("1", x, "x.example.fr", "http://10.1.0.1:80")
	bad["waf"] = map[string]any{"mode": "pas-un-mode"}
	bad["label_errors"] = []string{"waf: mode inconnu"}
	code, res = putState(t, s, state("portainer", "1", 3, bad))
	if code != http.StatusOK || res.Rejected != 1 || res.Pruned != 0 {
		t.Fatalf("une route refusée n'est pas élaguée : status %d, %+v", code, res)
	}
	if _, ok := s.table.ByID("portainer:1:" + x[:12] + ":x.example.fr"); !ok {
		t.Fatal("la route existante doit survivre au refus de sa nouvelle version")
	}
}

// Un conteneur recréé change d'identifiant, donc d'identifiant de route : la route existante de l'hôte reçoit son
// backend, et l'état complet qui suit ne doit pas la retirer parce que son identifiant est celui de l'ancien conteneur.
func TestAgentStatePortainerRecreatedContainerKeepsItsRoute(t *testing.T) {
	s := testEdgeServer()
	const host = "app.example.fr"
	const old, fresh = "aaaaaaaaaaaa1111", "bbbbbbbbbbbb2222"
	if code, _ := putState(t, s, state("portainer", "1", 1, portainerRoute("1", old, host, "http://10.1.0.1:32768"))); code != http.StatusOK {
		t.Fatalf("seed %d", code)
	}

	code, res := putState(t, s, state("portainer", "1", 2, portainerRoute("1", fresh, host, "http://10.1.0.1:32771")))
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	rt, ok := s.table.ByHost(host)
	if !ok {
		t.Fatalf("la route de %s a disparu après la recréation du conteneur (%+v)", host, res)
	}
	if len(rt.Backends) != 1 || rt.Backends[0].ContainerID != fresh || rt.Backends[0].URL != "http://10.1.0.1:32771" {
		t.Fatalf("le pool ne doit garder que le nouveau conteneur : %+v", rt.Backends)
	}
}

// Dans un pool de deux conteneurs, la recréation de l'un ne laisse ni son ancien backend (port mort) ni l'autre en moins.
func TestAgentStatePortainerPoolDropsOnlyTheReplacedBackend(t *testing.T) {
	s := testEdgeServer()
	const host = "app.example.fr"
	const a, b, b2 = "aaaaaaaaaaaa1111", "bbbbbbbbbbbb2222", "cccccccccccc3333"
	if code, _ := putState(t, s, state("portainer", "1", 1,
		portainerRoute("1", a, host, "http://10.1.0.1:8081"),
		portainerRoute("1", b, host, "http://10.1.0.1:8082"))); code != http.StatusOK {
		t.Fatalf("seed %d", code)
	}

	if code, _ := putState(t, s, state("portainer", "1", 2,
		portainerRoute("1", a, host, "http://10.1.0.1:8081"),
		portainerRoute("1", b2, host, "http://10.1.0.1:8083"))); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	rt, ok := s.table.ByHost(host)
	if !ok {
		t.Fatal("la route doit survivre")
	}
	got := map[string]bool{}
	for _, be := range rt.Backends {
		got[be.ContainerID] = true
	}
	if len(rt.Backends) != 2 || !got[a] || !got[b2] {
		t.Fatalf("attendu les conteneurs %s et %s, obtenu %+v", a, b2, rt.Backends)
	}
}

func TestAgentStateIgnoresAnOlderGeneration(t *testing.T) {
	s := testEdgeServer()
	const a = "aaaaaaaaaaaa1111"
	if code, _ := putState(t, s, state("docker", "", 5, dockerRoute("app.example.fr", a, "http://10.0.0.1:80"))); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	// Un envoi plus ancien, arrivé en retard, ne doit rien retirer ni rien rétablir.
	if code, _ := putState(t, s, state("docker", "", 4)); code != http.StatusConflict {
		t.Fatalf("génération dépassée : status %d, attendu 409", code)
	}
	if code, _ := putState(t, s, state("docker", "", 5)); code != http.StatusConflict {
		t.Fatalf("même génération : status %d, attendu 409", code)
	}
	if _, ok := s.table.ByHost("app.example.fr"); !ok {
		t.Fatal("un envoi ignoré ne doit rien retirer")
	}
}

func TestAgentStateRejectsInconsistentPayloads(t *testing.T) {
	s := testEdgeServer()
	const a = "aaaaaaaaaaaa1111"
	other := dockerRoute("app.example.fr", a, "http://10.0.0.1:80")
	other["agent_name"] = "someone-else"
	cases := map[string]map[string]any{
		"source sans état complet": state("podman", "", 1),
		"nom de source invalide":   state("Consul?", "", 1),
		"génération absente":       state("docker", "", 0),
		"route d'un autre Agent":   state("docker", "", 1, other),
		"route d'une autre source": state("docker", "", 1, portainerRoute("1", a, "app.example.fr", "http://10.0.0.1:80")),
		"route hors de l'endpoint": state("portainer", "2", 1, portainerRoute("1", a, "app.example.fr", "http://10.0.0.1:80")),
	}
	for name, st := range cases {
		if code, _ := putState(t, s, st); code != http.StatusBadRequest {
			t.Errorf("%s : status %d, attendu 400", name, code)
		}
	}
}

func TestAgentTokenMayPutState(t *testing.T) {
	if !agentTokenMayCall(http.MethodPut, "/internal/v1/agent/state") {
		t.Fatal("un jeton d'Agent doit pouvoir envoyer l'état complet")
	}
	if agentTokenMayCall(http.MethodPut, "/internal/v1/routes") {
		t.Fatal("un jeton d'Agent ne remplace pas les routes de l'Admin")
	}
}

func poolRoute(host, cid, backend, source string) map[string]any {
	return map[string]any{
		"host": host, "backends": []string{backend}, "source": source, "container_id": cid, "agent_name": "ag",
	}
}

func seedPool(t *testing.T, s *Server, routes ...map[string]any) {
	t.Helper()
	for _, r := range routes {
		body, _ := json.Marshal(r)
		rr := httptest.NewRecorder()
		s.handleAgentContainerStart(rr, httptest.NewRequest(http.MethodPost, "/internal/v1/agent/containers", bytes.NewReader(body)))
		if rr.Code != http.StatusNoContent {
			t.Fatalf("seed %v : %d %s", r["host"], rr.Code, rr.Body.String())
		}
	}
}

func backendIDs(t *testing.T, s *Server, host string) []string {
	t.Helper()
	rt, ok := s.table.ByHost(host)
	if !ok {
		return nil
	}
	var ids []string
	for _, b := range rt.Backends {
		ids = append(ids, b.ContainerID)
	}
	return ids
}

// Deux services Kubernetes partagent leurs 12 premiers caractères (« k8s:default/ ») : la comparaison des identifiants
// est exacte, sinon l'un déclaré garderait l'autre.
func TestAgentStateK8sComparesIdentifiersExactly(t *testing.T) {
	s := testEdgeServer()
	seedPool(t, s,
		poolRoute("shop.example.fr", "k8s:default/web-a", "http://10.0.1.1:80", "k8s"),
		poolRoute("shop.example.fr", "k8s:default/web-b", "http://10.0.1.2:80", "k8s"),
		poolRoute("gone.example.fr", "k8s:default/old", "http://10.0.1.3:80", "k8s"),
		dockerRoute("shop.example.fr", "aaaaaaaaaaaa1111", "http://10.0.0.1:80"),
	)

	code, res := putState(t, s, state("k8s", "", 1, poolRoute("shop.example.fr", "k8s:default/web-a", "http://10.0.1.1:80", "k8s")))
	if code != http.StatusOK || res.Pruned != 2 {
		t.Fatalf("status %d, %+v (web-b et old attendus retirés)", code, res)
	}
	ids := backendIDs(t, s, "shop.example.fr")
	if len(ids) != 2 {
		t.Fatalf("web-a (déclaré) et le conteneur Docker (autre source) restent : %v", ids)
	}
	for _, id := range ids {
		if id == "k8s:default/web-b" {
			t.Fatal("web-b doit être retiré : il ne partage que le préfixe de web-a")
		}
	}
	if _, ok := s.table.ByHost("gone.example.fr"); ok {
		t.Fatal("la route Kubernetes sans service déclaré doit disparaître")
	}
}

// Un annuaire n'efface que ses propres instances : ni celles d'un autre annuaire, ni Docker, ni Kubernetes.
func TestAgentStateDirectoryOnlyPrunesItsOwnSource(t *testing.T) {
	s := testEdgeServer()
	seedPool(t, s,
		poolRoute("svc.example.fr", "0123456789abcdef0123456789abcdef@consul", "http://10.0.2.1:80", "consul"),
		poolRoute("svc.example.fr", "fedcba9876543210fedcba9876543210@nomad", "http://10.0.2.2:80", "nomad"),
		poolRoute("svc.example.fr", "k8s:default/web", "http://10.0.2.3:80", "k8s"),
		dockerRoute("svc.example.fr", "aaaaaaaaaaaa1111", "http://10.0.2.4:80"),
		poolRoute("old.example.fr", "11111111111111111111111111111111@consul", "http://10.0.2.5:80", "consul"),
	)

	live := poolRoute("svc.example.fr", "0123456789abcdef0123456789abcdef@consul", "http://10.0.2.1:80", "consul")
	code, res := putState(t, s, state("consul", "", 1, live))
	if code != http.StatusOK || res.Pruned != 1 {
		t.Fatalf("status %d, %+v (seule l'instance consul disparue est retirée)", code, res)
	}
	if got := backendIDs(t, s, "svc.example.fr"); len(got) != 4 {
		t.Fatalf("consul déclaré, nomad, Kubernetes et Docker restent : %v", got)
	}
	if _, ok := s.table.ByHost("old.example.fr"); ok {
		t.Fatal("la route de l'instance consul disparue doit être retirée")
	}

	// Un état vide de consul retire ses instances et laisse les autres sources.
	if code, res := putState(t, s, state("consul", "", 2)); code != http.StatusOK || res.Pruned != 1 {
		t.Fatalf("état vide : status %d, %+v", code, res)
	}
	if got := backendIDs(t, s, "svc.example.fr"); len(got) != 3 {
		t.Fatalf("nomad, Kubernetes et Docker restent : %v", got)
	}
}

// Deux services Kubernetes d'un même namespace restent deux routes : leurs identifiants de conteneur
// (« k8s:default/web-a », « k8s:default/web-b ») partagent leurs 12 premiers caractères, que la passerelle prenait pour
// le même conteneur (le second service était replié dans la route du premier).
func TestK8sServicesOfOneNamespaceStaySeparateRoutes(t *testing.T) {
	s := testEdgeServer()
	seedPool(t, s,
		poolRoute("a.example.fr", "k8s:default/web-a", "http://10.0.1.1:80", "k8s"),
		poolRoute("b.example.fr", "k8s:default/web-b", "http://10.0.1.2:80", "k8s"),
	)
	a, okA := s.table.ByHost("a.example.fr")
	b, okB := s.table.ByHost("b.example.fr")
	if !okA || !okB || a.ID == b.ID {
		t.Fatalf("deux routes attendues : a=%v b=%v", okA, okB)
	}
	if len(a.Backends) != 1 || len(b.Backends) != 1 || a.Backends[0].URL == b.Backends[0].URL {
		t.Fatalf("chaque route garde son seul backend : %+v %+v", a.Backends, b.Backends)
	}
}
