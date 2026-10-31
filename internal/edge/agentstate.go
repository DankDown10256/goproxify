// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/labels"
)

// État complet d'une source de découverte (ADR 0014, étape 2). Les POST et DELETE d'un conteneur ne disent que ce qui
// change : un retrait manqué laisse une route obsolète pour toujours. L'Agent envoie donc, à la fin d'un scan complet,
// tout ce que la source publie ; la passerelle retire ce qu'elle gardait de cet Agent pour cette source et qui n'y est
// plus.

// poolSource dit comment reconnaître, dans les pools « docker-host: », les backends d'une source : Docker, Kubernetes et
// les annuaires y rangent chacun les leurs, et l'état complet de l'un ne doit toucher que les siens.
type poolSource struct {
	// owns : l'identifiant de conteneur d'un backend vient de cette source.
	owns func(containerID string) bool
	// same : l'identifiant stocké est celui que l'état déclare. Les identifiants Docker sont hexadécimaux et se
	// comparent sur leurs 12 premiers caractères ; ceux de Kubernetes (« k8s:ns/nom ») et des annuaires
	// (« empreinte@source ») partagent des préfixes et se comparent en entier.
	same func(stored, declared string) bool
}

// poolSourceOf rend la règle d'une source qui range ses backends dans les pools, ou faux. Tout nom de source qui n'est
// ni réservé ni Portainer est un annuaire (consul, nomad, etcd, ecs…) : ses backends portent le suffixe « @source ».
func poolSourceOf(source string) (poolSource, bool) {
	switch source {
	case "docker":
		return poolSource{owns: isDockerBackendID, same: containerIDMatch}, true
	case "k8s":
		return poolSource{owns: func(id string) bool { return strings.HasPrefix(id, "k8s:") }, same: sameID}, true
	case "portainer", "podman", "":
		return poolSource{}, false
	}
	if !directorySourceName.MatchString(source) {
		return poolSource{}, false
	}
	suffix := "@" + source
	return poolSource{owns: func(id string) bool { return strings.HasSuffix(id, suffix) }, same: sameID}, true
}

var directorySourceName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

func sameID(stored, declared string) bool { return stored != "" && stored == declared }

type agentStatePayload struct {
	AgentName string `json:"agent_name"`
	Source    string `json:"source"`
	// Scope délimite ce que l'envoi couvre dans la source : l'identifiant de l'endpoint Portainer. Un endpoint dont la
	// liste a échoué n'envoie rien, et ses routes ne sont pas touchées.
	Scope string `json:"scope,omitempty"`
	// Generation croît à chaque envoi pour un même (Agent, source, scope) : un envoi plus ancien qui arrive après un
	// plus récent est ignoré.
	Generation int64                   `json:"generation"`
	Routes     []agentContainerPayload `json:"routes"`
	// Inactive : les conteneurs de la source qui existent sans tourner (arrêtés, en pause, qui redémarrent). Un champ à
	// part, jamais dans Routes : une passerelle qui ne le connaît pas l'ignore, alors qu'elle ferait une route d'une entrée
	// de Routes. Ces entrées ne créent aucune route ; elles servent à l'inventaire que l'Admin affiche.
	Inactive []inactiveEntry `json:"inactive,omitempty"`
}

// inactiveEntry est un conteneur découvert qui ne tourne pas.
type inactiveEntry struct {
	ID          string   `json:"id"`
	Host        string   `json:"host"`
	Aliases     []string `json:"aliases,omitempty"`
	ContainerID string   `json:"container_id"`
	Name        string   `json:"name,omitempty"`
	State       string   `json:"state,omitempty"`
}

type agentStateResult struct {
	Applied  int `json:"applied"`
	Rejected int `json:"rejected"`
	Pruned   int `json:"pruned"`
	// changed : le contenu diffère du dernier état retenu pour cette clé. Un Agent renvoie son état complet à chaque
	// scan avec une génération plus récente, même quand rien n'a bougé : seul un changement est transmis aux pairs et
	// journalisé.
	changed bool
}

// agentGenerations retient la dernière génération acceptée par (Agent, source, scope). En mémoire seulement : après
// un redémarrage de la passerelle tout envoi est accepté, ce qui convient puisque l'Agent renvoie son état.
type agentGenerations struct {
	mu   sync.Mutex
	last map[string]int64
}

func (g *agentGenerations) accept(key string, gen int64) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.last == nil {
		g.last = map[string]int64{}
	}
	if gen <= g.last[key] {
		return false
	}
	g.last[key] = gen
	return true
}

func (g *agentGenerations) kept(key string) int64 {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.last[key]
}

func (st *agentStatePayload) key() string { return st.AgentName + "|" + st.Source + "|" + st.Scope }

func (s *Server) handleAgentState(w http.ResponseWriter, r *http.Request) {
	var st agentStatePayload
	if err := json.NewDecoder(r.Body).Decode(&st); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !s.agentMayActAs(w, r, st.AgentName) {
		return
	}
	res, status, msg := s.acceptAgentState(&st)
	if status == http.StatusConflict {
		// L'Agent compte un 409 comme « envoyé » : sans cette ligne, un état ignoré en continu (génération retenue en
		// avance de l'horloge de l'Agent, par exemple venue d'un pair) laisse des routes manquer sans aucune trace.
		if log, n := s.blockLog.Allow("generation|" + st.key()); log {
			s.log.Warn("agent: état complet ignoré, génération dépassée", "agent", st.AgentName, "source", st.Source, "scope", st.Scope, "reçue", st.Generation, "retenue", s.agentGen.kept(st.key()), "ignorés depuis la dernière ligne", n)
		}
	}
	if status != http.StatusOK {
		http.Error(w, msg, status)
		return
	}
	if res.changed {
		s.scheduleAgentStatePush(st.key())
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res) //nolint:errcheck
}

// acceptAgentState applique l'état complet d'une source : chaque route, puis le retrait de ce que l'Agent ne déclare
// plus. Rend le code HTTP à répondre (200 si tout va bien). L'état reçu directement de l'Agent et celui qu'un pair du
// groupe transmet passent par ici ; la génération écarte ce qui est déjà dépassé, quel que soit le chemin pris.
func (s *Server) acceptAgentState(st *agentStatePayload) (res agentStateResult, status int, msg string) {
	if err := st.validate(); err != nil {
		return res, http.StatusBadRequest, err.Error()
	}
	if !s.agentGen.accept(st.key(), st.Generation) {
		return res, http.StatusConflict, "génération déjà dépassée"
	}

	hostContainers := map[string][]string{}
	routeIDs := map[string]bool{}
	for i := range st.Routes {
		p := &st.Routes[i]
		// Une route refusée (labels de sécurité invalides) reste déclarée : on ne retire pas la route existante
		// parce que ses labels viennent d'être mal écrits.
		host, _ := labels.ParseHostEntry(p.Host)
		hostContainers[strings.ToLower(host)] = append(hostContainers[strings.ToLower(host)], p.ContainerID)
		routeIDs[p.ID] = true
		if code, why := s.applyAgentRoute(p); code != http.StatusNoContent {
			res.Rejected++
			s.log.Warn("agent: route de l'état complet refusée", "host", p.Host, "agent", st.AgentName, "source", st.Source, "status", code, "err", why)
			continue
		}
		res.Applied++
	}
	res.Pruned = s.pruneAgentSource(st, hostContainers, routeIDs)
	if res.Pruned > 0 {
		metrics.Edge.RouteCount.Set(float64(s.table.Len()))
		s.log.Info("agent: routes obsolètes retirées par l'état complet", "agent", st.AgentName, "source", st.Source, "scope", st.Scope, "retirées", res.Pruned)
	}
	res.changed = s.agentStates.put(st)
	if res.changed && len(st.Inactive) > 0 {
		s.log.Info("agent: conteneurs inactifs retenus", "agent", st.AgentName, "source", st.Source, "scope", st.Scope, "inactifs", len(st.Inactive))
	}
	return res, http.StatusOK, ""
}

func (st *agentStatePayload) validate() error {
	if st.AgentName == "" {
		return fmt.Errorf("agent_name requis")
	}
	if _, pool := poolSourceOf(st.Source); !pool && st.Source != "portainer" {
		return fmt.Errorf("source %q sans état complet", st.Source)
	}
	if st.Generation <= 0 {
		return fmt.Errorf("generation requise")
	}
	kept := st.Inactive[:0]
	for _, in := range st.Inactive {
		if in.Host != "" && in.ContainerID != "" {
			kept = append(kept, in)
		}
	}
	st.Inactive = kept
	for i := range st.Routes {
		p := &st.Routes[i]
		if p.AgentName == "" {
			p.AgentName = st.AgentName
		}
		if p.AgentName != st.AgentName {
			return fmt.Errorf("route d'un autre Agent (%q) dans l'état de %q", p.AgentName, st.AgentName)
		}
		if p.Source == "" {
			p.Source = st.Source
		}
		if p.Source != st.Source {
			return fmt.Errorf("route de source %q dans l'état de %q", p.Source, st.Source)
		}
		if st.Source == "portainer" && st.Scope != "" && !strings.HasPrefix(p.ID, "portainer:"+st.Scope+":") {
			return fmt.Errorf("route %q hors de l'endpoint %q", p.ID, st.Scope)
		}
	}
	return nil
}

// pruneAgentSource retire ce que la passerelle garde de cet Agent pour cette source et que l'état complet ne contient
// plus. Rend le nombre de routes supprimées ou réduites.
func (s *Server) pruneAgentSource(st *agentStatePayload, hostContainers map[string][]string, routeIDs map[string]bool) int {
	pruned := 0
	for _, rt := range s.table.All() {
		switch st.Source {
		case "portainer":
			if !strings.HasPrefix(rt.ID, "portainer:") || rt.AgentName != st.AgentName {
				continue
			}
			if st.Scope != "" && portainerEndpointOf(rt.ID) != st.Scope {
				continue
			}
			if s.prunePortainerRoute(rt, hostContainers[strings.ToLower(rt.Host)], routeIDs[rt.ID]) {
				pruned++
			}
		default:
			ps, pool := poolSourceOf(st.Source)
			if pool && isDockerDiscoveryRoute(rt) && s.prunePoolRoute(rt, st.AgentName, hostContainers[strings.ToLower(rt.Host)], ps) {
				pruned++
			}
		}
	}
	return pruned
}

// prunePortainerRoute retire d'une route Portainer les backends dont le conteneur n'est plus déclaré pour son hôte. Une
// route ne se juge pas sur son identifiant : il porte celui du premier conteneur de l'hôte, et un conteneur recréé vient
// s'ajouter à la route existante sans la renommer. La route disparaît quand il ne lui reste rien, avec son identifiant
// non déclaré ; un backend sans conteneur connu ne survit que si l'identifiant de la route est déclaré.
func (s *Server) prunePortainerRoute(rt *router.Route, declared []string, idDeclared bool) bool {
	kept := make([]router.Backend, 0, len(rt.Backends))
	changed := false
	for _, b := range rt.Backends {
		if b.OwnerEdgeEndpoint != "" || slices.Contains(declared, b.ContainerID) || b.ContainerID == "" && idDeclared {
			kept = append(kept, b)
			continue
		}
		changed = true
	}
	if rt.Canary != nil && !slices.Contains(declared, rt.Canary.ContainerID) {
		rt.Canary = nil
		changed = true
	}
	if rt.Shadow != nil && !slices.Contains(declared, rt.Shadow.ContainerID) {
		rt.Shadow = nil
		changed = true
	}
	if !changed {
		return false
	}
	rt.Backends = kept
	if len(kept) == 0 && rt.Canary == nil && rt.Shadow == nil {
		s.table.Delete(rt.ID)
		return true
	}
	s.table.Upsert(rt)
	return true
}

// portainerEndpointOf extrait l'identifiant d'endpoint de « portainer:{endpoint}:{conteneur}:{hôte} ».
func portainerEndpointOf(routeID string) string {
	parts := strings.SplitN(routeID, ":", 3)
	if len(parts) < 3 {
		return ""
	}
	return parts[1]
}

// isDockerBackendID : un conteneur Docker, par opposition à une instance d'annuaire (« …@source ») ou Kubernetes
// (« k8s:… ») qui réutilisent les routes « docker-host: ».
func isDockerBackendID(id string) bool {
	return id != "" && !strings.Contains(id, "@") && !strings.HasPrefix(id, "k8s:")
}

func (ps poolSource) declared(declared []string, id string) bool {
	for _, d := range declared {
		if ps.same(id, d) {
			return true
		}
	}
	return false
}

// prunePoolRoute retire d'une route à pool les backends, canary et shadow de cet Agent et de cette source que l'état
// complet ne déclare pas pour cet hôte. La route disparaît quand il ne lui reste rien.
func (s *Server) prunePoolRoute(rt *router.Route, agent string, declared []string, ps poolSource) bool {
	kept := make([]router.Backend, 0, len(rt.Backends))
	changed := false
	for _, b := range rt.Backends {
		owner := b.AgentName
		if owner == "" {
			owner = rt.AgentName
		}
		if b.OwnerEdgeEndpoint != "" || owner != agent || !ps.owns(b.ContainerID) || ps.declared(declared, b.ContainerID) {
			kept = append(kept, b)
			continue
		}
		changed = true
	}
	if rt.AgentName == agent {
		if rt.Canary != nil && ps.owns(rt.Canary.ContainerID) && !ps.declared(declared, rt.Canary.ContainerID) {
			rt.Canary = nil
			changed = true
		}
		if rt.Shadow != nil && ps.owns(rt.Shadow.ContainerID) && !ps.declared(declared, rt.Shadow.ContainerID) {
			rt.Shadow = nil
			changed = true
		}
	}
	if !changed {
		return false
	}
	rt.Backends = kept
	if len(kept) == 0 && rt.Canary == nil && rt.Shadow == nil {
		s.table.Delete(rt.ID)
		return true
	}
	s.table.Upsert(rt)
	return true
}
