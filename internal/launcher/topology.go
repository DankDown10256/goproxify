// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package launcher construit, à partir d'une topologie (hôtes et rôles), tout ce qu'il faut pour installer GoProxify
// sur un hôte : secrets, certificat de l'Admin, architecture.json et description de chaque hôte (ADR 0019).
package launcher

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/archstore"
)

// Rôles d'un hôte.
const (
	RoleAdmin = "admin"
	RoleEdge  = "edge"
	RoleAgent = "agent"
)

// Port d'écoute de l'API interne d'une passerelle (hub WebSocket des Admin et Agents).
const edgeHubPort = 8000

// Host est un serveur de l'infrastructure.
type Host struct {
	Name  string   `json:"name"`
	Addr  string   `json:"addr"`
	Roles []string `json:"roles"`
	// Group est le groupe HA de la passerelle de l'hôte ; vide = groupe d'un seul membre, nommé par GroupOf (ADR 0014).
	Group string `json:"group,omitempty"`

	// Renseignés quand la topologie est relue d'architecture.json (TopologyFromArchitecture) : les noms et identifiants
	// des nœuds déclarés font alors foi, au lieu d'être calculés. Absents d'un fichier de topologie.
	EdgeNode, EdgeID, AgentNode, AgentID string `json:"-"`
	// AgentTarget est la passerelle choisie pour l'Agent : le nom d'un nœud, ou `ha:<groupe>`.
	AgentTarget string `json:"-"`
}

// Topology est l'infrastructure à installer. Local est l'hôte sur lequel tourne le launcher.
type Topology struct {
	Hosts []Host `json:"hosts"`
	Local string `json:"local"`
}

var (
	nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
	addrRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)
)

func knownRole(r string) bool { return r == RoleAdmin || r == RoleEdge || r == RoleAgent }

// ParseRoles lit une liste de rôles séparés par des virgules.
func ParseRoles(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, r := range strings.Split(s, ",") {
		r = strings.TrimSpace(r)
		if !knownRole(r) {
			return nil, fmt.Errorf("rôle %q inconnu (admin, edge ou agent)", r)
		}
		if seen[r] {
			return nil, fmt.Errorf("rôle %q répété", r)
		}
		seen[r] = true
		out = append(out, r)
	}
	return out, nil
}

// DefaultHostName nomme un hôte d'après son adresse.
func DefaultHostName(addr string) string {
	return "host-" + regexp.MustCompile(`[^a-zA-Z0-9]+`).ReplaceAllString(addr, "-")
}

// ParseHost lit `[nom=]adresse[:rôles][@groupe]`, ou `adresse=rôles`. Sans rôle, l'hôte reçoit un Agent. L'adresse est
// une IPv4 ou un nom DNS.
func ParseHost(s string) (Host, error) {
	s = strings.TrimSpace(s)
	var h Host
	if i := strings.LastIndex(s, "@"); i >= 0 {
		h.Group, s = s[i+1:], s[:i]
	}
	name, rest := "", s
	if l, r, ok := strings.Cut(s, "="); ok {
		if _, err := ParseRoles(r); net.ParseIP(l) != nil && !strings.Contains(r, ":") && err == nil {
			rest = l + ":" + r
		} else {
			name, rest = l, r
		}
	}
	if h.Group != "" && !nameRe.MatchString(h.Group) {
		return Host{}, fmt.Errorf("groupe %q invalide dans %q", h.Group, s)
	}
	addr, roles := rest, RoleAgent
	if a, r, ok := strings.Cut(rest, ":"); ok {
		addr, roles = a, r
	}
	if !addrRe.MatchString(addr) {
		return Host{}, fmt.Errorf("adresse %q invalide dans %q", addr, s)
	}
	rs, err := ParseRoles(roles)
	if err != nil {
		return Host{}, fmt.Errorf("%q : %w", s, err)
	}
	if name == "" {
		name = DefaultHostName(addr)
	}
	h.Name, h.Addr, h.Roles = name, addr, rs
	return h, nil
}

// Has dit si l'hôte porte le rôle.
func (h Host) Has(role string) bool {
	for _, r := range h.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Validate vérifie la cohérence de la topologie avant d'installer quoi que ce soit.
func (t *Topology) Validate() error {
	if len(t.Hosts) == 0 {
		return fmt.Errorf("aucun hôte")
	}
	names := map[string]bool{}
	admins, edges := 0, 0
	for _, h := range t.Hosts {
		if !nameRe.MatchString(h.Name) {
			return fmt.Errorf("hôte %q : nom invalide", h.Name)
		}
		if names[h.Name] {
			return fmt.Errorf("hôte %q déclaré deux fois", h.Name)
		}
		names[h.Name] = true
		if !addrRe.MatchString(h.Addr) {
			return fmt.Errorf("hôte %q : adresse %q invalide", h.Name, h.Addr)
		}
		if len(h.Roles) == 0 {
			return fmt.Errorf("hôte %q : aucun rôle", h.Name)
		}
		seen := map[string]bool{}
		for _, r := range h.Roles {
			if !knownRole(r) || seen[r] {
				return fmt.Errorf("hôte %q : rôle %q inconnu ou répété", h.Name, r)
			}
			seen[r] = true
		}
		if h.Group != "" {
			if !nameRe.MatchString(h.Group) {
				return fmt.Errorf("hôte %q : groupe %q invalide", h.Name, h.Group)
			}
			if !h.Has(RoleEdge) {
				return fmt.Errorf("hôte %q : un groupe HA ne concerne que les passerelles", h.Name)
			}
		}
		if h.Has(RoleAdmin) {
			admins++
		}
		if h.Has(RoleEdge) {
			edges++
		}
	}
	if admins != 1 {
		return fmt.Errorf("il faut exactement un Admin (%d déclarés)", admins)
	}
	if edges == 0 {
		return fmt.Errorf("il faut au moins une passerelle")
	}
	local, ok := t.host(t.Local)
	if !ok {
		return fmt.Errorf("hôte local %q absent de la topologie", t.Local)
	}
	if !local.Has(RoleAdmin) {
		return fmt.Errorf("l'hôte local %q n'a pas le rôle admin : ce mode installe l'Admin (rejoindre une infrastructure existante se fait par ticket)", local.Name)
	}
	return nil
}

func (t *Topology) host(name string) (Host, bool) {
	for _, h := range t.Hosts {
		if h.Name == name {
			return h, true
		}
	}
	return Host{}, false
}

// AdminHost est l'hôte de l'Admin.
func (t *Topology) AdminHost() Host {
	for _, h := range t.Hosts {
		if h.Has(RoleAdmin) {
			return h
		}
	}
	return Host{}
}

func (t *Topology) count(role string) int {
	n := 0
	for _, h := range t.Hosts {
		if h.Has(role) {
			n++
		}
	}
	return n
}

// EdgeName est le nom de nœud de la passerelle d'un hôte. Une passerelle unique garde le nom du démarrage rapide
// (`goproxify-edge`) ; sinon le nom porte celui de l'hôte.
func (t *Topology) EdgeName(h Host) string {
	if h.EdgeNode != "" {
		return h.EdgeNode
	}
	if t.count(RoleEdge) == 1 {
		return "goproxify-edge"
	}
	return h.Name + "-edge"
}

// AgentName est le nom de nœud de l'Agent d'un hôte, construit comme EdgeName.
func (t *Topology) AgentName(h Host) string {
	if h.AgentNode != "" {
		return h.AgentNode
	}
	if t.count(RoleAgent) == 1 {
		return "goproxify-agent"
	}
	return h.Name + "-agent"
}

// EdgeNodeID est l'identifiant (dn_…) du nœud de la passerelle d'un hôte : celui de l'architecture déclarée, sinon
// celui que le launcher lui donne.
func (t *Topology) EdgeNodeID(h Host) string {
	if h.EdgeID != "" {
		return h.EdgeID
	}
	return nodeID(RoleEdge, t.EdgeName(h))
}

// AgentNodeID est l'équivalent de EdgeNodeID pour l'Agent.
func (t *Topology) AgentNodeID(h Host) string {
	if h.AgentID != "" {
		return h.AgentID
	}
	return nodeID(RoleAgent, t.AgentName(h))
}

// GroupOf est le groupe HA de la passerelle d'un hôte. Toute passerelle appartient à un groupe (ADR 0014, section 1) :
// sans groupe déclaré, elle forme le sien, d'un seul membre. Vide pour un hôte sans passerelle.
func (t *Topology) GroupOf(h Host) string {
	if !h.Has(RoleEdge) {
		return ""
	}
	if h.Group != "" {
		return h.Group
	}
	return "ha-" + h.Name
}

// TargetEdge est la passerelle à laquelle l'Agent d'un hôte s'appaire : celle que sa déclaration désigne (un nœud, ou
// un groupe `ha:<groupe>`), sinon celle de son hôte, sinon la première déclarée.
func (t *Topology) TargetEdge(h Host) Host {
	if target := h.AgentTarget; target != "" {
		group, isGroup := strings.CutPrefix(target, "ha:")
		for _, o := range t.Hosts {
			if !o.Has(RoleEdge) {
				continue
			}
			if (isGroup && t.GroupOf(o) == group) || (!isGroup && t.EdgeName(o) == target) {
				return o
			}
		}
	}
	if h.Has(RoleEdge) {
		return h
	}
	for _, o := range t.Hosts {
		if o.Has(RoleEdge) {
			return o
		}
	}
	return Host{}
}

// agentTargetRef est la cible d'un Agent telle que l'Admin la lit dans architecture.json : le groupe HA de sa
// passerelle (`ha:<groupe>`), sauf si une passerelle précise a été choisie explicitement.
func (t *Topology) agentTargetRef(h Host) string {
	if target := h.AgentTarget; target != "" && !strings.HasPrefix(target, "ha:") {
		return target
	}
	edge := t.TargetEdge(h)
	if group := t.GroupOf(edge); group != "" {
		return "ha:" + group
	}
	return t.EdgeName(edge)
}

func nodeID(role, name string) string {
	sum := sha256.Sum256([]byte(role + ":" + name))
	return "dn_" + hex.EncodeToString(sum[:])[:12]
}

// Architecture produit architecture.json, la source de vérité de la topologie : une entrée par passerelle et par
// Agent. Les hôtes autres que le local ne sont pas à acceptation automatique : un ticket valide le devient pour le
// temps de sa validité (ADR 0015, étape 3). L'Admin n'est pas un nœud de l'architecture.
func (t *Topology) Architecture() *archstore.Architecture {
	arch := &archstore.Architecture{SchemaVersion: 1}
	for _, h := range t.Hosts {
		remote := h.Name != t.Local
		if h.Has(RoleEdge) {
			name := t.EdgeName(h)
			endpoint := fmt.Sprintf("http://%s:%d", h.Addr, edgeHubPort)
			if !remote {
				endpoint = fmt.Sprintf("http://%s:%d", name, edgeHubPort)
			}
			cfg := map[string]any{
				"host": h.Name, "reachable_host": fmt.Sprintf("%s:%d", h.Addr, edgeHubPort), "internet_exposed": false,
				"cluster": true, "cluster_group": t.GroupOf(h),
			}
			arch.Nodes = append(arch.Nodes, archstore.NodeEntry{
				ID: t.EdgeNodeID(h), Role: RoleEdge, Name: name, Endpoint: endpoint, Config: mustJSON(cfg),
			})
		}
		if h.Has(RoleAgent) {
			name := t.AgentName(h)
			cfg := map[string]any{
				"host": h.Name, "reachable_host": h.Addr, "internet_exposed": false,
				"docker": true, "target_edge": t.agentTargetRef(h),
			}
			arch.Nodes = append(arch.Nodes, archstore.NodeEntry{
				ID: t.AgentNodeID(h), Role: RoleAgent, Name: name, Config: mustJSON(cfg),
			})
		}
	}
	return arch
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
