// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package launcher

import (
	"fmt"
	"html"
	"strings"
)

// Le schéma de l'infrastructure, d'après la topologie : le texte Mermaid (à coller dans une doc, un ADR ou Mermaid Live) et
// le même schéma dessiné en SVG, sans bibliothèque : la page du launcher est servie hors ligne, avec une politique de
// sécurité stricte, et donne un accès root, ce qui n'incite pas à y embarquer du JavaScript tiers.

type dgNode struct {
	id, kind, title, sub string
}

type dgHost struct {
	id, title string
	local     bool
	nodes     []dgNode
}

type dgLink struct {
	from, to, kind, label string
}

type diagram struct {
	hosts []dgHost
	links []dgLink
}

const (
	kindAdmin = "admin"
	kindEdge  = "edge"
	kindAgent = "agent"

	linkManage = "manage" // l'Admin pilote une passerelle
	linkRoutes = "routes" // un Agent annonce ses routes à une passerelle
	linkPeers  = "peers"  // deux passerelles d'un même groupe HA
)

// diagram ordonne les hôtes comme la topologie, et dans chacun l'Admin, la passerelle, l'Agent.
func (t *Topology) diagram() diagram {
	var d diagram
	index := map[string]int{}
	for i, h := range t.Hosts {
		if _, dup := index[h.Name]; !dup {
			index[h.Name] = i
		}
	}
	members := map[string]int{} // groupe → nombre de passerelles
	for _, h := range t.Hosts {
		if h.Has(RoleEdge) {
			members[t.GroupOf(h)]++
		}
	}
	nodeID := func(i int, kind string) string { return fmt.Sprintf("h%d_%s", i, kind) }

	for i, h := range t.Hosts {
		dh := dgHost{id: fmt.Sprintf("h%d", i), local: h.Name == t.Local && t.Local != ""}
		dh.title = h.Name
		if h.Addr != "" {
			dh.title += " · " + h.Addr
		}
		if h.Has(RoleAdmin) {
			dh.nodes = append(dh.nodes, dgNode{id: nodeID(i, kindAdmin), kind: kindAdmin, title: "Admin", sub: fmt.Sprintf("https :%d", adminPort)})
		}
		if h.Has(RoleEdge) {
			sub := t.EdgeName(h)
			if g := t.GroupOf(h); members[g] > 1 || h.Group != "" {
				sub += " · " + g
			}
			dh.nodes = append(dh.nodes, dgNode{id: nodeID(i, kindEdge), kind: kindEdge, title: "Passerelle", sub: sub})
		}
		if h.Has(RoleAgent) {
			dh.nodes = append(dh.nodes, dgNode{id: nodeID(i, kindAgent), kind: kindAgent, title: "Agent", sub: t.AgentName(h)})
		}
		d.hosts = append(d.hosts, dh)
	}

	var admin string
	for i, h := range t.Hosts {
		if h.Has(RoleAdmin) {
			admin = nodeID(i, kindAdmin)
			break
		}
	}
	lastOfGroup := map[string]string{}
	for i, h := range t.Hosts {
		if h.Has(RoleEdge) {
			if admin != "" {
				d.links = append(d.links, dgLink{from: admin, to: nodeID(i, kindEdge), kind: linkManage, label: "pilote"})
			}
			g := t.GroupOf(h)
			if prev, ok := lastOfGroup[g]; ok {
				d.links = append(d.links, dgLink{from: prev, to: nodeID(i, kindEdge), kind: linkPeers, label: "HA"})
			}
			lastOfGroup[g] = nodeID(i, kindEdge)
		}
		if h.Has(RoleAgent) {
			target := t.TargetEdge(h)
			if j, ok := index[target.Name]; ok && target.Has(RoleEdge) {
				d.links = append(d.links, dgLink{from: nodeID(i, kindAgent), to: nodeID(j, kindEdge), kind: linkRoutes, label: "routes"})
			}
		}
	}
	return d
}

// mmText met un texte entre guillemets Mermaid : ni guillemet ni chevron ne doivent en sortir.
func mmText(s string) string {
	return strings.NewReplacer(`"`, "#quot;", "<", "#lt;", ">", "#gt;", "&", "#amp;").Replace(s)
}

// Mermaid est le schéma au format Mermaid (flowchart). Un hôte est un sous-graphe ; l'Admin pilote les passerelles (trait
// pointillé), les Agents annoncent leurs routes à leur passerelle, les passerelles d'un même groupe HA se relient.
func (t *Topology) Mermaid() string {
	d := t.diagram()
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	b.WriteString("  classDef admin fill:#eef2ff,stroke:#4f46e5,color:#1e1b4b\n")
	b.WriteString("  classDef edge fill:#ecfeff,stroke:#0891b2,color:#164e63\n")
	b.WriteString("  classDef agent fill:#f0fdf4,stroke:#16a34a,color:#14532d\n")
	for _, h := range d.hosts {
		title := h.title
		if h.local {
			title += " (cette machine)"
		}
		fmt.Fprintf(&b, "  subgraph %s[\"%s\"]\n", h.id, mmText(title))
		if len(h.nodes) == 0 {
			fmt.Fprintf(&b, "    %s_none[\"aucun rôle\"]\n", h.id)
		}
		for _, n := range h.nodes {
			fmt.Fprintf(&b, "    %s[\"%s<br/>%s\"]:::%s\n", n.id, mmText(n.title), mmText(n.sub), n.kind)
		}
		b.WriteString("  end\n")
	}
	for _, l := range d.links {
		switch l.kind {
		case linkManage:
			fmt.Fprintf(&b, "  %s -.->|%s| %s\n", l.from, l.label, l.to)
		case linkPeers:
			fmt.Fprintf(&b, "  %s <-.->|%s| %s\n", l.from, l.label, l.to)
		default:
			fmt.Fprintf(&b, "  %s -->|%s| %s\n", l.from, l.label, l.to)
		}
	}
	return b.String()
}

// Dimensions du dessin, en unités du viewBox.
const (
	svgMargin  = 16
	svgColW    = 214
	svgColGap  = 92
	svgHeadH   = 52
	svgNodeW   = 182
	svgNodeH   = 58
	svgNodeGap = 34
	svgPad     = 16
)

type svgBox struct{ x, y, w, h int }

func (b svgBox) side(s string) (int, int) {
	switch s {
	case "l":
		return b.x, b.y + b.h/2
	case "r":
		return b.x + b.w, b.y + b.h/2
	case "t":
		return b.x + b.w/2, b.y
	}
	return b.x + b.w/2, b.y + b.h
}

// ellipsis abrège un texte trop long pour sa boîte ; le texte entier reste dans l'infobulle.
func ellipsis(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// SVG dessine le schéma : une colonne par hôte, les rôles empilés, les liens en courbes. Les couleurs viennent de classes
// CSS de la page (clair et sombre). Vide s'il n'y a aucun hôte.
func (t *Topology) SVG() string {
	d := t.diagram()
	if len(d.hosts) == 0 {
		return ""
	}
	boxes := map[string]svgBox{}
	hostOf := map[string]int{}
	maxNodes := 1
	for _, h := range d.hosts {
		if len(h.nodes) > maxNodes {
			maxNodes = len(h.nodes)
		}
	}
	hostH := svgHeadH + maxNodes*(svgNodeH+svgNodeGap) + svgPad - svgNodeGap
	width := 2*svgMargin + len(d.hosts)*svgColW + (len(d.hosts)-1)*svgColGap
	height := 2*svgMargin + hostH

	var b strings.Builder
	fmt.Fprintf(&b, `<svg class="dg" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" role="img" aria-label="Schéma de l'infrastructure">`, width, height)
	b.WriteString(`<defs>`)
	for _, k := range []string{linkManage, linkRoutes} {
		fmt.Fprintf(&b, `<marker id="dg-%s" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="dg-arrow dg-%s" d="M0,0 L10,5 L0,10 z"/></marker>`, k, k)
	}
	b.WriteString(`</defs>`)

	for i, h := range d.hosts {
		x := svgMargin + i*(svgColW+svgColGap)
		cls := "dg-host"
		if h.local {
			cls += " dg-local"
		}
		fmt.Fprintf(&b, `<g class="%s"><rect x="%d" y="%d" width="%d" height="%d" rx="14"/>`, cls, x, svgMargin, svgColW, hostH)
		fmt.Fprintf(&b, `<text class="dg-host-title" x="%d" y="%d"><title>%s</title>%s</text>`, x+svgPad, svgMargin+24, html.EscapeString(h.title), html.EscapeString(ellipsis(h.title, 26)))
		if h.local {
			fmt.Fprintf(&b, `<text class="dg-host-sub" x="%d" y="%d">cette machine</text>`, x+svgPad, svgMargin+42)
		}
		b.WriteString(`</g>`)
		for k, n := range h.nodes {
			boxes[n.id] = svgBox{x + (svgColW-svgNodeW)/2, svgMargin + svgHeadH + k*(svgNodeH+svgNodeGap), svgNodeW, svgNodeH}
			hostOf[n.id] = i
		}
	}

	for _, l := range d.links {
		from, to := boxes[l.from], boxes[l.to]
		var x1, y1, x2, y2 int
		var path string
		anchor := "middle"
		switch {
		case hostOf[l.from] == hostOf[l.to]:
			a, z := "b", "t"
			if from.y > to.y {
				a, z = "t", "b"
			}
			x1, y1 = from.side(a)
			x2, y2 = to.side(z)
			path = fmt.Sprintf("M%d,%d L%d,%d", x1, y1, x2, y2)
			anchor = "start"
		default:
			a, z, sign := "r", "l", 1
			if hostOf[l.to] < hostOf[l.from] {
				a, z, sign = "l", "r", -1
			}
			x1, y1 = from.side(a)
			x2, y2 = to.side(z)
			dx := sign * max(36, abs(x2-x1)/2)
			path = fmt.Sprintf("M%d,%d C%d,%d %d,%d %d,%d", x1, y1, x1+dx, y1, x2-dx, y2, x2, y2)
		}
		marker := ""
		if l.kind != linkPeers {
			marker = fmt.Sprintf(` marker-end="url(#dg-%s)"`, l.kind)
		}
		fmt.Fprintf(&b, `<path class="dg-link dg-%s" d="%s"%s/>`, l.kind, path, marker)
		lx, ly := (x1+x2)/2, (y1+y2)/2-4
		if anchor == "start" {
			lx, ly = lx+10, (y1+y2)/2+4
		}
		fmt.Fprintf(&b, `<text class="dg-link-label" x="%d" y="%d" text-anchor="%s">%s</text>`, lx, ly, anchor, html.EscapeString(l.label))
	}

	for _, h := range d.hosts {
		if len(h.nodes) == 0 {
			x := svgMargin + indexOfHost(d, h.id)*(svgColW+svgColGap)
			fmt.Fprintf(&b, `<text class="dg-none" x="%d" y="%d" text-anchor="middle">aucun rôle</text>`, x+svgColW/2, svgMargin+svgHeadH+24)
		}
		for _, n := range h.nodes {
			bx := boxes[n.id]
			fmt.Fprintf(&b, `<g class="dg-node dg-%s"><rect x="%d" y="%d" width="%d" height="%d" rx="10"/>`, n.kind, bx.x, bx.y, bx.w, bx.h)
			fmt.Fprintf(&b, `<text class="dg-node-title" x="%d" y="%d">%s</text>`, bx.x+14, bx.y+24, html.EscapeString(n.title))
			fmt.Fprintf(&b, `<text class="dg-node-sub" x="%d" y="%d"><title>%s</title>%s</text></g>`, bx.x+14, bx.y+44, html.EscapeString(n.sub), html.EscapeString(ellipsis(n.sub, 24)))
		}
	}
	b.WriteString(`</svg>`)
	return b.String()
}

func indexOfHost(d diagram, id string) int {
	for i, h := range d.hosts {
		if h.id == id {
			return i
		}
	}
	return 0
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
