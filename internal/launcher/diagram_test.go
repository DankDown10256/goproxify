// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package launcher

import (
	"encoding/xml"
	"io"
	"strings"
	"testing"
)

func TestMermaidDescribesHostsRolesAndLinks(t *testing.T) {
	m := twoHostTopology(t).Mermaid()
	for _, want := range []string{
		"flowchart LR",
		`subgraph h0["main · 192.168.1.10 (cette machine)"]`,
		`subgraph h1["nas · 192.168.1.50"]`,
		`h0_admin["Admin<br/>https :9443"]:::admin`,
		`h0_edge["Passerelle<br/>goproxify-edge"]:::edge`,
		`h1_agent["Agent<br/>nas-agent"]:::agent`,
		"h0_admin -.->|pilote| h0_edge",
		"h0_agent -->|routes| h0_edge",
		"h1_agent -->|routes| h0_edge",
	} {
		if !strings.Contains(m, want) {
			t.Errorf("le schéma Mermaid doit contenir %q :\n%s", want, m)
		}
	}
	if strings.Contains(m, "HA|") {
		t.Errorf("une passerelle seule n'a pas de pair HA :\n%s", m)
	}
}

func TestMermaidLinksTheMembersOfAnHAGroup(t *testing.T) {
	tp := &Topology{Local: "a", Hosts: []Host{
		{Name: "a", Addr: "10.0.0.1", Roles: []string{"admin", "edge"}, Group: "front"},
		{Name: "b", Addr: "10.0.0.2", Roles: []string{"edge"}, Group: "front"},
		{Name: "c", Addr: "10.0.0.3", Roles: []string{"agent"}},
	}}
	tp.Hosts[2].AgentTarget = "ha:front"
	m := tp.Mermaid()
	for _, want := range []string{"h0_edge <-.->|HA| h1_edge", "h2_agent -->|routes| h0_edge", "h0_admin -.->|pilote| h1_edge", "· front"} {
		if !strings.Contains(m, want) {
			t.Errorf("le groupe HA doit apparaître (%q) :\n%s", want, m)
		}
	}
}

func TestMermaidEscapesWhatWouldBreakTheSyntax(t *testing.T) {
	tp := &Topology{Local: "x", Hosts: []Host{{Name: `a"b<c>`, Addr: "1.2.3.4", Roles: []string{"agent"}}}}
	m := tp.Mermaid()
	if strings.Contains(m, `a"b`) || strings.Contains(m, "<c>") {
		t.Errorf("guillemets et chevrons doivent être échappés :\n%s", m)
	}
	if !strings.Contains(m, "a#quot;b#lt;c#gt;") {
		t.Errorf("échappement Mermaid attendu :\n%s", m)
	}
}

func TestMermaidToleratesAnEmptyOrRolelessDraft(t *testing.T) {
	if m := (&Topology{}).Mermaid(); !strings.HasPrefix(m, "flowchart LR") {
		t.Errorf("sans hôte, le schéma reste du Mermaid valide : %q", m)
	}
	m := (&Topology{Hosts: []Host{{Name: "seul"}}}).Mermaid()
	if !strings.Contains(m, "aucun rôle") {
		t.Errorf("un hôte sans rôle le dit : %s", m)
	}
}

// wellFormed lit le document XML jusqu'au bout.
func wellFormed(t *testing.T, doc string) {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(doc))
	for {
		if _, err := dec.Token(); err == io.EOF {
			return
		} else if err != nil {
			t.Fatalf("SVG mal formé : %v\n%s", err, doc)
		}
	}
}

func TestSVGIsAWellFormedDrawingOfTheTopology(t *testing.T) {
	svg := twoHostTopology(t).SVG()
	wellFormed(t, svg)
	if got := strings.Count(svg, `<g class="dg-host`); got != 2 {
		t.Errorf("une colonne par hôte : %d", got)
	}
	for _, want := range []string{`class="dg-node dg-admin"`, `class="dg-node dg-edge"`, `dg-local`, "cette machine", `dg-link dg-manage`, `dg-link dg-routes`, `role="img"`} {
		if !strings.Contains(svg, want) {
			t.Errorf("le dessin doit contenir %q", want)
		}
	}
	if strings.Count(svg, `class="dg-node dg-agent"`) != 2 || strings.Count(svg, `class="dg-link dg-routes"`) != 2 {
		t.Errorf("deux Agents, deux liens vers la passerelle :\n%s", svg)
	}
	if strings.Contains(svg, "<script") || strings.Contains(svg, " on") && strings.Contains(svg, "onload") {
		t.Error("aucun script dans le dessin")
	}
}

func TestSVGEscapesNamesAndStaysWellFormed(t *testing.T) {
	tp := &Topology{Local: `<b>`, Hosts: []Host{{Name: `<b>`, Addr: `"><script>alert(1)</script>`, Roles: []string{"admin", "edge", "agent"}}}}
	svg := tp.SVG()
	wellFormed(t, svg)
	if strings.Contains(svg, "<script>") || strings.Contains(svg, "<b>") {
		t.Errorf("les noms saisis ne doivent jamais devenir du balisage :\n%s", svg)
	}
	if !strings.Contains(svg, "&lt;b&gt;") {
		t.Error("le nom est écrit échappé")
	}
}

func TestSVGWithoutHostsIsEmptyAndLongNamesAreClipped(t *testing.T) {
	if (&Topology{}).SVG() != "" {
		t.Error("sans hôte, rien à dessiner")
	}
	long := strings.Repeat("x", 80)
	svg := (&Topology{Local: long, Hosts: []Host{{Name: long, Addr: "1.2.3.4", Roles: []string{"agent"}}}}).SVG()
	wellFormed(t, svg)
	if !strings.Contains(svg, "…") || !strings.Contains(svg, "<title>"+long) {
		t.Error("un nom trop long est abrégé, le nom entier reste dans l'infobulle")
	}
	// Plusieurs hôtes : la largeur suit le nombre de colonnes.
	three := &Topology{Local: "a", Hosts: []Host{{Name: "a", Addr: "1.1.1.1", Roles: []string{"admin", "edge"}}, {Name: "b", Addr: "1.1.1.2", Roles: []string{"agent"}}, {Name: "c", Addr: "1.1.1.3"}}}
	s3 := three.SVG()
	wellFormed(t, s3)
	if !strings.Contains(s3, "aucun rôle") {
		t.Error("un hôte sans rôle est signalé dans le dessin")
	}
}
