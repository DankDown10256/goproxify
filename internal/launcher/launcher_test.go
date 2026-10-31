// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package launcher

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/archstore"
	"github.com/vincamok/goproxify/internal/agent/docker"
	"github.com/vincamok/goproxify/internal/deploy"
	"github.com/vincamok/goproxify/internal/pairing"
)

func mustHost(t *testing.T, s string) Host {
	t.Helper()
	h, err := ParseHost(s)
	if err != nil {
		t.Fatalf("ParseHost(%q) : %v", s, err)
	}
	return h
}

func TestParseHost(t *testing.T) {
	cases := map[string]Host{
		"192.168.1.50":                {Name: "host-192-168-1-50", Addr: "192.168.1.50", Roles: []string{"agent"}},
		"192.168.1.50=agent":          {Name: "host-192-168-1-50", Addr: "192.168.1.50", Roles: []string{"agent"}},
		"192.168.1.50:edge,agent":     {Name: "host-192-168-1-50", Addr: "192.168.1.50", Roles: []string{"edge", "agent"}},
		"nas=192.168.1.60:edge,agent": {Name: "nas", Addr: "192.168.1.60", Roles: []string{"edge", "agent"}},
		"nas=192.168.1.60:edge@ha-1":  {Name: "nas", Addr: "192.168.1.60", Roles: []string{"edge"}, Group: "ha-1"},
		"vps=vps.example.org:edge":    {Name: "vps", Addr: "vps.example.org", Roles: []string{"edge"}},
		"192.168.1.70=edge,agent":     {Name: "host-192-168-1-70", Addr: "192.168.1.70", Roles: []string{"edge", "agent"}},
	}
	for in, want := range cases {
		got, err := ParseHost(in)
		if err != nil {
			t.Errorf("ParseHost(%q) : %v", in, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ParseHost(%q) = %+v, attendu %+v", in, got, want)
		}
	}
	for _, bad := range []string{"", "192.168.1.50:db", "192.168.1.50:agent,agent", "nas=:agent", "a b:agent", "x=1.2.3.4:edge@bad name"} {
		if _, err := ParseHost(bad); err == nil {
			t.Errorf("ParseHost(%q) doit échouer", bad)
		}
	}
}

func twoHostTopology(t *testing.T) *Topology {
	t.Helper()
	return &Topology{
		Local: "main",
		Hosts: []Host{
			{Name: "main", Addr: "192.168.1.10", Roles: []string{"admin", "edge", "agent"}},
			mustHost(t, "nas=192.168.1.50:agent"),
		},
	}
}

func TestValidateTopology(t *testing.T) {
	if err := twoHostTopology(t).Validate(); err != nil {
		t.Fatalf("topologie valide refusée : %v", err)
	}
	cases := map[string]func(tp *Topology){
		"aucun hôte":             func(tp *Topology) { tp.Hosts = nil },
		"deux Admin":             func(tp *Topology) { tp.Hosts[1].Roles = []string{"admin"} },
		"aucun Admin":            func(tp *Topology) { tp.Hosts[0].Roles = []string{"edge", "agent"} },
		"aucune passerelle":      func(tp *Topology) { tp.Hosts[0].Roles = []string{"admin", "agent"} },
		"nom en double":          func(tp *Topology) { tp.Hosts[1].Name = "main" },
		"hôte local inconnu":     func(tp *Topology) { tp.Local = "absent" },
		"local sans Admin":       func(tp *Topology) { tp.Local = "nas" },
		"groupe sans passerelle": func(tp *Topology) { tp.Hosts[1].Group = "ha-1" },
		"rôle inconnu":           func(tp *Topology) { tp.Hosts[1].Roles = []string{"db"} },
		"adresse invalide":       func(tp *Topology) { tp.Hosts[1].Addr = "a b" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tp := twoHostTopology(t)
			mutate(tp)
			if err := tp.Validate(); err == nil {
				t.Error("la topologie doit être refusée")
			}
		})
	}
}

func TestNodeNames(t *testing.T) {
	single := twoHostTopology(t)
	if single.EdgeName(single.Hosts[0]) != "goproxify-edge" {
		t.Errorf("une passerelle unique garde le nom du démarrage rapide : %s", single.EdgeName(single.Hosts[0]))
	}
	multi := twoHostTopology(t)
	multi.Hosts = append(multi.Hosts, mustHost(t, "vps=203.0.113.5:edge"))
	if multi.EdgeName(multi.Hosts[0]) != "main-edge" || multi.EdgeName(multi.Hosts[2]) != "vps-edge" {
		t.Errorf("noms avec plusieurs passerelles : %s %s", multi.EdgeName(multi.Hosts[0]), multi.EdgeName(multi.Hosts[2]))
	}
	if multi.AgentName(multi.Hosts[0]) != "main-agent" {
		t.Errorf("deux Agents portent le nom de leur hôte : %s", multi.AgentName(multi.Hosts[0]))
	}
}

func TestArchitectureIsReadableByTheAdmin(t *testing.T) {
	tp := twoHostTopology(t)
	tp.Hosts = append(tp.Hosts, mustHost(t, "vps=203.0.113.5:edge@ha-1"))
	raw, err := json.Marshal(tp.Architecture())
	if err != nil {
		t.Fatal(err)
	}

	var arch archstore.Architecture
	if err := json.Unmarshal(raw, &arch); err != nil {
		t.Fatal(err)
	}
	if arch.SchemaVersion != 1 {
		t.Errorf("schema_version = %d", arch.SchemaVersion)
	}
	byName := map[string]archstore.NodeEntry{}
	ids := map[string]bool{}
	for _, n := range arch.Nodes {
		byName[n.Name] = n
		if !strings.HasPrefix(n.ID, "dn_") || ids[n.ID] {
			t.Errorf("identifiant %q invalide ou répété", n.ID)
		}
		ids[n.ID] = true
	}
	if len(arch.Nodes) != 4 { // deux passerelles, deux Agents ; l'Admin n'est pas un nœud
		t.Fatalf("nœuds = %d : %v", len(arch.Nodes), byName)
	}
	if ep := byName["vps-edge"].ControlEndpoint(); ep != "http://203.0.113.5:8000" {
		t.Errorf("endpoint de la passerelle distante = %q", ep)
	}
	if ep := byName["main-edge"].ControlEndpoint(); ep != "http://main-edge:8000" {
		t.Errorf("endpoint de la passerelle locale = %q", ep)
	}
	if g := byName["vps-edge"].Group(); g != "ha-1" {
		t.Errorf("groupe = %q", g)
	}
	// Toute passerelle appartient à un groupe (ADR 0014) : sans groupe déclaré, elle forme le sien.
	if g := byName["main-edge"].Group(); g != "ha-main" {
		t.Errorf("groupe de la passerelle sans groupe déclaré = %q, ha-main attendu", g)
	}
	if g := byName["main-agent"].Group(); g != "" {
		t.Errorf("un Agent n'a pas de groupe : %q", g)
	}
	for _, n := range arch.Nodes {
		if strings.Contains(string(n.Config), "auto_accept") {
			t.Errorf("l'acceptation automatique vient d'un ticket valide, pas du fichier : %s %s", n.Name, n.Config)
		}
	}
}

// Ce que l'Admin relit d'architecture.json doit décrire un hôte comme le launcher l'aurait décrit : c'est la même
// description, servie plus tard par ticket.
func TestTopologyFromArchitectureDescribesRemoteHostsLikeTheLauncher(t *testing.T) {
	tp := twoHostTopology(t)
	tp.Hosts = append(tp.Hosts, mustHost(t, "vps=203.0.113.5:edge,agent@ha-1"))
	env := testEnv(t)

	raw, _ := json.Marshal(tp.Architecture())
	var arch archstore.Architecture
	if err := json.Unmarshal(raw, &arch); err != nil {
		t.Fatal(err)
	}
	derived := TopologyFromArchitecture(&arch)

	if len(derived.Hosts) != 3 {
		t.Fatalf("hôtes relus = %+v", derived.Hosts)
	}
	for _, name := range []string{"nas", "vps"} {
		want, err := tp.HostSpec(name, env)
		if err != nil {
			t.Fatal(err)
		}
		got, err := derived.HostSpec(name, env)
		if err != nil {
			t.Fatalf("%s : %v", name, err)
		}
		a, _ := json.Marshal(want)
		b, _ := json.Marshal(got)
		if string(a) != string(b) {
			t.Errorf("description de %s différente\nlauncher : %s\nrelue    : %s", name, a, b)
		}
	}
	vps, _ := derived.Host("vps")
	if vps.Group != "ha-1" || derived.EdgeName(vps) != "vps-edge" || !reflect.DeepEqual(derived.NodeNames(vps), []string{"vps-edge", "vps-agent"}) {
		t.Errorf("hôte vps relu = %+v", vps)
	}
}

func TestTopologyFromArchitectureSkipsNodesWithoutHostAndFollowsAgentTarget(t *testing.T) {
	arch := &archstore.Architecture{Nodes: []archstore.NodeEntry{
		{ID: "dn_1", Role: "edge", Name: "e1", Config: json.RawMessage(`{"host":"h1","reachable_host":"10.0.0.1:8000"}`)},
		{ID: "dn_2", Role: "edge", Name: "e2", Config: json.RawMessage(`{"host":"h2","reachable_host":"http://10.0.0.2:8000","cluster":true,"cluster_group":"g"}`)},
		{ID: "dn_3", Role: "agent", Name: "a1", Config: json.RawMessage(`{"host":"h3","reachable_host":"10.0.0.3","target_edge":"ha:g"}`)},
		{ID: "dn_4", Role: "agent", Name: "orphan", Config: json.RawMessage(`{}`)},
	}}
	tp := TopologyFromArchitecture(arch)
	if len(tp.Hosts) != 3 {
		t.Fatalf("hôtes = %+v", tp.Hosts)
	}
	h2, _ := tp.Host("h2")
	if h2.Addr != "10.0.0.2" {
		t.Errorf("adresse sans schéma ni port = %q", h2.Addr)
	}
	h3, _ := tp.Host("h3")
	if got := tp.TargetEdge(h3); got.Name != "h2" {
		t.Errorf("`ha:g` doit désigner la passerelle du groupe g : %+v", got)
	}
	if tp.EdgeNodeID(h2) != "dn_2" {
		t.Errorf("l'identifiant du fichier fait foi : %s", tp.EdgeNodeID(h2))
	}
}

func testEnv(t *testing.T) Env {
	t.Helper()
	s, err := NewSecrets("")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := NewAdminCert([]string{"192.168.1.10", "localhost"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return Env{Secrets: s, AdminEmail: "a@b.fr", AdminCert: cert}
}

func TestHostSpecGivesEachComponentOnlyItsKeys(t *testing.T) {
	tp := twoHostTopology(t)
	env := testEnv(t)
	spec, err := tp.HostSpec("main", env)
	if err != nil {
		t.Fatal(err)
	}
	if err := spec.Validate(nil); err != nil {
		t.Fatalf("la description produite doit être valide : %v", err)
	}
	names := []string{}
	byName := map[string]deploy.Container{}
	for _, c := range spec.Containers {
		names = append(names, c.Name)
		byName[c.Name] = c
	}
	if !reflect.DeepEqual(names, []string{"goproxify-admin", "goproxify-edge", "goproxify-agent"}) {
		t.Fatalf("ordre = %v", names)
	}

	admin, edge, agent := byName["goproxify-admin"], byName["goproxify-edge"], byName["goproxify-agent"]
	if admin.Env["GPX_PAIRING_SECRET"] != env.Secrets.Root {
		t.Error("l'Admin détient le secret racine")
	}
	for name, c := range map[string]deploy.Container{"edge": edge, "agent": agent} {
		for k, v := range c.Env {
			if v == env.Secrets.Root || strings.Contains(v, env.Secrets.Root) {
				t.Errorf("%s ne doit jamais recevoir le secret racine (%s)", name, k)
			}
		}
	}
	if edge.Env["GPX_AGENT_PAIRING_KEY"] != pairing.AgentKey(env.Secrets.Root) || agent.Env["GPX_AGENT_PAIRING_KEY"] != edge.Env["GPX_AGENT_PAIRING_KEY"] {
		t.Error("la passerelle et l'Agent reçoivent la clé d'appairage dérivée")
	}
	if edge.Env["GPX_EDGE_CHANNEL_KEY"] != pairing.EdgeChannelKey(env.Secrets.Root, nodeID(RoleEdge, "goproxify-edge")) {
		t.Error("la clé de canal est dérivée de l'identifiant du nœud de la passerelle")
	}
	if admin.Env["GPX_IDENTITY_EDGE_NODE_NAME"] != "goproxify-edge" || edge.Networks[0].Aliases[0] != "goproxify-edge" {
		t.Error("l'Admin joint la passerelle locale par son nom, alias du réseau")
	}
	if agent.Env["GPX_CONTROL_PLANE_EDGE_ENDPOINT"] != "http://goproxify-edge:8000" {
		t.Errorf("endpoint de l'Agent local = %q", agent.Env["GPX_CONTROL_PLANE_EDGE_ENDPOINT"])
	}
	if admin.Env["GPX_EDGE_CHANNEL_ROOT_FALLBACK"] != "false" || admin.Env["GPX_AGENT_PAIRING_ROOT"] != "false" {
		t.Error("l'Admin ne présente ni n'accepte le secret racine")
	}
	if len(env.Secrets.Backup) != 64 || admin.Env["GPX_BACKUP_KEY"] != env.Secrets.Backup {
		t.Errorf("l'Admin reçoit une clé de sauvegarde générée : %q", admin.Env["GPX_BACKUP_KEY"])
	}
	for name, c := range map[string]deploy.Container{"edge": edge, "agent": agent} {
		if _, ok := c.Env["GPX_BACKUP_KEY"]; ok {
			t.Errorf("%s n'a pas à connaître la clé de sauvegarde de l'Admin", name)
		}
	}

	files := map[string]deploy.File{}
	for _, f := range admin.Files {
		files[f.Path] = f
	}
	if files["/etc/goproxify/tls/admin.key"].Mode != 0o600 || files["/etc/goproxify/tls/admin.crt"].Content != env.AdminCert.CertPEM {
		t.Errorf("fichiers TLS = %v", files)
	}
	if _, ok := files["/etc/goproxify/state/architecture.json"]; !ok {
		t.Error("architecture.json doit être déposé dans le dossier d'état de l'Admin")
	}
	hasHub := false
	for _, p := range edge.Ports {
		hasHub = hasHub || p.ContainerPort == 8000
	}
	if !hasHub {
		t.Error("avec un autre hôte, le hub de la passerelle (8000) doit être publié")
	}
}

func TestHostSpecSingleHostKeepsHubPrivate(t *testing.T) {
	tp := &Topology{Local: "solo", Hosts: []Host{{Name: "solo", Addr: "localhost", Roles: []string{"admin", "edge"}}}}
	spec, err := tp.HostSpec("solo", testEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range spec.Containers {
		for _, p := range c.Ports {
			if p.ContainerPort == 8000 {
				t.Error("le hub n'a pas à être publié sur un seul hôte")
			}
		}
	}
	if len(spec.Containers) != 2 {
		t.Errorf("conteneurs = %d", len(spec.Containers))
	}
}

func TestHostSpecAgentOnRemoteHostTargetsTheEdgeAddress(t *testing.T) {
	tp := twoHostTopology(t)
	spec, err := tp.HostSpec("nas", testEnv(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Containers) != 1 || spec.Containers[0].Env["GPX_CONTROL_PLANE_EDGE_ENDPOINT"] != "http://192.168.1.10:8000" {
		t.Errorf("Agent distant = %+v", spec.Containers)
	}
}

func TestHostGroupSharesPortalKey(t *testing.T) {
	s, _ := NewSecrets("")
	if s.PortalKey("group:ha-1") != s.PortalKey("group:ha-1") || s.PortalKey("group:ha-1") == s.PortalKey("group:ha-2") {
		t.Error("la clé du portail est stable pour un groupe et distincte d'un groupe à l'autre")
	}
}

func TestNewAdminCert(t *testing.T) {
	now := time.Now()
	c, err := NewAdminCert([]string{"192.168.1.10", "admin.lan", "192.168.1.10", ""}, now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(c.CertPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(block.Bytes)
	if c.Fingerprint != hex.EncodeToString(sum[:]) {
		t.Error("l'empreinte est le SHA-256 du certificat DER")
	}
	if len(cert.IPAddresses) != 1 || cert.IPAddresses[0].String() != "192.168.1.10" || !reflect.DeepEqual(cert.DNSNames, []string{"admin.lan"}) {
		t.Errorf("SAN = %v %v", cert.IPAddresses, cert.DNSNames)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, DNSName: "admin.lan", CurrentTime: now.Add(24 * time.Hour)}); err != nil {
		t.Errorf("le certificat doit valoir pour ses noms : %v", err)
	}
	if !cert.NotAfter.After(now.AddDate(1, 11, 0)) {
		t.Errorf("validité = %v", cert.NotAfter)
	}
	if _, err := tlsKeyPair(c); err != nil {
		t.Errorf("la clé doit correspondre au certificat : %v", err)
	}
	other, _ := NewAdminCert([]string{"x"}, now)
	if other.Fingerprint == c.Fingerprint {
		t.Error("deux certificats ne partagent pas d'empreinte")
	}
}

// fakeAPI accepte tout ce que le moteur lui envoie et note les conteneurs créés et les fichiers déposés.
type fakeAPI struct {
	mu      sync.Mutex
	created []string
	started []string
	files   map[string]string
	ids     map[string]string
	bodies  map[string]map[string]any
	pulled  []string
}

func newFakeAPI() *fakeAPI {
	return &fakeAPI{files: map[string]string{}, ids: map[string]string{}, bodies: map[string]map[string]any{}}
}

func (f *fakeAPI) Get(_ context.Context, path string, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasPrefix(path, "/containers/ctr-") && strings.HasSuffix(path, "/json") && out != nil {
		b, _ := json.Marshal(map[string]any{"State": map[string]any{"Status": "running", "Health": map[string]any{"Status": "healthy"}}})
		return json.Unmarshal(b, out)
	}
	return &docker.APIError{Method: "GET", Path: path, Status: http.StatusNotFound}
}

func (f *fakeAPI) Post(_ context.Context, path string, body any, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, _ := url.Parse(path)
	switch {
	case u.Path == "/containers/create":
		name := u.Query().Get("name")
		id := "ctr-" + name
		f.created = append(f.created, name)
		f.ids[id] = name
		raw, _ := json.Marshal(body)
		var b map[string]any
		_ = json.Unmarshal(raw, &b)
		f.bodies[name] = b
		if out != nil {
			return json.Unmarshal([]byte(`{"Id":"`+id+`"}`), out)
		}
	case strings.HasSuffix(u.Path, "/start"):
		f.started = append(f.started, f.ids[strings.TrimSuffix(strings.TrimPrefix(u.Path, "/containers/"), "/start")])
	case u.Path == "/networks/create" && out != nil:
		return json.Unmarshal([]byte(`{"Id":"net1"}`), out)
	}
	return nil
}

func (f *fakeAPI) PostStream(_ context.Context, path string, _ map[string]string, _ func([]byte)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pulled = append(f.pulled, path)
	return nil
}

func (f *fakeAPI) PutArchive(_ context.Context, path string, r io.Reader) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		var b bytes.Buffer
		_, _ = io.Copy(&b, tr)
		f.files["/"+h.Name] = b.String()
	}
}

func (f *fakeAPI) Delete(context.Context, string) error { return nil }

func TestRunInstallsTheLocalHost(t *testing.T) {
	api := newFakeAPI()
	var out bytes.Buffer
	rep, err := Run(context.Background(), api, Options{Topology: twoHostTopology(t), AdminEmail: "me@lan.fr", Out: &out})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(api.created, []string{"goproxify-admin", "goproxify-edge", "goproxify-agent"}) ||
		!reflect.DeepEqual(api.started, api.created) {
		t.Errorf("créés = %v, démarrés = %v", api.created, api.started)
	}
	if rep.AdminURL != "https://192.168.1.10:9443" || rep.AdminEmail != "me@lan.fr" || len(rep.AdminPassword) < 16 {
		t.Errorf("rapport = %+v", rep)
	}
	if len(rep.Pending) != 1 || rep.Pending[0].Name != "nas" {
		t.Errorf("hôtes en attente = %v", rep.Pending)
	}

	// Le certificat déposé est bien celui dont l'empreinte est annoncée.
	block, _ := pem.Decode([]byte(api.files["/etc/goproxify/tls/admin.crt"]))
	sum := sha256.Sum256(block.Bytes)
	if hex.EncodeToString(sum[:]) != rep.Fingerprint {
		t.Error("l'empreinte annoncée doit être celle du certificat déposé dans l'Admin")
	}
	var arch archstore.Architecture
	if err := json.Unmarshal([]byte(api.files["/etc/goproxify/state/architecture.json"]), &arch); err != nil || len(arch.Nodes) != 3 {
		t.Errorf("architecture.json déposé : %v, %d nœuds", err, len(arch.Nodes))
	}
	if strings.Contains(out.String(), rep.AdminPassword) {
		t.Error("le mot de passe ne doit pas passer dans le journal d'avancement")
	}
}

func TestRunDryRunCreatesNothing(t *testing.T) {
	api := newFakeAPI()
	var out bytes.Buffer
	rep, err := Run(context.Background(), api, Options{Topology: twoHostTopology(t), DryRun: true, Out: &out})
	if err != nil {
		t.Fatal(err)
	}
	if len(api.created) != 0 || len(api.pulled) != 0 || len(rep.Containers) != 0 {
		t.Errorf("rien ne doit être créé : %v %v", api.created, api.pulled)
	}
	if len(rep.Plan.Pull) != 3 || !strings.Contains(out.String(), "goproxify_net") {
		t.Errorf("plan = %+v\n%s", rep.Plan, out.String())
	}
}

func TestRunRefusesAnInvalidTopology(t *testing.T) {
	tp := twoHostTopology(t)
	tp.Hosts[0].Roles = []string{"admin", "agent"} // plus aucune passerelle
	api := newFakeAPI()
	if _, err := Run(context.Background(), api, Options{Topology: tp}); err == nil {
		t.Fatal("la topologie doit être refusée")
	}
	if len(api.created) != 0 {
		t.Error("rien ne doit être créé")
	}
}

func tlsKeyPair(c *AdminCert) (tls.Certificate, error) {
	return tls.X509KeyPair([]byte(c.CertPEM), []byte(c.KeyPEM))
}

func TestEveryEdgeHasAGroupAndTheAgentCanTargetIt(t *testing.T) {
	tp := twoHostTopology(t)
	if g := tp.GroupOf(tp.Hosts[0]); g != "ha-main" {
		t.Errorf("groupe de la passerelle seule = %q", g)
	}
	if g := tp.GroupOf(tp.Hosts[1]); g != "" {
		t.Errorf("l'hôte du nas n'a pas de passerelle, donc pas de groupe : %q", g)
	}
	tp.Hosts[1].AgentTarget = "ha:ha-main"
	if got := tp.TargetEdge(tp.Hosts[1]); got.Name != "main" {
		t.Errorf("un Agent visant le groupe d'une passerelle seule doit la trouver : %q", got.Name)
	}
	tp.Hosts[0].Group = "front"
	if g := tp.GroupOf(tp.Hosts[0]); g != "front" {
		t.Errorf("un groupe déclaré l'emporte : %q", g)
	}
}

func agentTargets(t *testing.T, tp *Topology) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, n := range tp.Architecture().Nodes {
		if n.Role != RoleAgent {
			continue
		}
		var cfg struct {
			TargetEdge string `json:"target_edge"`
		}
		if err := json.Unmarshal(n.Config, &cfg); err != nil {
			t.Fatal(err)
		}
		out[n.Name] = cfg.TargetEdge
	}
	return out
}

func TestAgentsAreAttachedToTheGroupOfTheirEdge(t *testing.T) {
	tp := twoHostTopology(t)
	for name, target := range agentTargets(t, tp) {
		if target != "ha:ha-main" {
			t.Errorf("l'Agent %s doit viser le groupe de sa passerelle (ha:<groupe>), pas son nom : %q", name, target)
		}
	}
	tp.Hosts[0].Group = "front"
	for name, target := range agentTargets(t, tp) {
		if target != "ha:front" {
			t.Errorf("l'Agent %s doit suivre le groupe déclaré : %q", name, target)
		}
	}
	tp.Hosts[1].AgentTarget = "main"
	if got := agentTargets(t, tp)[tp.AgentName(tp.Hosts[1])]; got != "main" {
		t.Errorf("une passerelle choisie explicitement est conservée : %q", got)
	}
}
