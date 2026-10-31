// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/agent/docker"
)

// fakeDaemon joue un démon Docker en mémoire : il connaît des images, réseaux, volumes et conteneurs, et peut
// échouer à la demande.
type fakeDaemon struct {
	mu         sync.Mutex
	images     map[string]bool
	networks   map[string]string // nom → identifiant
	volumes    map[string]bool
	byID       map[string]string // identifiant → nom
	bodies     map[string]map[string]any
	running    map[string]bool
	connects   []string
	calls      []string
	seq        int
	failCreate string // nom du conteneur dont la création échoue
	failStart  string
	pullError  string
	unhealthy  bool
	failPut    bool
	files      map[string]map[string]string // nom du conteneur → chemin → contenu
	modes      map[string]int64             // chemin → mode
	onCreate   func(name string)
}

func newFake() *fakeDaemon {
	return &fakeDaemon{
		images: map[string]bool{}, networks: map[string]string{}, volumes: map[string]bool{},
		byID: map[string]string{}, bodies: map[string]map[string]any{}, running: map[string]bool{},
		files: map[string]map[string]string{}, modes: map[string]int64{},
	}
}

func (f *fakeDaemon) PutArchive(_ context.Context, path string, r io.Reader) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "PUT "+path)
	if f.failPut {
		return &docker.APIError{Method: "PUT", Path: path, Status: 500, Body: "read-only volume"}
	}
	u, _ := url.Parse(path)
	name := f.byID[strings.TrimSuffix(strings.TrimPrefix(u.Path, "/containers/"), "/archive")]
	if f.files[name] == nil {
		f.files[name] = map[string]string{}
	}
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		b, _ := io.ReadAll(tr)
		f.files[name]["/"+h.Name] = string(b)
		f.modes["/"+h.Name] = h.Mode
	}
}

func notFound(method, path string) error {
	return &docker.APIError{Method: method, Path: path, Status: http.StatusNotFound, Body: "no such object"}
}

func fill(out, v any) error {
	if out == nil {
		return nil
	}
	b, _ := json.Marshal(v)
	return json.Unmarshal(b, out)
}

func (f *fakeDaemon) idOf(nameOrID string) (string, bool) {
	if _, ok := f.byID[nameOrID]; ok {
		return nameOrID, true
	}
	for id, n := range f.byID {
		if n == nameOrID {
			return id, true
		}
	}
	return "", false
}

func (f *fakeDaemon) Get(_ context.Context, path string, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json"):
		id, ok := f.idOf(strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/json"))
		if !ok {
			return notFound("GET", path)
		}
		state := map[string]any{"Status": "running"}
		if _, hasCheck := f.bodies[id]["Healthcheck"]; hasCheck {
			status := "healthy"
			if f.unhealthy {
				status = "starting"
			}
			state["Health"] = map[string]any{"Status": status}
		}
		return fill(out, map[string]any{"State": state})
	case strings.HasPrefix(path, "/networks/"):
		if _, ok := f.networks[strings.TrimPrefix(path, "/networks/")]; ok {
			return nil
		}
	case strings.HasPrefix(path, "/volumes/"):
		if f.volumes[strings.TrimPrefix(path, "/volumes/")] {
			return nil
		}
	case strings.HasPrefix(path, "/images/"):
		if f.images[strings.TrimSuffix(strings.TrimPrefix(path, "/images/"), "/json")] {
			return nil
		}
	}
	return notFound("GET", path)
}

func (f *fakeDaemon) Post(_ context.Context, path string, body any, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "POST "+path)
	u, _ := url.Parse(path)
	switch {
	case u.Path == "/networks/create":
		name := body.(map[string]any)["Name"].(string)
		f.seq++
		id := fmt.Sprintf("net%09d", f.seq)
		f.networks[name], f.networks[id] = id, id
		return fill(out, map[string]any{"Id": id})
	case u.Path == "/volumes/create":
		f.volumes[body.(map[string]any)["Name"].(string)] = true
		return nil
	case u.Path == "/containers/create":
		name := u.Query().Get("name")
		if f.onCreate != nil {
			f.onCreate(name)
		}
		if name == f.failCreate {
			return &docker.APIError{Method: "POST", Path: path, Status: 500, Body: "boom"}
		}
		raw, _ := json.Marshal(body)
		var b map[string]any
		_ = json.Unmarshal(raw, &b)
		f.seq++
		id := fmt.Sprintf("ctr%09d", f.seq)
		f.byID[id], f.bodies[id] = name, b
		return fill(out, map[string]any{"Id": id})
	case strings.HasSuffix(u.Path, "/start"):
		id := strings.TrimSuffix(strings.TrimPrefix(u.Path, "/containers/"), "/start")
		if f.byID[id] == f.failStart {
			return &docker.APIError{Method: "POST", Path: path, Status: 500, Body: "port already allocated"}
		}
		f.running[id] = true
		return nil
	case strings.HasSuffix(u.Path, "/connect"):
		f.connects = append(f.connects, strings.TrimSuffix(strings.TrimPrefix(u.Path, "/networks/"), "/connect")+" <- "+
			f.byID[body.(map[string]any)["Container"].(string)])
		return nil
	}
	return fmt.Errorf("fake: POST %s non géré", path)
}

func (f *fakeDaemon) PostStream(_ context.Context, path string, _ map[string]string, fn func([]byte)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "POST "+path)
	u, _ := url.Parse(path)
	if f.pullError != "" {
		fn([]byte(`{"status":"Pulling"}`))
		fn([]byte(`{"error":"` + f.pullError + `"}`))
		return nil
	}
	f.images[u.Query().Get("fromImage")] = true
	fn([]byte(`{"status":"Download complete"}`))
	return nil
}

func (f *fakeDaemon) Delete(_ context.Context, path string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, "DELETE "+path)
	u, _ := url.Parse(path)
	switch {
	case strings.HasPrefix(u.Path, "/containers/"):
		id := strings.TrimPrefix(u.Path, "/containers/")
		if _, ok := f.byID[id]; !ok {
			return notFound("DELETE", path)
		}
		delete(f.byID, id)
		delete(f.running, id)
	case strings.HasPrefix(u.Path, "/volumes/"):
		delete(f.volumes, strings.TrimPrefix(u.Path, "/volumes/"))
	case strings.HasPrefix(u.Path, "/networks/"):
		id := strings.TrimPrefix(u.Path, "/networks/")
		for k, v := range f.networks {
			if k == id || v == id {
				delete(f.networks, k)
			}
		}
	}
	return nil
}

func (f *fakeDaemon) containerNames() []string {
	var out []string
	for _, n := range f.byID {
		out = append(out, n)
	}
	return out
}

func baseSpec() *HostSpec {
	return &HostSpec{
		Version:  SpecVersion,
		Name:     "host1",
		Networks: []Network{{Name: "gpx-net"}, {Name: "gpx-mon"}},
		Volumes:  []string{"gpx-data"},
		Containers: []Container{
			{
				Name: "gpx-admin", Image: "ghcr.io/x/admin:1", Env: map[string]string{"B": "2", "A": "1"},
				Ports:       []Port{{HostPort: 9443, ContainerPort: 9443}},
				Mounts:      []Mount{{Type: "volume", Source: "gpx-data", Target: "/data"}},
				Networks:    []Attach{{Name: "gpx-net", Aliases: []string{"admin"}}},
				Healthcheck: &Healthcheck{Test: []string{"CMD", "true"}, IntervalS: 5}, WaitHealthy: true,
			},
			{
				Name: "gpx-agent", Image: "ghcr.io/x/agent:1",
				Mounts:   []Mount{{Type: "bind", Source: "/var/run/docker.sock", Target: "/var/run/docker.sock"}},
				Networks: []Attach{{Name: "gpx-net"}, {Name: "gpx-mon", Aliases: []string{"agent"}}},
			},
		},
	}
}

func testOptions() Options {
	return Options{DeployID: "dep1", PollInterval: time.Millisecond, HealthTimeout: 30 * time.Millisecond}
}

func TestApplyDeploysInOrder(t *testing.T) {
	f := newFake()
	f.images["ghcr.io/x/agent:1"] = true // déjà présente : pas de pull
	var steps []string
	opt := testOptions()
	opt.Progress = func(e Event) { steps = append(steps, e.Step+":"+e.Name) }

	res, err := New(f, opt).Apply(context.Background(), baseSpec())
	if err != nil {
		t.Fatal(err)
	}

	if len(res.Containers) != 2 || res.Containers[0].Name != "gpx-admin" || res.Containers[1].Name != "gpx-agent" {
		t.Fatalf("résultat = %+v", res.Containers)
	}
	if !f.images["ghcr.io/x/admin:1"] {
		t.Error("l'image absente doit être tirée")
	}
	for _, s := range steps {
		if s == "pull:ghcr.io/x/agent:1" {
			t.Error("l'image déjà présente ne doit pas être tirée")
		}
	}
	if len(f.networks) == 0 || !f.volumes["gpx-data"] {
		t.Errorf("réseaux/volumes non créés : %v %v", f.networks, f.volumes)
	}
	if len(f.running) != 2 {
		t.Errorf("conteneurs démarrés = %d", len(f.running))
	}
	if !reflect.DeepEqual(f.connects, []string{"gpx-mon <- gpx-agent"}) {
		t.Errorf("réseaux supplémentaires = %v", f.connects)
	}

	// Le premier conteneur démarre (et est sain) avant la création du second.
	want := []string{"create:gpx-admin", "start:gpx-admin", "healthy:gpx-admin", "create:gpx-agent", "start:gpx-agent"}
	var got []string
	for _, s := range steps {
		if strings.HasPrefix(s, "create:") || strings.HasPrefix(s, "start:") || strings.HasPrefix(s, "healthy:") {
			got = append(got, s)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("étapes = %v", got)
	}
}

func TestContainerBody(t *testing.T) {
	c := baseSpec().Containers[0]
	b := containerBody(c, map[string]string{"io.goproxify.deploy.id": "dep1"})

	if !reflect.DeepEqual(b["Env"], []string{"A=1", "B=2"}) {
		t.Errorf("Env = %v", b["Env"])
	}
	if asMap(b["Labels"])["io.goproxify.deploy.id"] != "dep1" {
		t.Errorf("Labels = %v", b["Labels"])
	}
	hc := asMap(b["HostConfig"])
	if asMap(hc["RestartPolicy"])["Name"] != "unless-stopped" {
		t.Errorf("redémarrage par défaut = %v", hc["RestartPolicy"])
	}
	if hc["NetworkMode"] != "gpx-net" || !reflect.DeepEqual(hc["Binds"], []string{"gpx-data:/data"}) {
		t.Errorf("HostConfig = %v", hc)
	}
	eps := asMap(asMap(b["NetworkingConfig"])["EndpointsConfig"])
	if !reflect.DeepEqual(asMap(eps["gpx-net"])["Aliases"], []string{"admin"}) {
		t.Errorf("alias = %v", eps)
	}
	if _, ok := b["ExposedPorts"].(map[string]any)["9443/tcp"]; !ok {
		t.Errorf("ExposedPorts = %v", b["ExposedPorts"])
	}
	hcheck := asMap(b["Healthcheck"])
	if hcheck["Interval"] != int64(5*time.Second) {
		t.Errorf("Healthcheck = %v", hcheck)
	}
}

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	// containerBody construit des map[string]any et des types concrets : on passe par JSON pour les comparer.
	raw, _ := json.Marshal(v)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return m
}

func TestApplyRefusesExistingContainerAndCreatesNothing(t *testing.T) {
	f := newFake()
	f.byID["old"] = "gpx-agent"

	_, err := New(f, testOptions()).Apply(context.Background(), baseSpec())
	if err == nil || !strings.Contains(err.Error(), "gpx-agent") {
		t.Fatalf("err = %v", err)
	}
	if len(f.networks) != 0 || len(f.volumes) != 0 || len(f.calls) != 0 {
		t.Errorf("rien ne doit être créé : %v %v %v", f.networks, f.volumes, f.calls)
	}
}

func TestApplyRollsBackOnFailure(t *testing.T) {
	cases := map[string]func(f *fakeDaemon){
		"création du second conteneur": func(f *fakeDaemon) { f.failCreate = "gpx-agent" },
		"démarrage du second":          func(f *fakeDaemon) { f.failStart = "gpx-agent" },
		"premier jamais sain":          func(f *fakeDaemon) { f.unhealthy = true },
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFake()
			f.images["ghcr.io/x/admin:1"], f.images["ghcr.io/x/agent:1"] = true, true
			f.networks["gpx-mon"] = "preexisting" // laissé en place
			setup(f)

			if _, err := New(f, testOptions()).Apply(context.Background(), baseSpec()); err == nil {
				t.Fatal("l'échec doit être remonté")
			}

			if got := f.containerNames(); len(got) != 0 {
				t.Errorf("conteneurs restants : %v", got)
			}
			if f.volumes["gpx-data"] {
				t.Error("le volume créé par ce déploiement doit être retiré")
			}
			if _, ok := f.networks["gpx-net"]; ok {
				t.Error("le réseau créé par ce déploiement doit être retiré")
			}
			if f.networks["gpx-mon"] != "preexisting" {
				t.Error("un réseau déjà présent ne doit pas être touché")
			}
		})
	}
}

func TestApplyRollsBackWhenContextCanceled(t *testing.T) {
	f := newFake()
	f.images["ghcr.io/x/admin:1"], f.images["ghcr.io/x/agent:1"] = true, true
	ctx, cancel := context.WithCancel(context.Background())
	f.onCreate = func(name string) {
		if name == "gpx-agent" {
			cancel()
		}
	}
	f.failCreate = "gpx-agent"

	if _, err := New(f, testOptions()).Apply(ctx, baseSpec()); err == nil {
		t.Fatal("l'échec doit être remonté")
	}
	if len(f.containerNames()) != 0 || f.volumes["gpx-data"] {
		t.Errorf("le retour arrière doit se faire malgré l'annulation : %v %v", f.containerNames(), f.volumes)
	}
}

func TestApplyPullErrorCreatesNothing(t *testing.T) {
	f := newFake()
	f.pullError = "manifest unknown"

	_, err := New(f, testOptions()).Apply(context.Background(), baseSpec())
	if err == nil || !strings.Contains(err.Error(), "manifest unknown") {
		t.Fatalf("err = %v", err)
	}
	if len(f.networks) != 0 || len(f.volumes) != 0 || len(f.byID) != 0 {
		t.Error("un pull en échec ne doit rien laisser")
	}
}

func TestPlanIsReadOnly(t *testing.T) {
	f := newFake()
	f.images["ghcr.io/x/agent:1"] = true
	f.networks["gpx-net"] = "n1"

	p, err := New(f, testOptions()).Plan(context.Background(), baseSpec())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(p.Pull, []string{"ghcr.io/x/admin:1"}) ||
		!reflect.DeepEqual(p.Networks, []string{"gpx-mon"}) || !reflect.DeepEqual(p.Volumes, []string{"gpx-data"}) {
		t.Errorf("plan = %+v", p)
	}
	if len(f.calls) != 0 {
		t.Errorf("Plan ne doit rien modifier : %v", f.calls)
	}
}

func TestValidate(t *testing.T) {
	cases := map[string]func(s *HostSpec){
		"version inconnue":          func(s *HostSpec) { s.Version = 2 },
		"aucun conteneur":           func(s *HostSpec) { s.Containers = nil },
		"nom de conteneur invalide": func(s *HostSpec) { s.Containers[0].Name = "../x" },
		"conteneur en double":       func(s *HostSpec) { s.Containers[1].Name = s.Containers[0].Name },
		"image invalide":            func(s *HostSpec) { s.Containers[0].Image = "a b" },
		"réseau non déclaré":        func(s *HostSpec) { s.Containers[0].Networks[0].Name = "inconnu" },
		"volume non déclaré":        func(s *HostSpec) { s.Containers[0].Mounts[0].Source = "inconnu" },
		"montage de la racine":      func(s *HostSpec) { s.Containers[1].Mounts[0].Source = "/" },
		"montage de /proc":          func(s *HostSpec) { s.Containers[1].Mounts[0].Source = "/proc/1" },
		"chemin avec ..":            func(s *HostSpec) { s.Containers[1].Mounts[0].Source = "/etc/../root" },
		"type de montage inconnu":   func(s *HostSpec) { s.Containers[0].Mounts[0].Type = "tmpfs" },
		"port invalide":             func(s *HostSpec) { s.Containers[0].Ports[0].ContainerPort = 0 },
		"variable invalide":         func(s *HostSpec) { s.Containers[0].Env["A=B"] = "x" },
		"redémarrage inconnu":       func(s *HostSpec) { s.Containers[0].Restart = "souvent" },
		"wait_healthy sans santé":   func(s *HostSpec) { s.Containers[0].Healthcheck = nil },
		"capacité invalide":         func(s *HostSpec) { s.Containers[0].CapAdd = []string{"net admin"} },
	}
	if err := baseSpec().Validate(nil); err != nil {
		t.Fatalf("la description de base doit être valide : %v", err)
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := baseSpec()
			mutate(s)
			if err := s.Validate(nil); err == nil {
				t.Error("la description doit être refusée")
			}
		})
	}
}

func TestApplyDepositsFilesBeforeStart(t *testing.T) {
	f := newFake()
	f.images["ghcr.io/x/admin:1"], f.images["ghcr.io/x/agent:1"] = true, true
	spec := baseSpec()
	spec.Containers[0].Files = []File{
		{Path: "/etc/goproxify/tls/admin.crt", Content: "CERT"},
		{Path: "/etc/goproxify/tls/admin.key", Mode: 0o600, Content: "KEY"},
	}

	if _, err := New(f, testOptions()).Apply(context.Background(), spec); err != nil {
		t.Fatal(err)
	}

	got := f.files["gpx-admin"]
	if got["/etc/goproxify/tls/admin.crt"] != "CERT" || got["/etc/goproxify/tls/admin.key"] != "KEY" {
		t.Errorf("fichiers déposés = %v", got)
	}
	if f.modes["/etc/goproxify/tls/admin.crt"] != 0o644 || f.modes["/etc/goproxify/tls/admin.key"] != 0o600 {
		t.Errorf("modes = %v", f.modes)
	}
	put, start := -1, -1
	for i, c := range f.calls {
		if strings.HasPrefix(c, "PUT ") && put < 0 {
			put = i
		}
		if strings.HasSuffix(c, "/start") && start < 0 {
			start = i
		}
	}
	if put < 0 || put > start {
		t.Errorf("les fichiers doivent être déposés avant le démarrage : %v", f.calls)
	}
}

func TestApplyRollsBackWhenFilesCannotBeDeposited(t *testing.T) {
	f := newFake()
	f.images["ghcr.io/x/admin:1"], f.images["ghcr.io/x/agent:1"] = true, true
	f.failPut = true
	spec := baseSpec()
	spec.Containers[0].Files = []File{{Path: "/etc/goproxify/x", Content: "x"}}

	if _, err := New(f, testOptions()).Apply(context.Background(), spec); err == nil {
		t.Fatal("l'échec doit être remonté")
	}
	if len(f.containerNames()) != 0 || len(f.running) != 0 {
		t.Errorf("rien ne doit rester : %v", f.containerNames())
	}
}

func TestValidateFiles(t *testing.T) {
	for name, files := range map[string][]File{
		"chemin relatif":       {{Path: "etc/x"}},
		"chemin non normalisé": {{Path: "/etc/../x"}},
		"racine":               {{Path: "/"}},
		"mode invalide":        {{Path: "/x", Mode: 0o1777}},
		"trop volumineux":      {{Path: "/x", Content: strings.Repeat("a", maxFilesSize+1)}},
	} {
		t.Run(name, func(t *testing.T) {
			s := baseSpec()
			s.Containers[0].Files = files
			if err := s.Validate(nil); err == nil {
				t.Error("la description doit être refusée")
			}
		})
	}
}

func TestValidateCustomBindPolicy(t *testing.T) {
	deny := func(string) error { return errors.New("non") }
	if err := baseSpec().Validate(deny); err == nil {
		t.Error("la politique fournie doit s'appliquer aux montages de l'hôte")
	}
}
