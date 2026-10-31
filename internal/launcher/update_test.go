// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package launcher

import (
	"bytes"
	"context"
	"encoding/json"
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

type updCtr struct {
	id, name, imageID string
	config            map[string]any
	status            string
	unhealthy         bool
}

// updDaemon est un démon Docker minimal avec état : conteneurs, images locales et ce qu'un pull apporte.
type updDaemon struct {
	mu         sync.Mutex
	next       int
	ctrs       map[string]*updCtr // par identifiant
	names      map[string]string  // nom → identifiant
	images     map[string]string  // image locale : référence → identifiant
	pullTo     map[string]string  // ce qu'un pull apporte, par référence
	pullFail   map[string]bool
	badImages  map[string]bool // identifiants d'images dont le conteneur ne devient jamais sain
	pulled     []string
	recreated  []string // noms créés, dans l'ordre
	deletedIDs []string
}

func newUpdDaemon() *updDaemon {
	return &updDaemon{
		ctrs: map[string]*updCtr{}, names: map[string]string{}, images: map[string]string{},
		pullTo: map[string]string{}, pullFail: map[string]bool{}, badImages: map[string]bool{},
	}
}

// install pose un conteneur déjà en place, créé depuis la référence, dont l'image locale vaut imageID.
func (d *updDaemon) install(name, ref, imageID string, env ...string) {
	d.images[ref] = imageID
	d.next++
	c := &updCtr{id: fmt.Sprintf("old%d", d.next), name: name, imageID: imageID, status: "running", config: map[string]any{
		"Image": ref, "Env": env, "Healthcheck": map[string]any{"Test": []string{"CMD", "true"}},
	}}
	d.ctrs[c.id] = c
	d.names[name] = c.id
}

func (d *updDaemon) lookup(x string) *updCtr {
	if id, ok := d.names[x]; ok {
		return d.ctrs[id]
	}
	return d.ctrs[x]
}

func fill(out any, v any) error {
	b, _ := json.Marshal(v)
	return json.Unmarshal(b, out)
}

func notFound(method, path string) error {
	return &docker.APIError{Method: method, Path: path, Status: http.StatusNotFound}
}

func (d *updDaemon) Get(_ context.Context, path string, out any) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json"):
		c := d.lookup(strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/json"))
		if c == nil {
			return notFound("GET", path)
		}
		state := map[string]any{"Status": c.status}
		if c.config["Healthcheck"] != nil && c.status == "running" {
			health := "healthy"
			if c.unhealthy {
				health = "starting"
			}
			state["Health"] = map[string]any{"Status": health}
		}
		return fill(out, map[string]any{
			"Id": c.id, "Name": "/" + c.name, "Image": c.imageID, "Config": c.config, "State": state,
			"HostConfig":      map[string]any{"NetworkMode": "goproxify_net"},
			"NetworkSettings": map[string]any{"Networks": map[string]any{"goproxify_net": map[string]any{"Aliases": []string{c.name}}}},
		})
	case strings.HasPrefix(path, "/images/") && strings.HasSuffix(path, "/json"):
		ref := strings.TrimSuffix(strings.TrimPrefix(path, "/images/"), "/json")
		id, ok := d.images[ref]
		if !ok {
			return notFound("GET", path)
		}
		return fill(out, map[string]any{"Id": id})
	}
	return notFound("GET", path)
}

func (d *updDaemon) Post(_ context.Context, path string, body any, out any) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	u, _ := url.Parse(path)
	switch {
	case u.Path == "/containers/create":
		raw, _ := json.Marshal(body)
		var b map[string]any
		_ = json.Unmarshal(raw, &b)
		ref, _ := b["Image"].(string)
		imageID := d.images[ref]
		if strings.HasPrefix(ref, "sha256:") {
			imageID = ref
		}
		d.next++
		c := &updCtr{id: fmt.Sprintf("new%d", d.next), name: u.Query().Get("name"), imageID: imageID, config: b, status: "created"}
		c.unhealthy = d.badImages[imageID]
		d.ctrs[c.id] = c
		d.names[c.name] = c.id
		d.recreated = append(d.recreated, c.name)
		return fill(out, map[string]any{"Id": c.id})
	case strings.HasSuffix(u.Path, "/stop"):
		if c := d.lookup(strings.TrimSuffix(strings.TrimPrefix(u.Path, "/containers/"), "/stop")); c != nil {
			c.status = "exited"
		}
	case strings.HasSuffix(u.Path, "/start"):
		if c := d.lookup(strings.TrimSuffix(strings.TrimPrefix(u.Path, "/containers/"), "/start")); c != nil {
			c.status = "running"
		}
	case strings.HasSuffix(u.Path, "/rename"):
		c := d.lookup(strings.TrimSuffix(strings.TrimPrefix(u.Path, "/containers/"), "/rename"))
		if c == nil {
			return notFound("POST", path)
		}
		delete(d.names, c.name)
		c.name = u.Query().Get("name")
		d.names[c.name] = c.id
	case strings.HasSuffix(u.Path, "/tag"):
		id := strings.TrimSuffix(strings.TrimPrefix(u.Path, "/images/"), "/tag")
		d.images[u.Query().Get("repo")+":"+u.Query().Get("tag")] = id
	}
	return nil
}

func (d *updDaemon) PostWithHeaders(ctx context.Context, path string, body any, out any, _ map[string]string) error {
	return d.Post(ctx, path, body, out)
}

func (d *updDaemon) PostStream(_ context.Context, path string, _ map[string]string, _ func([]byte)) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	u, _ := url.Parse(path)
	ref := u.Query().Get("fromImage")
	d.pulled = append(d.pulled, ref)
	if d.pullFail[ref] {
		return &docker.APIError{Method: "POST", Path: path, Status: http.StatusForbidden}
	}
	if id, ok := d.pullTo[ref]; ok {
		d.images[ref] = id
	}
	return nil
}

func (d *updDaemon) PutArchive(context.Context, string, io.Reader) error { return nil }

func (d *updDaemon) Delete(_ context.Context, path string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	u, _ := url.Parse(path)
	id := strings.TrimPrefix(u.Path, "/containers/")
	if c, ok := d.ctrs[id]; ok {
		if d.names[c.name] == id {
			delete(d.names, c.name)
		}
		delete(d.ctrs, id)
		d.deletedIDs = append(d.deletedIDs, id)
	}
	return nil
}

func (d *updDaemon) container(name string) *updCtr {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lookup(name)
}

func fastUpdate(out io.Writer) UpdateOptions {
	return UpdateOptions{Out: out, HealthTimeout: 100 * time.Millisecond, PollInterval: time.Millisecond}
}

const (
	adminRef = "reg.lan/goproxify/admin:latest"
	edgeRef  = "reg.lan/goproxify/edge:latest"
	agentRef = "reg.lan/goproxify/agent:latest"
)

func installedDaemon() *updDaemon {
	d := newUpdDaemon()
	d.install("goproxify-admin", adminRef, "sha256:admin-old", "GPX_PAIRING_SECRET=root", "TZ=Europe/Paris")
	d.install("goproxify-edge", edgeRef, "sha256:edge-1", "GPX_EDGE_CHANNEL_KEY=k")
	d.install("goproxify-agent", agentRef, "sha256:agent-1")
	return d
}

func TestUpdateRecreatesOnlyWhatChangedAndKeepsItsConfiguration(t *testing.T) {
	d := installedDaemon()
	d.pullTo[adminRef] = "sha256:admin-new"
	var out bytes.Buffer
	rep, err := Update(context.Background(), d, fastUpdate(&out))
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !reflect.DeepEqual(rep.Updated, []string{"goproxify-admin"}) || !reflect.DeepEqual(rep.Current, []string{"goproxify-edge", "goproxify-agent"}) {
		t.Errorf("mis à jour = %v, déjà à jour = %v", rep.Updated, rep.Current)
	}
	if !reflect.DeepEqual(d.recreated, []string{"goproxify-admin"}) {
		t.Errorf("seul l'Admin est recréé : %v", d.recreated)
	}
	admin := d.container("goproxify-admin")
	if admin.imageID != "sha256:admin-new" || admin.status != "running" || !strings.HasPrefix(admin.id, "new") {
		t.Errorf("l'Admin doit tourner avec la nouvelle image : %+v", admin)
	}
	if env, _ := admin.config["Env"].([]any); len(env) != 2 || env[0] != "GPX_PAIRING_SECRET=root" {
		t.Errorf("les variables (secrets compris) sont conservées : %v", admin.config["Env"])
	}
	if admin.config["Image"] != adminRef {
		t.Errorf("l'image reste désignée par son étiquette : %v", admin.config["Image"])
	}
	if edge := d.container("goproxify-edge"); !strings.HasPrefix(edge.id, "old") {
		t.Errorf("la passerelle n'est pas touchée : %+v", edge)
	}
	if len(d.ctrs) != 3 {
		t.Errorf("l'ancien conteneur de l'Admin ne doit pas rester : %d conteneurs", len(d.ctrs))
	}
	if s := rep.Summary(); !strings.Contains(s, "goproxify-admin") || !strings.Contains(s, "déjà à jour") {
		t.Errorf("résumé : %q", s)
	}
}

func TestUpdateAllCurrent(t *testing.T) {
	d := installedDaemon()
	rep, err := Update(context.Background(), d, fastUpdate(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Updated) != 0 || len(d.recreated) != 0 {
		t.Errorf("rien à faire : %+v, recréés %v", rep, d.recreated)
	}
	if rep.Summary() != "\nTout est déjà à jour.\n" {
		t.Errorf("résumé : %q", rep.Summary())
	}
}

func TestUpdateRollsBackWhenTheNewContainerNeverGetsHealthy(t *testing.T) {
	d := installedDaemon()
	d.pullTo[adminRef] = "sha256:admin-new"
	d.badImages["sha256:admin-new"] = true
	var out bytes.Buffer
	rep, err := Update(context.Background(), d, fastUpdate(&out))
	if err == nil || !strings.Contains(err.Error(), "annulée") {
		t.Fatalf("la mise à jour doit échouer : %v", err)
	}
	if len(rep.Updated) != 0 {
		t.Errorf("rien n'est mis à jour : %v", rep.Updated)
	}
	admin := d.container("goproxify-admin")
	if admin.imageID != "sha256:admin-old" || admin.status != "running" {
		t.Errorf("l'Admin doit retrouver son ancienne image : %+v", admin)
	}
	if admin.config["Image"] != adminRef {
		t.Errorf("l'étiquette doit désigner l'ancienne image, pour que la mise à jour suivante tire la bonne : %v", admin.config["Image"])
	}
	if d.images[adminRef] != "sha256:admin-old" {
		t.Errorf("étiquette locale = %q", d.images[adminRef])
	}
	if !strings.Contains(out.String(), "retour à l'ancienne image") {
		t.Errorf("sortie : %s", out.String())
	}
}

func TestUpdateUsesTheLocalImageWhenThePullIsRefused(t *testing.T) {
	d := installedDaemon()
	// Registre privé : le démon n'a pas d'identifiants, mais l'image a été tirée à la main.
	d.pullFail[adminRef] = true
	d.images[adminRef] = "sha256:admin-by-hand"
	var out bytes.Buffer
	rep, err := Update(context.Background(), d, fastUpdate(&out))
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if !reflect.DeepEqual(rep.Updated, []string{"goproxify-admin"}) {
		t.Errorf("mis à jour = %v", rep.Updated)
	}
	if d.container("goproxify-admin").imageID != "sha256:admin-by-hand" {
		t.Error("l'Admin doit passer à l'image tirée à la main")
	}
	if !strings.Contains(out.String(), "attention") || !strings.Contains(out.String(), "image locale") {
		t.Errorf("l'échec du pull doit être signalé : %s", out.String())
	}
}

func TestUpdateFailsWhenThePullFailsAndNoLocalImageExists(t *testing.T) {
	d := installedDaemon()
	d.pullFail[adminRef] = true
	delete(d.images, adminRef)
	if _, err := Update(context.Background(), d, fastUpdate(nil)); err == nil || !strings.Contains(err.Error(), "pull") {
		t.Fatalf("l'échec du pull doit remonter : %v", err)
	}
	if len(d.recreated) != 0 {
		t.Errorf("rien ne doit être touché avant que toutes les images soient là : %v", d.recreated)
	}
}

func TestUpdateWithoutInstallationFails(t *testing.T) {
	if _, err := Update(context.Background(), newUpdDaemon(), fastUpdate(nil)); err == nil || !strings.Contains(err.Error(), "aucune installation") {
		t.Fatalf("erreur attendue : %v", err)
	}
}

func TestUpdateDryRunChangesNothing(t *testing.T) {
	d := installedDaemon()
	d.pullTo[adminRef] = "sha256:admin-new"
	var out bytes.Buffer
	opt := fastUpdate(&out)
	opt.DryRun = true
	if _, err := Update(context.Background(), d, opt); err != nil {
		t.Fatal(err)
	}
	if len(d.pulled) != 0 || len(d.recreated) != 0 {
		t.Errorf("rien ne doit être tiré ni recréé : %v %v", d.pulled, d.recreated)
	}
	if !strings.Contains(out.String(), adminRef) {
		t.Errorf("sortie : %s", out.String())
	}
}

func TestSplitRef(t *testing.T) {
	for _, c := range []struct{ ref, repo, tag string; ok bool }{
		{"ghcr.io/vincamok/goproxify/edge:preview", "ghcr.io/vincamok/goproxify/edge", "preview", true},
		{"localhost:5000/edge", "localhost:5000/edge", "latest", true},
		{"localhost:5000/edge:1.2", "localhost:5000/edge", "1.2", true},
		{"reg/edge@sha256:abc", "", "", false},
	} {
		repo, tag, ok := splitRef(c.ref)
		if repo != c.repo || tag != c.tag || ok != c.ok {
			t.Errorf("splitRef(%q) = %q, %q, %v", c.ref, repo, tag, ok)
		}
	}
}
