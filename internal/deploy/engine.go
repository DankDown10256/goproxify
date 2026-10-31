// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/agent/docker"
)

// API est la part de l'API Docker dont le moteur a besoin ; *docker.Client la satisfait.
type API interface {
	Get(ctx context.Context, path string, out any) error
	Post(ctx context.Context, path string, body any, out any) error
	PostStream(ctx context.Context, path string, headers map[string]string, fn func([]byte)) error
	PutArchive(ctx context.Context, path string, tarBody io.Reader) error
	Delete(ctx context.Context, path string) error
}

// Options règle un déploiement. Tout est facultatif.
type Options struct {
	// DeployID est posé en label (io.goproxify.deploy.id) sur tout ce qui est créé.
	DeployID string
	// PullAlways tire les images même si elles sont déjà présentes.
	PullAlways bool
	// RegistryAuth est la valeur de l'en-tête X-Registry-Auth pour un registre privé.
	RegistryAuth string
	// HealthTimeout borne l'attente d'un conteneur wait_healthy (2 minutes par défaut).
	HealthTimeout time.Duration
	// PollInterval est l'intervalle de cette attente (1 seconde par défaut).
	PollInterval time.Duration
	// AllowBind juge les montages de l'hôte (DefaultAllowBind par défaut).
	AllowBind func(source string) error
	// Progress reçoit les étapes au fur et à mesure.
	Progress func(Event)
}

// Event est une étape du déploiement : pull, network, volume, create, start, healthy, rollback.
type Event struct {
	Step   string
	Name   string
	Detail string
}

// Plan est ce qu'Apply ferait, sans rien modifier.
type Plan struct {
	Pull     []string
	Networks []string
	Volumes  []string
}

// Result liste les conteneurs déployés.
type Result struct {
	Containers []Deployed
}

// Deployed est un conteneur créé et démarré.
type Deployed struct {
	Name string
	ID   string
}

// Engine applique des descriptions d'hôte.
type Engine struct {
	api API
	opt Options
}

// New crée un moteur.
func New(api API, opt Options) *Engine {
	if opt.HealthTimeout <= 0 {
		opt.HealthTimeout = 2 * time.Minute
	}
	if opt.PollInterval <= 0 {
		opt.PollInterval = time.Second
	}
	return &Engine{api: api, opt: opt}
}

func (e *Engine) emit(step, name, detail string) {
	if e.opt.Progress != nil {
		e.opt.Progress(Event{Step: step, Name: name, Detail: detail})
	}
}

func (e *Engine) exists(ctx context.Context, path string) (bool, error) {
	err := e.api.Get(ctx, path, nil)
	if err == nil {
		return true, nil
	}
	if docker.IsNotFound(err) {
		return false, nil
	}
	return false, err
}

// Plan valide la description et dit ce qu'il faudrait créer. Un conteneur du même nom déjà présent est un conflit :
// on ne déploie pas par-dessus une installation existante.
func (e *Engine) Plan(ctx context.Context, spec *HostSpec) (*Plan, error) {
	if err := spec.Validate(e.opt.AllowBind); err != nil {
		return nil, err
	}
	p := &Plan{}
	var conflicts []string
	for _, c := range spec.Containers {
		found, err := e.exists(ctx, "/containers/"+c.Name+"/json")
		if err != nil {
			return nil, err
		}
		if found {
			conflicts = append(conflicts, c.Name)
		}
	}
	if len(conflicts) > 0 {
		return nil, fmt.Errorf("conteneurs déjà présents sur cet hôte : %s", strings.Join(conflicts, ", "))
	}
	for _, n := range spec.Networks {
		found, err := e.exists(ctx, "/networks/"+n.Name)
		if err != nil {
			return nil, err
		}
		if !found {
			p.Networks = append(p.Networks, n.Name)
		}
	}
	for _, v := range spec.Volumes {
		found, err := e.exists(ctx, "/volumes/"+v)
		if err != nil {
			return nil, err
		}
		if !found {
			p.Volumes = append(p.Volumes, v)
		}
	}
	pulled := map[string]bool{}
	for _, c := range spec.Containers {
		if pulled[c.Image] {
			continue
		}
		pulled[c.Image] = true
		found := false
		if !e.opt.PullAlways {
			var err error
			if found, err = e.exists(ctx, "/images/"+c.Image+"/json"); err != nil {
				return nil, err
			}
		}
		if !found {
			p.Pull = append(p.Pull, c.Image)
		}
	}
	return p, nil
}

// journal garde ce que ce déploiement a créé, pour le défaire à l'envers.
type journal struct {
	containers []string
	volumes    []string
	networks   []string
}

// Apply déploie la description : images, réseaux, volumes, puis chaque conteneur dans l'ordre. Si une étape échoue,
// tout ce que ce déploiement a créé est retiré (un réseau ou un volume déjà présent est laissé en place), y compris
// quand ctx est annulé en cours de route.
func (e *Engine) Apply(ctx context.Context, spec *HostSpec) (*Result, error) {
	plan, err := e.Plan(ctx, spec)
	if err != nil {
		return nil, err
	}
	for _, img := range plan.Pull {
		e.emit("pull", img, "")
		if err := e.pull(ctx, img); err != nil {
			return nil, err
		}
	}

	j := &journal{}
	res, err := e.run(ctx, spec, plan, j)
	if err != nil {
		if rerr := e.rollback(ctx, j); rerr != nil {
			return nil, fmt.Errorf("%w (retour arrière incomplet : %v)", err, rerr)
		}
		return nil, err
	}
	return res, nil
}

func (e *Engine) run(ctx context.Context, spec *HostSpec, plan *Plan, j *journal) (*Result, error) {
	labels := map[string]string{}
	if e.opt.DeployID != "" {
		labels["io.goproxify.deploy.id"] = e.opt.DeployID
	}

	byName := map[string]Network{}
	for _, n := range spec.Networks {
		byName[n.Name] = n
	}
	for _, name := range plan.Networks {
		e.emit("network", name, "")
		var created struct {
			ID string `json:"Id"`
		}
		body := map[string]any{"Name": name, "Driver": "bridge", "Internal": byName[name].Internal, "Labels": labels}
		if err := e.api.Post(ctx, "/networks/create", body, &created); err != nil {
			return nil, err
		}
		j.networks = append(j.networks, nameOr(created.ID, name))
	}
	for _, name := range plan.Volumes {
		e.emit("volume", name, "")
		if err := e.api.Post(ctx, "/volumes/create", map[string]any{"Name": name, "Labels": labels}, nil); err != nil {
			return nil, err
		}
		j.volumes = append(j.volumes, name)
	}

	res := &Result{}
	for _, c := range spec.Containers {
		e.emit("create", c.Name, "")
		var created struct {
			ID string `json:"Id"`
		}
		if err := e.api.Post(ctx, "/containers/create?name="+c.Name, containerBody(c, labels), &created); err != nil {
			return nil, fmt.Errorf("création de %s : %w", c.Name, err)
		}
		j.containers = append(j.containers, created.ID)
		for _, a := range c.Networks[min(1, len(c.Networks)):] {
			body := map[string]any{"Container": created.ID, "EndpointConfig": endpoint(a)}
			if err := e.api.Post(ctx, "/networks/"+a.Name+"/connect", body, nil); err != nil {
				return nil, fmt.Errorf("branchement de %s à %s : %w", c.Name, a.Name, err)
			}
		}
		if len(c.Files) > 0 {
			e.emit("files", c.Name, "")
			if err := e.api.PutArchive(ctx, "/containers/"+created.ID+"/archive?path=/", filesArchive(c.Files)); err != nil {
				return nil, fmt.Errorf("dépôt des fichiers de %s : %w", c.Name, err)
			}
		}
		e.emit("start", c.Name, "")
		if err := e.api.Post(ctx, "/containers/"+created.ID+"/start", nil, nil); err != nil {
			return nil, fmt.Errorf("démarrage de %s : %w", c.Name, err)
		}
		if c.WaitHealthy {
			if err := e.waitHealthy(ctx, c.Name, created.ID); err != nil {
				return nil, err
			}
		}
		res.Containers = append(res.Containers, Deployed{Name: c.Name, ID: created.ID})
	}
	return res, nil
}

// Pull tire une image, avec l'authentification de registre des options.
func (e *Engine) Pull(ctx context.Context, image string) error { return e.pull(ctx, image) }

func (e *Engine) pull(ctx context.Context, image string) error {
	pctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	var headers map[string]string
	if e.opt.RegistryAuth != "" {
		headers = map[string]string{"X-Registry-Auth": e.opt.RegistryAuth}
	}
	// Le démon signale un échec de pull dans le flux, avec un statut 200.
	var streamErr string
	err := e.api.PostStream(pctx, "/images/create?fromImage="+url.QueryEscape(image), headers, func(line []byte) {
		var m struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(line, &m) == nil && m.Error != "" {
			streamErr = m.Error
		}
	})
	if err != nil {
		return fmt.Errorf("pull de %s : %w", image, err)
	}
	if streamErr != "" {
		return fmt.Errorf("pull de %s : %s", image, streamErr)
	}
	return nil
}

func (e *Engine) waitHealthy(ctx context.Context, name, id string) error {
	e.emit("healthy", name, "")
	deadline := time.Now().Add(e.opt.HealthTimeout)
	for {
		var st struct {
			State struct {
				Status string `json:"Status"`
				Health *struct {
					Status string `json:"Status"`
				} `json:"Health"`
			} `json:"State"`
		}
		if err := e.api.Get(ctx, "/containers/"+id+"/json", &st); err != nil {
			return fmt.Errorf("état de %s : %w", name, err)
		}
		switch {
		case st.State.Health != nil && st.State.Health.Status == "healthy":
			return nil
		case st.State.Status == "exited" || st.State.Status == "dead":
			return fmt.Errorf("%s s'est arrêté avant d'être sain", name)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s n'est pas sain après %s", name, e.opt.HealthTimeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(e.opt.PollInterval):
		}
	}
}

// rollback retire ce que le déploiement a créé, du dernier au premier. Il ne dépend pas de ctx : l'annulation d'un
// déploiement est justement le moment où il faut nettoyer.
func (e *Engine) rollback(ctx context.Context, j *journal) error {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
	defer cancel()
	var failed []string
	del := func(kind, path, label string) {
		e.emit("rollback", label, kind)
		if err := e.api.Delete(rctx, path); err != nil && !docker.IsNotFound(err) {
			failed = append(failed, fmt.Sprintf("%s %s : %v", kind, label, err))
		}
	}
	for i := len(j.containers) - 1; i >= 0; i-- {
		del("conteneur", "/containers/"+j.containers[i]+"?force=true", shortID(j.containers[i]))
	}
	for i := len(j.volumes) - 1; i >= 0; i-- {
		del("volume", "/volumes/"+j.volumes[i], j.volumes[i])
	}
	for i := len(j.networks) - 1; i >= 0; i-- {
		del("réseau", "/networks/"+j.networks[i], shortID(j.networks[i]))
	}
	if len(failed) > 0 {
		return errors.New(strings.Join(failed, " ; "))
	}
	return nil
}

// containerBody est le corps de POST /containers/create pour un conteneur de la description.
func containerBody(c Container, deployLabels map[string]string) map[string]any {
	body := map[string]any{"Image": c.Image}

	if len(c.Env) > 0 {
		env := make([]string, 0, len(c.Env))
		for k, v := range c.Env {
			env = append(env, k+"="+v)
		}
		sort.Strings(env)
		body["Env"] = env
	}
	if len(c.Cmd) > 0 {
		body["Cmd"] = c.Cmd
	}
	if c.User != "" {
		body["User"] = c.User
	}
	labels := map[string]string{}
	for k, v := range c.Labels {
		labels[k] = v
	}
	for k, v := range deployLabels {
		labels[k] = v
	}
	if len(labels) > 0 {
		body["Labels"] = labels
	}
	if h := c.Healthcheck; h != nil {
		sec := func(n int) int64 { return int64(n) * int64(time.Second) }
		body["Healthcheck"] = map[string]any{
			"Test": h.Test, "Interval": sec(h.IntervalS), "Timeout": sec(h.TimeoutS),
			"Retries": h.Retries, "StartPeriod": sec(h.StartPeriodS),
		}
	}

	// Les infrastructures doivent revenir seules après un redémarrage de l'hôte.
	restart := c.Restart
	if restart == "" {
		restart = "unless-stopped"
	}
	hc := map[string]any{"RestartPolicy": map[string]any{"Name": restart}}
	if len(c.CapAdd) > 0 {
		hc["CapAdd"] = c.CapAdd
	}
	if len(c.CapDrop) > 0 {
		hc["CapDrop"] = c.CapDrop
	}
	if c.ReadOnlyRootfs {
		hc["ReadonlyRootfs"] = true
	}

	if len(c.Ports) > 0 {
		exposed := map[string]any{}
		bindings := map[string][]map[string]string{}
		for _, p := range c.Ports {
			proto := p.Proto
			if proto == "" {
				proto = "tcp"
			}
			key := strconv.Itoa(p.ContainerPort) + "/" + proto
			exposed[key] = map[string]any{}
			host := ""
			if p.HostPort > 0 {
				host = strconv.Itoa(p.HostPort)
			}
			bindings[key] = append(bindings[key], map[string]string{"HostIp": p.HostIP, "HostPort": host})
		}
		body["ExposedPorts"] = exposed
		hc["PortBindings"] = bindings
	}
	if len(c.Mounts) > 0 {
		binds := make([]string, 0, len(c.Mounts))
		for _, m := range c.Mounts {
			b := m.Source + ":" + m.Target
			if m.ReadOnly {
				b += ":ro"
			}
			binds = append(binds, b)
		}
		hc["Binds"] = binds
	}
	if len(c.Networks) > 0 {
		primary := c.Networks[0]
		hc["NetworkMode"] = primary.Name
		body["NetworkingConfig"] = map[string]any{"EndpointsConfig": map[string]any{primary.Name: endpoint(primary)}}
	}
	body["HostConfig"] = hc
	return body
}

// filesArchive range les fichiers dans une archive tar extraite à la racine du conteneur ; le démon crée les dossiers
// manquants. Propriétaire root : c'est l'utilisateur des images GoProxify.
func filesArchive(files []File) io.Reader {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		mode := f.Mode
		if mode == 0 {
			mode = 0o644
		}
		// Une erreur d'écriture dans un tampon mémoire n'arrive pas ; Close finalise l'archive.
		_ = tw.WriteHeader(&tar.Header{Name: strings.TrimPrefix(f.Path, "/"), Mode: mode, Size: int64(len(f.Content)), Typeflag: tar.TypeReg, ModTime: time.Now()})
		_, _ = tw.Write([]byte(f.Content))
	}
	_ = tw.Close()
	return &buf
}

func endpoint(a Attach) map[string]any {
	cfg := map[string]any{}
	if len(a.Aliases) > 0 {
		cfg["Aliases"] = a.Aliases
	}
	return cfg
}

func nameOr(id, name string) string {
	if id != "" {
		return id
	}
	return name
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
