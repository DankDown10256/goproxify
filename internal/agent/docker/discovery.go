// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vincamok/goproxify/internal/agent/statepub"
)

// LifecycleEventFn est appelé pour start/die/destroy sur les conteneurs gérés.
type LifecycleEventFn func(containerID, containerName, action string)

// Discovery écoute les événements Docker et rapporte les changements à l'Administration.
type Discovery struct {
	client       *Client
	edgeEndpoint string
	agentName    string
	mu           sync.RWMutex
	authToken    string
	labelPrefix  string
	log          *slog.Logger
	netManager   *NetworkManager
	onLifecycle  LifecycleEventFn
	known        map[string]string // containerID → name (proxies goproxify)

	endpointFn func() string       // passerelle courante (bascule HA) ; nil = edgeEndpoint
	state      *statepub.Publisher // état complet de la source ; nil = publication route par route seulement
	stateOK    atomic.Bool         // la passerelle a pris le dernier état complet : un événement en provoque un nouveau
	stateTimer *time.Timer         // regroupe les événements rapprochés en un seul état complet

	// dirty : un envoi vers la passerelle a échoué, l'état publié est peut-être en retard.
	dirty atomic.Bool
}

// resyncInterval est le délai entre deux vérifications du drapeau dirty.
const resyncInterval = 20 * time.Second

// NewDiscovery crée un Discovery.
func NewDiscovery(client *Client, edgeEndpoint, authToken, labelPrefix, agentName string,
	netMgr *NetworkManager, log *slog.Logger) *Discovery {
	return &Discovery{
		client:       client,
		edgeEndpoint: edgeEndpoint,
		agentName:    agentName,
		authToken:    authToken,
		labelPrefix:  labelPrefix,
		log:          log,
		netManager:   netMgr,
		known:        make(map[string]string),
	}
}

// SetEndpointFunc fait suivre à la découverte la passerelle courante de l'Agent (bascule HA) au lieu
// de l'adresse fixée à la création.
func (d *Discovery) SetEndpointFunc(fn func() string) {
	d.mu.Lock()
	d.endpointFn = fn
	d.mu.Unlock()
}

func (d *Discovery) endpoint() string {
	d.mu.RLock()
	fn, fixed := d.endpointFn, d.edgeEndpoint
	d.mu.RUnlock()
	if fn != nil {
		if ep := fn(); ep != "" {
			return ep
		}
	}
	return fixed
}

// SetStatePublisher active l'envoi de l'état complet à la fin d'un scan.
func (d *Discovery) SetStatePublisher(p *statepub.Publisher) {
	d.mu.Lock()
	d.state = p
	d.mu.Unlock()
}

// SetToken met à jour le token d'authentification (après un appairage différé).
func (d *Discovery) SetToken(token string) {
	d.mu.Lock()
	d.authToken = token
	d.mu.Unlock()
}

// SetOnLifecycle enregistre le callback pour les événements de cycle de vie.
func (d *Discovery) SetOnLifecycle(fn LifecycleEventFn) {
	d.mu.Lock()
	d.onLifecycle = fn
	d.mu.Unlock()
}

// IsKnown indique si le conteneur (ID complet ou préfixe ≥12) est dans le
// catalogue découvert (labels goproxify).
func (d *Discovery) IsKnown(containerID string) bool {
	if d == nil || containerID == "" {
		return false
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if _, ok := d.known[containerID]; ok {
		return true
	}
	if len(containerID) >= 12 {
		prefix := containerID
		if len(prefix) > 12 {
			prefix = prefix[:12]
		}
		for id := range d.known {
			if strings.HasPrefix(id, prefix) || strings.HasPrefix(containerID, id) {
				return true
			}
		}
	}
	return false
}

func (d *Discovery) emitLifecycle(containerID, containerName, action string) {
	d.mu.RLock()
	fn := d.onLifecycle
	d.mu.RUnlock()
	if fn != nil {
		fn(containerID, containerName, action)
	}
}

// Start lance la boucle de découverte : scan initial + écoute du stream d'événements.
func (d *Discovery) Start(ctx context.Context) {
	// Scan initial des conteneurs existants
	d.ScanAll(ctx)
	go d.resyncLoop(ctx)

	// Stream des événements Docker
	go func() {
		for {
			err := d.client.StreamLines(ctx, "/events?filters=%7B%22type%22%3A%7B%22container%22%3Atrue%7D%7D", func(line []byte) {
				var ev Event
				if json.Unmarshal(line, &ev) == nil {
					d.handleEvent(ctx, ev)
				}
			})
			if ctx.Err() != nil {
				return
			}
			d.log.Warn("docker: stream événements interrompu, reconnexion", "err", err)
			time.Sleep(5 * time.Second)
		}
	}()
}

// resyncLoop réannonce tout l'état dès qu'un envoi a échoué : un changement survenu pendant une
// coupure de la passerelle n'est pas perdu.
func (d *Discovery) resyncLoop(ctx context.Context) {
	t := time.NewTicker(resyncInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if d.dirty.Swap(false) {
				d.log.Info("docker: réannonce après envoi en échec")
				d.ScanAll(ctx)
			}
		}
	}
}

// ScanAll liste les conteneurs actifs et rapporte ceux avec les labels Goproxify. Les conteneurs
// connus qui ont disparu depuis (arrêt manqué pendant une coupure) sont signalés comme arrêtés.
// Appelé aussi à chaque reconnexion à la passerelle et par la commande rescan de l'Admin.
func (d *Discovery) ScanAll(ctx context.Context) {
	// Instantané avant la liste : un conteneur démarré pendant le scan n'est pas pris pour un disparu.
	d.mu.RLock()
	knownBefore := make(map[string]string, len(d.known))
	for id, name := range d.known {
		knownBefore[id] = name
	}
	d.mu.RUnlock()

	var containers []ContainerSummary
	if err := d.client.Get(ctx, "/containers/json?all=true", &containers); err != nil {
		d.log.Error("docker: liste containers", "err", err)
		return
	}
	running := make(map[string]struct{}, len(containers))
	for _, c := range containers {
		if containerRunning(c.State) {
			running[c.ID] = struct{}{}
		}
	}
	for id, name := range knownBefore {
		if _, ok := running[id]; ok {
			continue
		}
		d.mu.Lock()
		_, tracked := d.known[id]
		delete(d.known, id)
		d.mu.Unlock()
		if tracked {
			d.log.Info("docker: conteneur disparu pendant une coupure", "name", name)
			d.reportStop(ctx, id, name)
		}
	}
	var all []*ProxySpec
	var inactive []map[string]any
	for _, c := range containers {
		netName, ip := firstNetworkWithIP(c)
		specs := ParseLabelsMulti(c.ID, firstName(c.Names), c.Image, netName, c.Labels, firstExposedPortsFromSummary(c), ip)
		if len(specs) == 0 {
			continue
		}
		// Un conteneur qui ne tourne pas n'a pas de route : il part dans l'inventaire des inactifs, que l'Admin affiche.
		if !containerRunning(c.State) {
			for _, spec := range specs {
				inactive = append(inactive, inactivePayload(spec, c.State))
			}
			continue
		}
		if d.netManager != nil && netName != "" {
			if err := d.netManager.ConnectEdgeToNetwork(ctx, netName); err != nil {
				d.log.Warn("docker: connexion passerelle au réseau (scan initial)", "network", netName, "err", err)
			}
		}
		for _, spec := range specs {
			d.resolveNetworkWhitelist(ctx, spec, netName)
			all = append(all, spec)
		}
		d.mu.Lock()
		d.known[c.ID] = trimSlash(firstName(c.Names))
		d.mu.Unlock()
	}
	if d.publishState(ctx, all, inactive) {
		return
	}
	for _, spec := range all {
		d.report(ctx, spec)
	}
}

// publishState envoie à la passerelle tout ce que Docker publie : elle retire ce qu'elle gardait de cet Agent et qui
// n'y est plus. Faux si la passerelle ne connaît pas l'appel (version ancienne) : l'Agent publie alors route par route.
func (d *Discovery) publishState(ctx context.Context, specs []*ProxySpec, inactive []map[string]any) bool {
	d.mu.RLock()
	pub, token := d.state, d.authToken
	d.mu.RUnlock()
	if pub == nil {
		return false
	}
	routes := make([]map[string]any, 0, len(specs))
	for _, spec := range specs {
		routes = append(routes, d.payload(spec))
	}
	res, err := pub.PutState(ctx, d.endpoint(), token, "docker", "", routes, inactive)
	switch res {
	case statepub.Sent:
		d.stateOK.Store(true)
		if errors.Is(err, statepub.ErrStale) {
			d.log.Warn("docker: état complet ignoré par la passerelle", "err", err)
			return true
		}
		d.log.Info("docker: état complet envoyé à la passerelle", "routes", len(routes), "inactifs", len(inactive))
		return true
	case statepub.Failed:
		d.dirty.Store(true)
		d.log.Warn("docker: état complet non envoyé", "err", err)
		return true
	}
	d.stateOK.Store(false)
	return false
}

// containerRunning : seul un conteneur en cours d'exécution sert une route. Un état vide (liste sans état) vaut « tourne ».
func containerRunning(state string) bool {
	s := strings.ToLower(strings.TrimSpace(state))
	return s == "" || s == "running"
}

// inactivePayload décrit un conteneur découvert qui ne tourne pas (arrêté, en pause, qui redémarre).
func inactivePayload(spec *ProxySpec, state string) map[string]any {
	shortID := spec.ContainerID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	return map[string]any{
		"id":           "docker:" + shortID + ":" + spec.Host,
		"host":         spec.Host,
		"aliases":      spec.Aliases,
		"container_id": spec.ContainerID,
		"name":         strings.TrimPrefix(spec.ContainerName, "/"),
		"state":        strings.ToLower(state),
	}
}

// stateAfterEventDelay regroupe les événements rapprochés (un stack qui démarre) en un seul état complet.
const stateAfterEventDelay = 2 * time.Second

// scheduleState renvoie l'état complet peu après un événement : la passerelle qui reçoit directement l'Agent a déjà la
// route par le POST ou le DELETE, c'est cet état qui atteint les autres membres du groupe HA. Sans effet tant que la
// passerelle n'a pas pris d'état complet (publication route par route, passerelle ancienne).
func (d *Discovery) scheduleState(ctx context.Context) {
	if !d.stateOK.Load() {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stateTimer != nil {
		return
	}
	d.stateTimer = time.AfterFunc(stateAfterEventDelay, func() {
		d.mu.Lock()
		d.stateTimer = nil
		d.mu.Unlock()
		if ctx.Err() == nil {
			d.ScanAll(ctx)
		}
	})
}

// handleEvent réagit aux événements start/die/destroy.
func (d *Discovery) handleEvent(ctx context.Context, ev Event) {
	switch ev.Action {
	case "start":
		var inspect ContainerInspect
		if err := d.client.Get(ctx, "/containers/"+ev.Actor.ID+"/json", &inspect); err != nil {
			d.log.Warn("docker: inspect container", "id", ev.Actor.ID, "err", err)
			return
		}
		name := inspect.Name
		firstNet, ip := "", ""
		for netName, net := range inspect.NetworkSettings.Networks {
			firstNet = netName
			ip = net.IPAddress
			break
		}
		specs := ParseLabelsMulti(ev.Actor.ID, name, inspect.Config.Image, firstNet, inspect.Config.Labels, inspect.Config.ExposedPorts, ip)
		if len(specs) == 0 {
			return
		}
		d.log.Info("docker: conteneur découvert", "name", name, "hosts", len(specs))

		if d.netManager != nil && firstNet != "" {
			if err := d.netManager.ConnectEdgeToNetwork(ctx, firstNet); err != nil {
				d.log.Warn("docker: connexion passerelle au réseau", "network", firstNet, "err", err)
			}
		}
		for _, spec := range specs {
			d.resolveNetworkWhitelist(ctx, spec, firstNet)
			d.report(ctx, spec)
		}
		d.mu.Lock()
		d.known[ev.Actor.ID] = trimSlash(name)
		d.mu.Unlock()
		d.emitLifecycle(ev.Actor.ID, trimSlash(name), "start")
		d.scheduleState(ctx)

	case "die", "destroy":
		name := ev.Actor.Attributes["name"]
		d.mu.Lock()
		knownName, tracked := d.known[ev.Actor.ID]
		if tracked {
			delete(d.known, ev.Actor.ID)
		}
		d.mu.Unlock()
		if !tracked {
			return
		}
		if name == "" {
			name = knownName
		}
		d.log.Info("docker: conteneur arrêté", "name", name)
		d.reportStop(ctx, ev.Actor.ID, name)
		action := ev.Action
		if action == "die" {
			action = "stop"
		}
		d.emitLifecycle(ev.Actor.ID, name, action)
		d.scheduleState(ctx)
	}
}

// resolveNetworkWhitelist résout le CIDR du réseau Docker et l'ajoute à spec.EphorWhitelist
// si goproxify.ephor.whitelist.network est "true".
func (d *Discovery) resolveNetworkWhitelist(ctx context.Context, spec *ProxySpec, networkID string) {
	var extra []string

	if spec.EphorWhitelistSelf && spec.IPAddress != "" {
		extra = append(extra, spec.IPAddress)
	}

	if spec.EphorWhitelistNetwork && networkID != "" {
		cidrs := d.client.NetworkCIDRs(ctx, networkID)
		if len(cidrs) == 0 {
			d.log.Warn("docker: ephor.whitelist.network: CIDR introuvable", "network", networkID, "container", spec.ContainerID)
		}
		extra = append(extra, cidrs...)
	}

	if len(extra) == 0 {
		return
	}
	existing := spec.EphorWhitelist
	for _, e := range extra {
		if existing == "" {
			existing = e
		} else {
			existing += "," + e
		}
	}
	spec.EphorWhitelist = existing
}

// payload construit la charge utile qu'une route Docker envoie à la passerelle.
func (d *Discovery) payload(spec *ProxySpec) map[string]any {
	shortID := spec.ContainerID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	payload := map[string]any{
		"id":           "docker:" + shortID + ":" + spec.Host,
		"host":         spec.Host,
		"aliases":      spec.Aliases,
		"paths":        spec.Paths,
		"route_type":   spec.Type,
		"backends":     []string{spec.BackendURL},
		"tls_enabled":  spec.TLS,
		"passthrough":  spec.Passthrough,
		"source":       "docker",
		"container_id": spec.ContainerID,
		"image":        spec.Image,
		"agent_name":   d.agentName,
		"role":         spec.Role,
	}
	if spec.Role == RoleCanary {
		payload["canary_weight"] = spec.CanaryWeight
	}
	AttachSecurityPayload(payload, spec)
	return payload
}

// report envoie la config proxy vers la passerelle.
func (d *Discovery) report(ctx context.Context, spec *ProxySpec) {
	payload := d.payload(spec)

	d.mu.RLock()
	token := d.authToken
	d.mu.RUnlock()

	body, _ := json.Marshal(payload)
	url := d.endpoint() + "/internal/v1/agent/containers"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		d.dirty.Store(true)
		d.log.Warn("docker: report vers passerelle", "host", spec.Host, "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		d.dirty.Store(true)
	}
	d.log.Info("docker: proxy rapporté à la passerelle", "host", spec.Host, "status", resp.StatusCode)
}

// reportStop notifie la passerelle qu'un conteneur est arrêté.
func (d *Discovery) reportStop(ctx context.Context, id, name string) {
	payload := map[string]any{
		"container_id": id,
		"name":         name,
		"action":       "stop",
	}

	d.mu.RLock()
	token := d.authToken
	d.mu.RUnlock()

	body, _ := json.Marshal(payload)
	url := d.endpoint() + "/internal/v1/agent/containers"
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		d.dirty.Store(true)
		d.log.Warn("docker: report stop vers passerelle", "err", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		d.dirty.Store(true)
	}
}

// --- Helpers ---------------------------------------------------------------

func firstName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

func firstNetworkWithIP(c ContainerSummary) (name, ip string) {
	for n, net := range c.NetworkSettings.Networks {
		return n, net.IPAddress
	}
	return "", ""
}

// firstExposedPortsFromSummary construit un map ExposedPorts depuis les Ports du summary.
func firstExposedPortsFromSummary(c ContainerSummary) map[string]struct{} {
	if len(c.Ports) == 0 {
		return nil
	}
	m := make(map[string]struct{}, len(c.Ports))
	for _, p := range c.Ports {
		if p.Type == "tcp" && p.PrivatePort > 0 {
			m[strconv.Itoa(p.PrivatePort)+"/tcp"] = struct{}{}
		}
	}
	return m
}

// Ping vérifie que le daemon Docker est joignable.
func (d *Discovery) Ping(ctx context.Context) error {
	var info struct {
		ID string `json:"ID"`
	}
	if err := d.client.Get(ctx, "/info", &info); err != nil {
		return fmt.Errorf("docker daemon injoignable : %w", err)
	}
	return nil
}
