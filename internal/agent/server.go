// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package agent implémente l'Agent Goproxify : découverte Docker/Podman/K8s, télémétrie,
// log forwarding, auto-scaling, gestion du cycle de vie des images.
package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	agentdocker "github.com/vincamok/goproxify/internal/agent/docker"
	agentk8s "github.com/vincamok/goproxify/internal/agent/k8s"
	agentportainer "github.com/vincamok/goproxify/internal/agent/portainer"
	"github.com/vincamok/goproxify/internal/agent/telemetry"
	"github.com/vincamok/goproxify/internal/agent/wsclient"
	"github.com/vincamok/goproxify/internal/buildinfo"
	"github.com/vincamok/goproxify/internal/config"
	corews "github.com/vincamok/goproxify/internal/core/ws"
	"github.com/vincamok/goproxify/internal/nodeident"
)

// Agent orchestre tous les sous-systèmes.
type Agent struct {
	cfg               *config.AgentConfig
	log               *slog.Logger
	discovery         *agentdocker.Discovery
	portainerDisc     *agentportainer.Discovery
	k8sDiscovery      *agentk8s.Discovery
	lifecycle         *agentdocker.LifecycleManager
	logFwd            *agentdocker.LogForwarder
	telSrv            *telemetry.Server
	internalAPI       *internalAPI
	autoScaler        *agentdocker.AutoScaler
	digestWatch       *agentdocker.DigestWatcher
	schedWatch        *agentdocker.ScheduleWatcher
	wsClient          *wsclient.Client // client WS persistant Agent→Core (nil si pas de JoinToken)
	dockerClient      *agentdocker.Client
	shellHub          *shellHub
}

// New crée un Agent à partir de la config.
func New(cfg *config.AgentConfig) (*Agent, error) {
	cfg.Identity.NodeName = nodeident.Resolve("agent")

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	socketPath := agentdocker.AutoDetectSocket(cfg.Docker.Runtime, cfg.Docker.SocketPath)
	cfg.Docker.SocketPath = socketPath
	client := agentdocker.NewClient(socketPath)

	// Network manager
	netMgr := agentdocker.NewNetworkManager(client, cfg.NetworkManagement.CoreContainerName, log)

	// Discovery
	disc := agentdocker.NewDiscovery(
		client,
		cfg.ControlPlane.CoreEndpoint,
		cfg.ControlPlane.AuthToken,
		cfg.Docker.LabelPrefix,
		cfg.Identity.NodeName,
		netMgr,
		log,
	)

	// Lifecycle
	lc := agentdocker.NewLifecycleManager(client, log)
	if cfg.Docker.RegistryUsername != "" {
		lc.SetRegistryAuth(&agentdocker.RegistryAuth{
			Username: cfg.Docker.RegistryUsername,
			Password: cfg.Docker.RegistryPassword,
			Server:   cfg.Docker.RegistryServer,
		})
	}

	// Log forwarder
	var logFwd *agentdocker.LogForwarder
	if cfg.LogForwarding.Enabled {
		logFwd = agentdocker.NewLogForwarder(
			client,
			cfg.ControlPlane.CoreEndpoint,
			cfg.ControlPlane.AuthToken,
			cfg.LogForwarding.BufferLines,
			log,
		)
	}

	// Télémétrie Prometheus
	var tel *telemetry.Server
	if cfg.Telemetry.Enabled {
		tel = telemetry.NewServer(
			cfg.Telemetry.MetricsPort,
			cfg.Telemetry.ScrapeIntervalMs,
			cfg.Identity.NodeName,
			log,
		)
	}

	// API interne (reçoit les commandes de l'Admin)
	intAPI := newInternalAPI(cfg.InternalAPI.Port, lc, log)

	// Auto-scaler
	var as *agentdocker.AutoScaler
	if cfg.AutoScale.Enabled {
		as = agentdocker.NewAutoScaler(
			client, lc,
			cfg.AutoScale.CPUScaleUpPct,
			cfg.AutoScale.CPUScaleDownPct,
			cfg.AutoScale.CooldownS,
			log,
			func(ev agentdocker.ScaleEvent) {
				go reportEvent(context.Background(),
					cfg.ControlPlane.CoreEndpoint,
					cfg.ControlPlane.AuthToken,
					cfg.Identity.NodeName, "",
					"scale_"+ev.Direction,
					fmt.Sprintf("service=%s from=%d to=%d reason=%s", ev.Service, ev.From, ev.To, ev.Reason),
					nil,
					log,
				)
			},
		)
	}

	// Digest watcher (détection proactive de nouvelles versions)
	var dw *agentdocker.DigestWatcher
	if cfg.DigestWatch.Enabled {
		dw = agentdocker.NewDigestWatcher(client, lc, log, func(containerID, image string) {
			go reportEvent(context.Background(),
				cfg.ControlPlane.CoreEndpoint,
				cfg.ControlPlane.AuthToken,
				cfg.Identity.NodeName, containerID,
				"new_digest",
				"image="+image,
				nil,
				log,
			)
			// Mise à jour automatique si label auto=true
			go func() {
				if err := lc.UpdateContainer(context.Background(), containerID, false); err != nil {
					log.Error("digest: auto-update échoué", "container", containerID, "err", err)
				}
			}()
		})
	}

	// Schedule watcher (mises à jour selon cron label)
	sw := agentdocker.NewScheduleWatcher(client, lc, log)

	// Portainer discovery (optionnel — remplace ou complète la discovery locale)
	var portainerDisc *agentportainer.Discovery
	if cfg.Portainer.Enabled && cfg.Portainer.URL != "" && cfg.Portainer.APIKey != "" {
		pc := agentportainer.NewClient(cfg.Portainer.URL, cfg.Portainer.APIKey)
		portainerDisc = agentportainer.NewDiscovery(
			pc,
			cfg.ControlPlane.AdminEndpoint,
			cfg.ControlPlane.AuthToken,
			cfg.Docker.LabelPrefix,
			cfg.Identity.NodeName,
			cfg.Portainer.PollIntervalS,
			log,
		)
	}

	// Kubernetes discovery (optionnel)
	var k8sDisc *agentk8s.Discovery
	if cfg.Kubernetes.Enabled {
		if kd, err := agentk8s.New(cfg, log); err != nil {
			log.Warn("k8s discovery: initialisation impossible", "err", err)
		} else {
			k8sDisc = kd
		}
	}

	intAPI.setDiscovery(disc)

	return &Agent{
		cfg:           cfg,
		log:           log,
		discovery:     disc,
		portainerDisc: portainerDisc,
		k8sDiscovery:  k8sDisc,
		lifecycle:     lc,
		logFwd:        logFwd,
		telSrv:        tel,
		internalAPI:   intAPI,
		autoScaler:    as,
		digestWatch:   dw,
		schedWatch:    sw,
		dockerClient:  client,
	}, nil
}

const agentTokenPath = "/etc/goproxify/agent.token"

// resolveAuthToken retourne le token à utiliser :
// 1. Celui de la config (GPX_CONTROLPLANE_AUTH_TOKEN) s'il est défini.
// 2. Sinon, le token persisté localement après un appairage précédent.
func (a *Agent) resolveAuthToken() string {
	if a.cfg.ControlPlane.AuthToken != "" {
		return a.cfg.ControlPlane.AuthToken
	}
	data, err := os.ReadFile(agentTokenPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// pairWithCore obtient un token Agent auprès du Core local via GPX_PAIRING_SECRET.
// Évite de contacter l'Admin, particulièrement utile sur les hôtes distants.
func (a *Agent) pairWithCore(ctx context.Context) (string, error) {
	if a.cfg.ControlPlane.CoreEndpoint == "" {
		return "", fmt.Errorf("GPX_CONTROL_PLANE_CORE_ENDPOINT non défini")
	}
	// GPX_PAIRING_SECRET est obligatoire (fail-closed côté Core/Admin).
	secret := os.Getenv("GPX_PAIRING_SECRET")
	if secret == "" {
		return "", fmt.Errorf("GPX_PAIRING_SECRET non défini")
	}

	nodeName := a.cfg.Identity.NodeName
	if nodeName == "" {
		nodeName = "agent-1"
	}

	payload, _ := json.Marshal(map[string]string{
		"secret":    secret,
		"node_name": nodeName,
		"role":      "agent",
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		a.cfg.ControlPlane.CoreEndpoint+"/internal/v1/pair", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("core injoignable: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		if resp.StatusCode == http.StatusForbidden {
			return "", fmt.Errorf("appairage refusé : secret invalide")
		}
		if resp.StatusCode == http.StatusServiceUnavailable {
			return "", fmt.Errorf("appairage refusé : pairing non configuré côté Core")
		}
		return "", fmt.Errorf("appairage Core échoué: status %d", resp.StatusCode)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &result); err != nil || result.Token == "" {
		return "", fmt.Errorf("réponse appairage invalide")
	}

	if err := os.WriteFile(agentTokenPath, []byte(result.Token), 0600); err != nil {
		a.log.Warn("agent: impossible de persister le token Core", "err", err)
	}
	a.cfg.ControlPlane.AuthToken = result.Token
	a.internalAPI.setAuthTokens(os.Getenv("GPX_PAIRING_SECRET"), result.Token)
	a.log.Info("agent: appairage Core réussi — token obtenu et persisté", "node", nodeName)
	return result.Token, nil
}

// pairWithAdmin obtient un token Agent auprès de l'Admin via GPX_PAIRING_SECRET.
// Le token est persisté dans agentTokenPath et stocké dans cfg pour la session.
func (a *Agent) pairWithAdmin(ctx context.Context) (string, error) {
	secret := os.Getenv("GPX_PAIRING_SECRET")
	if secret == "" {
		return "", fmt.Errorf("GPX_PAIRING_SECRET non défini")
	}
	if a.cfg.ControlPlane.AdminEndpoint == "" {
		return "", fmt.Errorf("GPX_CONTROLPLANE_ADMIN_ENDPOINT non défini")
	}

	nodeName := a.cfg.Identity.NodeName
	if nodeName == "" {
		nodeName = "agent-1"
	}

	payload, _ := json.Marshal(map[string]string{
		"secret":    secret,
		"node_name": nodeName,
		"role":      "agent",
	})

	url := a.cfg.ControlPlane.AdminEndpoint + "/internal/v1/pair"

	for i := range 5 {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			wait := time.Duration(1<<uint(i)) * time.Second
			a.log.Warn("agent: appairage Admin échoué", "attempt", i+1, "err", err, "wait", wait)
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(wait):
			}
			continue
		}

		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			if resp.StatusCode == http.StatusForbidden {
				return "", fmt.Errorf("appairage refusé : secret invalide")
			}
			wait := time.Duration(1<<uint(i)) * time.Second
			a.log.Warn("agent: appairage Admin échoué", "attempt", i+1, "status", resp.StatusCode, "wait", wait)
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(wait):
			}
			continue
		}

		var result struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(body, &result); err != nil || result.Token == "" {
			return "", fmt.Errorf("réponse appairage invalide")
		}

		if err := os.WriteFile(agentTokenPath, []byte(result.Token), 0600); err != nil {
			a.log.Warn("agent: impossible de persister le token d'appairage", "err", err)
		}
		a.cfg.ControlPlane.AuthToken = result.Token
		a.internalAPI.setAuthTokens(os.Getenv("GPX_PAIRING_SECRET"), result.Token)
		a.log.Info("agent: appairage réussi — token obtenu et persisté", "node", nodeName)
		return result.Token, nil
	}
	return "", fmt.Errorf("agent: appairage impossible après 5 tentatives")
}

// retryPairing tente de s'appairer avec l'Admin toutes les 60 s jusqu'au succès.
// Appelé en goroutine quand l'appairage initial a échoué (ex : Admin temporairement
// injoignable, AGENT_ADMIN_URL mal configuré puis corrigé sans redémarrage).
// Une fois le token obtenu, la discovery est mise à jour et un re-scan est déclenché.
func (a *Agent) retryPairing(ctx context.Context) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if a.cfg.ControlPlane.AuthToken != "" {
				return // appairage réussi entre-temps
			}
			token, err := a.pairWithCore(ctx)
			if err != nil {
				token, err = a.pairWithAdmin(ctx)
			}
			if err != nil {
				a.log.Warn("agent: appairage (retry) échoué", "err", err)
				continue
			}
			a.discovery.SetToken(token)
			go a.discovery.ScanAll(ctx)
			a.log.Info("agent: appairage réussi — scan initial relancé")
			return
		}
	}
}

// handleWSCommand traite les commandes Core → Agent reçues via WebSocket.
func (a *Agent) handleWSCommand(action string, payload json.RawMessage) {
	a.log.Info("agent: commande WS reçue", "action", action)

	triggerRescan := func() {
		if a.discovery == nil {
			a.log.Warn("agent: rescan WS ignoré — discovery non initialisée")
			return
		}
		go func() {
			a.log.Info("agent: commande rescan — scan Docker forcé")
			a.discovery.ScanAll(context.Background())
		}()
	}

	switch action {
	case "rescan":
		triggerRescan()
	case "command":
		var cmd struct {
			Action string `json:"action"`
		}
		if json.Unmarshal(payload, &cmd) == nil && cmd.Action == "rescan" {
			triggerRescan()
		}
	case corews.TypeShellOpen, corews.TypeShellData, corews.TypeShellClose:
		if a.shellHub != nil {
			a.shellHub.Handle(action, payload)
		}
	}
}

// Start démarre tous les sous-systèmes.
func (a *Agent) Start(ctx context.Context) error {
	a.log.Info("agent démarré",
		"node", a.cfg.Identity.NodeName,
		"admin", a.cfg.ControlPlane.AdminEndpoint,
		"core", a.cfg.ControlPlane.CoreEndpoint,
		"docker", a.cfg.Docker.SocketPath,
	)

	// Télémétrie Prometheus
	if a.telSrv != nil {
		a.telSrv.Start(ctx)
	}

	// API interne (Admin → Agent push) — auth fail-closed via pairing secret + token Agent.
	if a.cfg.InternalAPI.Port == 0 {
		a.cfg.InternalAPI.Port = 8001
	}
	internalEndpoint := fmt.Sprintf("http://%s:%d", externalIP(a.cfg.ControlPlane.CoreEndpoint), a.cfg.InternalAPI.Port)
	a.internalAPI.setAuthTokens(os.Getenv("GPX_PAIRING_SECRET"), a.cfg.ControlPlane.AuthToken)
	a.internalAPI.Start(ctx)

	// Amorçage via GPX_AGENT_TOKEN : toujours écrire le token (permet la rotation sans vider le volume).
	if prebuilt := os.Getenv("GPX_AGENT_TOKEN"); prebuilt != "" {
		if wErr := os.WriteFile(agentTokenPath, []byte(strings.TrimSpace(prebuilt)), 0600); wErr == nil {
			a.log.Info("agent: token pré-configuré écrit (GPX_AGENT_TOKEN)", "path", agentTokenPath)
		}
	}

	// Résolution du token : config → fichier local → appairage Core → appairage Admin
	token := a.resolveAuthToken()
	if token == "" {
		var err error
		token, err = a.pairWithCore(ctx)
		if err != nil {
			a.log.Debug("agent: appairage Core échoué, tentative Admin", "err", err)
			token, err = a.pairWithAdmin(ctx)
		}
		if err != nil {
			a.log.Warn("agent: appairage impossible — retry en arrière-plan toutes les 60 s", "err", err)
			go a.retryPairing(ctx)
		}
	}
	if token != "" {
		a.internalAPI.setAuthTokens(os.Getenv("GPX_PAIRING_SECRET"), token)
	}

	// Détection des runtimes actifs
	runtimes := a.detectedRuntimes()

	// Propager le token résolu à la discovery et aux autres composants
	// qui ont été construits avant le pairing (dans New()).
	if token != "" {
		a.discovery.SetToken(token)
	}

	// Client WS persistant Agent→Core
	// Priorité : HMAC persisté > JOIN_TOKEN explicite > token d'appairage Core
	savedHMAC := wsclient.LoadPersistedHMAC()
	joinToken := a.cfg.ControlPlane.JoinToken
	if joinToken == "" && savedHMAC == "" {
		// Pas de HMAC ni de JOIN_TOKEN configuré : utiliser le token d'appairage
		// obtenu via pairWithCore comme bootstrap WS (met l'agent en état "pending").
		joinToken = token
	}
	if savedHMAC != "" || joinToken != "" {
		a.wsClient = wsclient.NewClient(
			a.cfg.Identity.NodeName,
			a.cfg.Identity.NodeName,
			buildinfo.Agent,
			a.cfg.ControlPlane.CoreEndpoint,
			joinToken,
			savedHMAC,
			a.handleWSCommand,
			a.log,
		)
		if a.dockerClient != nil {
			allow := func(id string) bool { return true }
			if a.discovery != nil {
				allow = a.discovery.IsKnown
			}
			a.shellHub = newShellHub(a.dockerClient, a.wsClient, allow)
		}
		if savedHMAC != "" {
			a.log.Info("agent: HMAC persisté chargé — reconnexion WS sans JOIN_TOKEN")
		}
	}

	// Événements cycle de vie / santé → Core (WS prioritaire, HTTP fallback)
	a.discovery.SetOnLifecycle(func(containerID, containerName, action string) {
		go a.emitEvent(containerID, action, "container="+containerName)
	})
	a.lifecycle.SetOnEscalation(func(containerID, containerName, eventType, detail string) {
		go a.emitEvent(containerID, eventType, detail)
	})

	// Heartbeat vers Core (WS si connecté, HTTP sinon)
	go heartbeatLoop(ctx,
		a.cfg.ControlPlane.CoreEndpoint,
		token,
		a.cfg.Identity.NodeName,
		buildinfo.Agent,
		internalEndpoint,
		runtimes,
		a.wsClient,
		a.log,
	)

	// Signal online pour l'historique UI (Événements agent)
	go a.emitEvent("", "agent_online", "version="+buildinfo.Agent)

	// Discovery Docker/Podman (socket local)
	a.discovery.Start(ctx)

	// Métriques conteneur → Core (LB adaptatif)
	if a.wsClient != nil && a.dockerClient != nil {
		go metricsLoop(ctx, a.dockerClient, a.cfg.Identity.NodeName, a.wsClient, a.log)
	}

	// Discovery Portainer (multi-hôtes via API)
	if a.portainerDisc != nil {
		go a.portainerDisc.Start(ctx)
	}

	// Discovery Kubernetes (si activé)
	if a.k8sDiscovery != nil {
		go a.k8sDiscovery.Start(ctx)
	}

	// Schedule watcher (cron label)
	a.schedWatch.Start(ctx)

	// Auto-scaler
	if a.autoScaler != nil {
		a.autoScaler.Start(ctx, a.cfg.AutoScale.CheckIntervalS)
	}

	// Digest watcher
	if a.digestWatch != nil {
		a.digestWatch.Start(ctx, a.cfg.DigestWatch.CheckIntervalS)
	}

	// Health escalation + log forwarding sur les conteneurs existants
	if a.cfg.HealthEscalation.Enabled || (a.logFwd != nil) {
		go a.watchContainersHealth(ctx)
	}

	return nil
}

// emitEvent rapporte un événement au Core (WS si actif, sinon HTTP).
func (a *Agent) emitEvent(containerID, eventType, detail string) {
	token := a.resolveAuthToken()
	if token == "" {
		token = a.cfg.ControlPlane.AuthToken
	}
	reportEvent(context.Background(),
		a.cfg.ControlPlane.CoreEndpoint,
		token,
		a.cfg.Identity.NodeName,
		containerID,
		eventType,
		detail,
		a.wsClient,
		a.log,
	)
}

// detectedRuntimes retourne la liste des runtimes de conteneurs actifs sur cet agent.
func (a *Agent) detectedRuntimes() []string {
	var runtimes []string
	sp := a.cfg.Docker.SocketPath
	if sp != "" {
		if strings.Contains(sp, "podman") {
			runtimes = append(runtimes, "podman")
		} else {
			runtimes = append(runtimes, "docker")
		}
	}
	if a.k8sDiscovery != nil {
		runtimes = append(runtimes, "kubernetes")
	}
	return runtimes
}

// Stop arrête proprement l'agent.
func (a *Agent) Stop(ctx context.Context) {
	if a.wsClient != nil {
		a.wsClient.Close()
	}
	a.internalAPI.Stop(ctx)
	if a.telSrv != nil {
		a.telSrv.Stop(ctx)
	}
	a.log.Info("agent arrêté")
}

// watchContainersHealth surveille la santé et active le log forwarding.
func (a *Agent) watchContainersHealth(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	cfg := agentdocker.HealthEscalationConfig{
		RestartMaxRetries: a.cfg.HealthEscalation.RestartMaxRetries,
		RecreateTimeoutS:  a.cfg.HealthEscalation.RecreateTimeoutS,
		CheckIntervalS:    a.cfg.HealthEscalation.CheckIntervalS,
	}

	watched := make(map[string]bool)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.scheduleHealthWatch(ctx, watched, cfg)
		}
	}
}

func (a *Agent) scheduleHealthWatch(ctx context.Context, watched map[string]bool, cfg agentdocker.HealthEscalationConfig) {
	client := agentdocker.NewClient(a.cfg.Docker.SocketPath)
	var containers []agentdocker.ContainerSummary
	if err := client.Get(ctx, "/containers/json?all=false", &containers); err != nil {
		return
	}
	for _, c := range containers {
		if watched[c.ID] {
			continue
		}
		spec := agentdocker.ParseLabels(c.ID, "", c.Image, "", c.Labels, nil, "")
		if spec == nil {
			continue
		}
		watched[c.ID] = true
		name := ""
		if len(c.Names) > 0 {
			name = c.Names[0]
		}

		if a.cfg.HealthEscalation.Enabled {
			cid, cname := c.ID, name
			go func() {
				a.emitEvent(cid, "health_watch_started", "container="+cname)
				a.lifecycle.WatchHealth(ctx, cid, cname, cfg)
			}()
		}

		if a.logFwd != nil && spec.LogForwarding {
			a.logFwd.Watch(ctx, c.ID, name)
		}
	}
}

// externalIP retourne l'IP routable de l'agent sur le réseau Docker partagé
// en ouvrant une socket UDP vers l'endpoint cible (pas de paquet envoyé).
func externalIP(toward string) string {
	if toward != "" {
		target := strings.TrimPrefix(strings.TrimPrefix(toward, "https://"), "http://")
		if !strings.Contains(target, ":") {
			target += ":80"
		}
		conn, err := net.DialTimeout("udp", target, 2*time.Second)
		if err == nil {
			defer conn.Close()
			if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok && !addr.IP.IsLoopback() {
				return addr.IP.String()
			}
		}
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "127.0.0.1"
	}
	return hostname
}
