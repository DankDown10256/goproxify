// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package agent implémente l'Agent Goproxify : découverte Docker/Podman/K8s, télémétrie,
// log forwarding, auto-scaling, gestion du cycle de vie des images.
package agent

import (
	"github.com/vincamok/goproxify/internal/pairing"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"time"

	agentdocker "github.com/vincamok/goproxify/internal/agent/docker"
	"github.com/vincamok/goproxify/internal/agent/edgeset"
	agentsources "github.com/vincamok/goproxify/internal/agent/sources"
	"github.com/vincamok/goproxify/internal/agent/statepub"
	"github.com/vincamok/goproxify/internal/agent/telemetry"
	"github.com/vincamok/goproxify/internal/agent/wsclient"
	"github.com/vincamok/goproxify/internal/buildinfo"
	"github.com/vincamok/goproxify/internal/config"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
	"github.com/vincamok/goproxify/internal/nodeident"
)

// Agent orchestre tous les sous-systèmes.
type Agent struct {
	cfg          *config.AgentConfig
	cfgPath      string // chemin vers agent.json (pour les écritures de config)
	log          *slog.Logger
	discovery    *agentdocker.Discovery   // source Docker/Podman (accès typé : rescan, cycle de vie)
	sources      []*agentsources.Instance // toutes les sources de découverte actives (registre)
	lifecycle    *agentdocker.LifecycleManager
	logFwd       *agentdocker.LogForwarder
	telSrv       *telemetry.Server
	internalAPI  *internalAPI
	autoScaler   *agentdocker.AutoScaler
	digestWatch  *agentdocker.DigestWatcher
	schedWatch   *agentdocker.ScheduleWatcher
	wsClient     *wsclient.Client // client WS persistant Agent→Passerelle (nil si pas de JoinToken)
	dockerClient *agentdocker.Client
	shellHub     *shellHub
	tokenUpdate  chan string  // notifie heartbeatLoop d'un nouveau token (retryPairing)
	edges        *edgeset.Set // passerelle courante et autres membres du groupe HA (bascule)

	repairMu   sync.Mutex // sérialise refreshToken
	lastRepair time.Time
}

// agentEdgesPath conserve les autres membres du groupe HA annoncés par la passerelle.
const agentEdgesPath = "/etc/goproxify/agent-edges.json"

// agentStateGenPath conserve la dernière génération d'état complet envoyée : un Agent redémarré ne repart pas en dessous.
const agentStateGenPath = "/etc/goproxify/agent-state-generation"

// New crée un Agent à partir de la config.
func New(cfg *config.AgentConfig, cfgPath string) (*Agent, error) {
	cfg.Identity.NodeName = nodeident.Resolve("agent")
	edges := edgeset.New(cfg.ControlPlane.EdgeEndpoint, agentEdgesPath)

	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	socketPath := agentdocker.AutoDetectSocket(cfg.Docker.Runtime, cfg.Docker.SocketPath)
	cfg.Docker.SocketPath = socketPath
	client := agentdocker.NewClient(socketPath)

	// Network manager
	netMgr := agentdocker.NewNetworkManager(client, cfg.NetworkManagement.EdgeContainerName, log)

	// Sources de découverte (Docker/Podman, Portainer, Kubernetes… : modules du registre
	// internal/agent/sources). Docker reste actif avec une ancienne config qui définit
	// docker.runtime ; Docker est désactivable via docker.enabled: false.
	state := statepub.New(cfg.Identity.NodeName, agentStateGenPath)
	srcs := agentsources.BuildBuiltin(agentsources.Deps{Cfg: cfg, Log: log, Docker: client, Net: netMgr, Edges: edges, State: state})
	var disc *agentdocker.Discovery
	for _, s := range srcs {
		if d, ok := s.Impl.(*agentdocker.Discovery); ok {
			disc = d
		}
	}

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
			cfg.ControlPlane.EdgeEndpoint,
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
					edges.Current(),
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
				edges.Current(),
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

	intAPI.setDiscovery(disc)
	intAPI.cfgPath = cfgPath

	a := &Agent{
		edges:        edges,
		cfg:          cfg,
		cfgPath:      cfgPath,
		log:          log,
		discovery:    disc,
		sources:      srcs,
		lifecycle:    lc,
		logFwd:       logFwd,
		telSrv:       tel,
		internalAPI:  intAPI,
		autoScaler:   as,
		digestWatch:  dw,
		schedWatch:   sw,
		dockerClient: client,
	}
	state.SetOnUnauthorized(a.refreshToken)
	return a, nil
}

// repairBackoff sépare deux réappairages après un 401 : une passerelle qui refuse l'appairage ne doit pas être
// martelée par chaque envoi d'état de chaque endpoint.
const repairBackoff = 30 * time.Second

// refreshToken s'appaire de nouveau avec la passerelle parce qu'elle a refusé le jeton HTTP de l'Agent (401). Cela
// arrive quand son magasin de jetons a été remis à zéro (volume recréé) : le WebSocket, authentifié par HMAC, reste
// connecté, le battement de cœur passe par lui et ne le voit pas. Les envois d'état de toutes les sources (chacune
// scanne en parallèle) arrivent ici ensemble : un seul appairage a lieu, les autres reprennent son jeton.
func (a *Agent) refreshToken(ctx context.Context, stale string) string {
	a.repairMu.Lock()
	defer a.repairMu.Unlock()
	if cur := a.cfg.ControlPlane.AuthToken; cur != "" && cur != stale {
		return cur // un autre envoi l'a déjà renouvelé
	}
	if !a.lastRepair.IsZero() && time.Since(a.lastRepair) < repairBackoff {
		return ""
	}
	a.lastRepair = time.Now()
	a.log.Warn("agent: la passerelle refuse le jeton HTTP (401) — re-appairage")
	t, err := a.pair(ctx)
	if err != nil {
		a.log.Warn("agent: re-appairage impossible après un 401", "err", err)
		return ""
	}
	a.setSourcesToken(t)
	select {
	case a.tokenUpdate <- t:
	default:
	}
	return t
}

// agentTokenPath est une variable pour que les tests l'écartent du vrai dossier d'état (voir main_test.go).
var agentTokenPath = "/etc/goproxify/agent.token"

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

// pairingCredential : la clé d'appairage de l'Agent (GPX_AGENT_PAIRING_KEY), ou à défaut le secret racine d'une
// installation qui n'a pas migré — l'Agent le détient alors, ce qu'on évite : voir le paquet pairing.
func (a *Agent) pairingCredential() string {
	cred, legacyRoot := pairing.AgentCredential()
	if legacyRoot && cred != "" {
		a.log.Warn("agent: GPX_PAIRING_SECRET (secret racine) est présent sur cet hôte — utilisez GPX_AGENT_PAIRING_KEY, une clé dérivée qui ne permet pas de se faire passer pour l'Admin")
	}
	return cred
}

// setInternalAuth déclare les Bearer que l'API interne de l'Agent accepte : la clé d'appairage et sa dérivée (ce que
// l'Admin et la passerelle envoient), plus le jeton de la passerelle.
func (a *Agent) setInternalAuth(token string) {
	accepted := append(pairing.AgentBearers(), token)
	a.internalAPI.setAuthTokens(accepted...)
}

// pairingCredentials : la clé d'appairage courante, puis les précédentes d'une rotation en cours.
func (a *Agent) pairingCredentials() []string {
	_ = a.pairingCredential() // avertit si l'Agent détient le secret racine
	creds, _ := pairing.AgentCredentials()
	out := make([]string, 0, len(creds))
	for _, c := range creds {
		out = append(out, c.Value)
	}
	return out
}

// pair obtient le jeton HTTP de l'Agent. Un Agent qui a une passerelle ne s'appaire qu'avec elle, même quand elle ne répond
// pas encore (redéploiement simultané) : l'Admin émet un jeton que la passerelle, qui a son propre magasin, ne connaîtra
// jamais ; l'Agent le garderait dans agent.token et recevrait des 401 sur chaque appel, sans qu'aucune bascule ni
// aucun redémarrage n'y change rien (ADR 0006 : l'Agent ne dépend que de sa passerelle). L'Admin ne sert que sans
// passerelle configurée.
func (a *Agent) pair(ctx context.Context) (string, error) {
	if a.cfg.ControlPlane.EdgeEndpoint == "" {
		return a.pairWithAdmin(ctx)
	}
	return a.pairWithEdge(ctx)
}

// pairWithEdge obtient un token Agent auprès de la passerelle locale avec la clé d'appairage.
// Évite de contacter l'Admin, particulièrement utile sur les hôtes distants.
func (a *Agent) pairWithEdge(ctx context.Context) (string, error) {
	if a.cfg.ControlPlane.EdgeEndpoint == "" {
		return "", fmt.Errorf("GPX_CONTROL_PLANE_EDGE_ENDPOINT non défini")
	}
	// La clé d'appairage est obligatoire (fail-closed côté passerelle/Admin).
	creds := a.pairingCredentials()
	if len(creds) == 0 {
		return "", fmt.Errorf("GPX_AGENT_PAIRING_KEY non défini")
	}

	nodeName := a.cfg.Identity.NodeName
	if nodeName == "" {
		nodeName = "agent-1"
	}

	var lastErr error
	for i, secret := range creds {
		payload, _ := json.Marshal(map[string]string{
			"secret":    secret,
			"node_name": nodeName,
			"role":      "agent",
		})

		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			a.edges.Current()+"/internal/v1/pair", bytes.NewReader(payload))
		if err != nil {
			return "", err
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return "", fmt.Errorf("edge injoignable: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
			if resp.StatusCode == http.StatusForbidden {
				// Pendant une rotation, la passerelle peut n'avoir encore que l'autre clé : on essaie la suivante.
				lastErr = fmt.Errorf("appairage refusé : secret invalide")
				if i < len(creds)-1 {
					continue
				}
				return "", lastErr
			}
			if resp.StatusCode == http.StatusServiceUnavailable {
				return "", fmt.Errorf("appairage refusé : pairing non configuré côté passerelle")
			}
			return "", fmt.Errorf("appairage passerelle échoué: status %d", resp.StatusCode)
		}

		var result struct {
			Token string `json:"token"`
		}
		if err := json.Unmarshal(body, &result); err != nil || result.Token == "" {
			return "", fmt.Errorf("réponse appairage invalide")
		}

		if err := os.WriteFile(agentTokenPath, []byte(result.Token), 0600); err != nil {
			a.log.Warn("agent: impossible de persister le token passerelle", "err", err)
		}
		a.cfg.ControlPlane.AuthToken = result.Token
		a.setInternalAuth(result.Token)
		if i > 0 {
			a.log.Warn("agent: appairé avec une clé précédente — rotation en cours, mettre GPX_AGENT_PAIRING_KEY à la clé courante de la passerelle")
		}
		a.log.Info("agent: appairage passerelle réussi — token obtenu et persisté", "node", nodeName)
		return result.Token, nil
	}
	return "", lastErr
}

// pairWithAdmin obtient un token Agent auprès de l'Admin avec la clé d'appairage.
// Le token est persisté dans agentTokenPath et stocké dans cfg pour la session.
func (a *Agent) pairWithAdmin(ctx context.Context) (string, error) {
	secret := a.pairingCredential()
	if secret == "" {
		return "", fmt.Errorf("GPX_AGENT_PAIRING_KEY non défini")
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
		// Un Agent déjà appairé présente son jeton : sans lui, l'Admin ne le lui rend pas et attend l'approbation.
		if tok := a.resolveAuthToken(); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}

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
		a.setInternalAuth(result.Token)
		a.log.Info("agent: appairage réussi — token obtenu et persisté", "node", nodeName)
		return result.Token, nil
	}
	return "", fmt.Errorf("agent: appairage impossible après 5 tentatives")
}

// retryPairing tente de s'appairer avec la passerelle/Admin en backoff exponentiel
// (5 s → 10 s → 20 s → 40 s → 60 s max) jusqu'au succès.
// Appelé en goroutine quand l'appairage initial a échoué (ex : Passerelle qui démarre
// après l'Agent, AGENT_ADMIN_URL mal configuré puis corrigé sans redémarrage).
// Une fois le token obtenu, la discovery est mise à jour et un re-scan est déclenché.
func (a *Agent) retryPairing(ctx context.Context) {
	delay := 5 * time.Second
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
			if delay < 60*time.Second {
				delay *= 2
				if delay > 60*time.Second {
					delay = 60 * time.Second
				}
			}
			if a.cfg.ControlPlane.AuthToken != "" {
				return // appairage réussi entre-temps
			}
			token, err := a.pair(ctx)
			if err != nil {
				a.log.Warn("agent: appairage (retry) échoué", "err", err, "prochain_essai", delay)
				continue
			}
			a.setSourcesToken(token)
			a.reannounceSources(ctx)
			// Propager le token au heartbeatLoop (qui tourne avec authToken="")
			select {
			case a.tokenUpdate <- token:
			default:
			}
			// Créer le client WS maintenant que le token est disponible
			if a.wsClient == nil {
				a.wsClient = wsclient.NewClient(
					a.cfg.Identity.NodeName,
					a.cfg.Identity.NodeName,
					buildinfo.Agent,
					a.cfg.ControlPlane.EdgeEndpoint,
					token,
					"",
					a.handleWSCommand,
					a.log,
				)
				a.reannounceOnConnect()
			}
			a.log.Info("agent: appairage réussi — scan initial relancé")
			return
		}
	}
}

// onEdgeSwitch suit la bascule vers un autre membre du groupe HA : le jeton HTTP de l'Agent a été
// émis par l'ancienne passerelle, on en demande un à la nouvelle (le secret d'appairage est commun),
// puis on republie tous les conteneurs. Le WebSocket, lui, s'authentifie avec le HMAC répliqué.
func (a *Agent) onEdgeSwitch(edge string) {
	ctx := context.Background()
	a.log.Warn("agent: bascule vers une autre passerelle du groupe", "edge", edge)
	token, err := a.pairWithEdge(ctx)
	if err != nil {
		a.log.Warn("agent: appairage sur la nouvelle passerelle échoué — il sera retenté par le heartbeat", "edge", edge, "err", err)
	} else {
		a.setSourcesToken(token)
		select {
		case a.tokenUpdate <- token:
		default:
		}
	}
	a.reannounceSources(ctx)
}

// reannounceSources fait republier son état complet à chaque source (Docker, Portainer,
// Kubernetes…) vers la passerelle courante. Chaque source part dans sa goroutine : une source lente
// ne retarde ni les autres ni l'appelant.
func (a *Agent) reannounceSources(ctx context.Context) {
	for _, s := range a.sources {
		if s.Reannounce != nil {
			go s.Reannounce(ctx)
		}
	}
}

func (a *Agent) hasReannounce() bool {
	for _, s := range a.sources {
		if s.Reannounce != nil {
			return true
		}
	}
	return false
}

// reannounceOnConnect republie toutes les sources à chaque (re)connexion à la passerelle : un
// changement survenu pendant une coupure, ou une passerelle redémarrée, n'est pas perdu.
func (a *Agent) reannounceOnConnect() {
	if a.wsClient == nil {
		return
	}
	a.wsClient.SetEdgeSet(a.edges, a.onEdgeSwitch)
	if !a.hasReannounce() {
		return
	}
	a.wsClient.SetOnConnect(func() {
		a.log.Info("agent: connexion à la passerelle — réannonce de toutes les sources")
		a.reannounceSources(context.Background())
	})
}

// handleWSCommand traite les commandes passerelle → Agent reçues via WebSocket.
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
			Action string          `json:"action"`
			Patch  json.RawMessage `json:"patch"`
		}
		if json.Unmarshal(payload, &cmd) != nil {
			break
		}
		switch cmd.Action {
		case "rescan":
			triggerRescan()
		case "configure":
			if a.internalAPI.cfgPath == "" {
				a.log.Warn("agent: configure WS ignoré — cfgPath non configuré")
				break
			}
			if err := applyConfigPatch(a.internalAPI.cfgPath, cmd.Patch); err != nil {
				a.log.Error("agent: configure WS échoué", "err", err)
				break
			}
			a.log.Info("agent: configure WS appliqué — redémarrage")
			go func() {
				p, err := os.FindProcess(os.Getpid())
				if err == nil {
					_ = p.Signal(syscall.SIGTERM)
				}
			}()
		}
	case edgews.TypeShellOpen, edgews.TypeShellData, edgews.TypeShellClose:
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
		"edge", a.cfg.ControlPlane.EdgeEndpoint,
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
	internalEndpoint := fmt.Sprintf("http://%s:%d", externalIP(a.cfg.ControlPlane.EdgeEndpoint), a.cfg.InternalAPI.Port)
	a.setInternalAuth(a.cfg.ControlPlane.AuthToken)
	a.internalAPI.Start(ctx)

	// Amorçage via GPX_AGENT_TOKEN : toujours écrire le token (permet la rotation sans vider le volume).
	if prebuilt := os.Getenv("GPX_AGENT_TOKEN"); prebuilt != "" {
		if wErr := os.WriteFile(agentTokenPath, []byte(strings.TrimSpace(prebuilt)), 0600); wErr == nil {
			a.log.Info("agent: token pré-configuré écrit (GPX_AGENT_TOKEN)", "path", agentTokenPath)
		}
	}

	// Résolution du token : config → fichier local → appairage passerelle → appairage Admin
	token := a.resolveAuthToken()
	if token == "" {
		var err error
		token, err = a.pair(ctx)
		if err != nil {
			a.log.Warn("agent: appairage impossible — retry en arrière-plan (backoff 5 s → 60 s)", "err", err)
			go a.retryPairing(ctx)
		}
	}
	if token != "" {
		a.setInternalAuth(token)
	}

	// Détection des runtimes actifs
	runtimes := a.detectedRuntimes()

	// Propager le token résolu à la discovery et aux autres composants
	// qui ont été construits avant le pairing (dans New()).
	if token != "" {
		a.setSourcesToken(token)
	}

	// Client WS persistant Agent→Passerelle
	// Priorité : HMAC persisté > JOIN_TOKEN explicite > token frais pairWithEdge
	savedHMAC := wsclient.LoadPersistedHMAC()
	joinToken := a.cfg.ControlPlane.JoinToken
	if joinToken == "" && savedHMAC == "" {
		// Les join tokens sont à usage unique dans le joinStore de la passerelle.
		// Un token persisté dans agent.token a peut-être déjà été consommé lors d'un
		// démarrage précédent sans que l'Agent ait jamais été approuvé. On rappelle
		// toujours pairWithEdge pour obtenir un token frais garanti non-consommé.
		if freshToken, err := a.pairWithEdge(ctx); err == nil {
			joinToken = freshToken
		} else {
			joinToken = token // fallback : token existant si pairWithEdge échoue
		}
	}
	if savedHMAC != "" || joinToken != "" {
		a.wsClient = wsclient.NewClient(
			a.cfg.Identity.NodeName,
			a.cfg.Identity.NodeName,
			buildinfo.Agent,
			a.cfg.ControlPlane.EdgeEndpoint,
			joinToken,
			savedHMAC,
			a.handleWSCommand,
			a.log,
		)
		a.reannounceOnConnect()
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

	// Événements cycle de vie / santé → passerelle (WS prioritaire, HTTP fallback)
	if a.discovery != nil {
		a.discovery.SetOnLifecycle(func(containerID, containerName, action string) {
			go a.emitEvent(containerID, action, "container="+containerName)
		})
	}
	a.lifecycle.SetOnEscalation(func(containerID, containerName, eventType, detail string) {
		go a.emitEvent(containerID, eventType, detail)
	})

	// Canal de mise à jour du token pour retryPairing → heartbeatLoop
	a.tokenUpdate = make(chan string, 1)

	// Heartbeat vers passerelle (WS si connecté, HTTP sinon)
	go heartbeatLoop(ctx,
		a.edges.Current,
		token,
		a.cfg.Identity.NodeName,
		buildinfo.Agent,
		internalEndpoint,
		runtimes,
		sanitizedAgentConfig(a.cfg),
		a.wsClient,
		a.tokenUpdate,
		func() string {
			t, err := a.pair(ctx)
			if err != nil {
				a.log.Warn("heartbeat: re-appairage impossible", "err", err)
				return ""
			}
			a.setSourcesToken(t)
			return t
		},
		a.log,
	)

	// Signal online pour l'historique UI (Événements agent)
	go a.emitEvent("", "agent_online", "version="+buildinfo.Agent)

	// Sources de découverte qui rendent la main après leur scan initial (Docker/Podman, socket local)
	a.startSources(ctx, false)

	// Métriques conteneur → passerelle (LB adaptatif)
	if a.wsClient != nil && a.dockerClient != nil {
		go metricsLoop(ctx, a.dockerClient, a.cfg.Identity.NodeName, a.wsClient, a.log)
	}

	// Sources qui bouclent jusqu'à l'arrêt (Portainer multi-hôtes, Kubernetes…) : une goroutine chacune
	a.startSources(ctx, true)

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

// emitEvent rapporte un événement à la passerelle (WS si actif, sinon HTTP).
func (a *Agent) emitEvent(containerID, eventType, detail string) {
	token := a.resolveAuthToken()
	if token == "" {
		token = a.cfg.ControlPlane.AuthToken
	}
	reportEvent(context.Background(),
		a.edges.Current(),
		token,
		a.cfg.Identity.NodeName,
		containerID,
		eventType,
		detail,
		a.wsClient,
		a.log,
	)
}

func maskIfSet(s string) string {
	if s == "" {
		return ""
	}
	return "••••••••"
}

// sanitizedAgentConfig retourne la config agent sans les secrets (api_key, auth_token, passwords).
// Utilisé pour le heartbeat : l'Admin pré-remplit le modal de configuration sans exposer les secrets.
func sanitizedAgentConfig(cfg *config.AgentConfig) map[string]any {
	epEdges := map[string]any{}
	for name, ec := range cfg.Portainer.EndpointEdges {
		epEdges[name] = map[string]any{
			"edge_endpoint": ec.EdgeEndpoint,
			"auth_token":    "••••••••",
		}
	}
	out := map[string]any{
		"control_plane": map[string]any{
			"edge_endpoint": cfg.ControlPlane.EdgeEndpoint,
		},
		"docker": map[string]any{
			"enabled":     cfg.Docker.Enabled || cfg.Docker.Runtime != "",
			"socket_path": cfg.Docker.SocketPath,
		},
		"portainer": map[string]any{
			"enabled":         cfg.Portainer.Enabled,
			"url":             cfg.Portainer.URL,
			"api_key":         maskIfSet(cfg.Portainer.APIKey),
			"poll_interval_s": cfg.Portainer.PollIntervalS,
			"skip_endpoints":  cfg.Portainer.SkipEndpoints,
			"endpoint_edges":  epEdges,
		},
	}
	// Sources déclarées par un manifeste (Kubernetes et sources ajoutées) : champs du manifeste,
	// secrets masqués. Docker et Portainer gardent la forme historique ci-dessus.
	if m, ok := agentsources.ManifestOf("kubernetes"); ok {
		out["kubernetes"] = agentsources.View(m, structToMap(cfg.Kubernetes))
	}
	if len(cfg.Sources) > 0 {
		extra := map[string]any{}
		for typ, settings := range cfg.Sources {
			if m, ok := agentsources.ManifestOf(typ); ok {
				extra[typ] = agentsources.View(m, settings)
			}
		}
		if len(extra) > 0 {
			out["sources"] = extra
		}
	}
	return out
}

// detectedRuntimes retourne la liste des runtimes de conteneurs actifs sur cet agent.
func (a *Agent) detectedRuntimes() []string {
	var runtimes []string
	for _, s := range a.sources {
		runtimes = append(runtimes, s.Runtimes...)
	}
	return runtimes
}

// setSourcesToken transmet le jeton d'agent (obtenu à l'appairage, après la construction) à chaque
// source qui en reçoit un.
func (a *Agent) setSourcesToken(token string) {
	for _, s := range a.sources {
		if s.SetToken != nil {
			s.SetToken(token)
		}
	}
}

// startSources démarre les sources dont Blocking vaut blocking : celles qui bouclent
// jusqu'à l'arrêt dans leur propre goroutine, les autres en rendant la main.
func (a *Agent) startSources(ctx context.Context, blocking bool) {
	for _, s := range a.sources {
		if s.Blocking != blocking || s.Start == nil {
			continue
		}
		if blocking {
			go s.Start(ctx)
		} else {
			s.Start(ctx)
		}
	}
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

// structToMap lit une section de configuration (champs étiquetés mapstructure) sous la forme
// clé de agent.json → valeur, pour la confronter au manifeste d'une source.
func structToMap(v any) map[string]any {
	rv := reflect.ValueOf(v)
	rt := rv.Type()
	out := make(map[string]any, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		if tag := rt.Field(i).Tag.Get("mapstructure"); tag != "" && tag != "-" {
			out[tag] = rv.Field(i).Interface()
		}
	}
	return out
}
