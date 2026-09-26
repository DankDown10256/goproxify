// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package k8s fournit la découverte de services Kubernetes pour l'Agent Goproxify.
// Il surveille les Services et Ingress annotés et les enregistre comme routes proxy.
package k8s

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/agent/docker"
	"github.com/vincamok/goproxify/internal/config"
)

const (
	inClusterAPIServer = "https://kubernetes.default.svc"
	inClusterTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	inClusterCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// Discovery surveille les Services et Ingress Kubernetes portant le label
// goproxify.enabled=true et pousse les routes correspondantes vers la passerelle.
type Discovery struct {
	cfg         *config.AgentConfig
	adminURL    string
	authToken   string
	labelPrefix string
	log         *slog.Logger
	client      *http.Client
	apiServer   string
	k8sToken    string

	// hostByKey mappe "namespace/name" → host courant pour permettre la suppression.
	mu        sync.Mutex
	hostByKey map[string]string
}

// New crée une Discovery K8s. Retourne une erreur si la configuration est invalide.
func New(cfg *config.AgentConfig, log *slog.Logger) (*Discovery, error) {
	d := &Discovery{
		cfg:         cfg,
		adminURL:    cfg.ControlPlane.EdgeEndpoint,
		authToken:   cfg.ControlPlane.AuthToken,
		labelPrefix: cfg.Kubernetes.LabelPrefix,
		log:         log,
		hostByKey:   make(map[string]string),
	}
	if d.labelPrefix == "" {
		d.labelPrefix = cfg.Docker.LabelPrefix
	}
	if d.labelPrefix == "" {
		d.labelPrefix = "goproxify."
	}

	apiServer := cfg.Kubernetes.APIServer
	token := cfg.Kubernetes.Token
	caData := cfg.Kubernetes.CACert

	// In-cluster autodetect
	if apiServer == "" {
		apiServer = inClusterAPIServer
		if b, err := os.ReadFile(inClusterTokenFile); err == nil {
			token = strings.TrimSpace(string(b))
		}
		if caData == "" {
			caData = inClusterCAFile
		}
	}

	d.apiServer = apiServer
	d.k8sToken = token

	tlsCfg := &tls.Config{}
	if caData != "" {
		var caBytes []byte
		if _, err := os.Stat(caData); err == nil {
			caBytes, _ = os.ReadFile(caData)
		} else {
			caBytes = []byte(caData)
		}
		if len(caBytes) > 0 {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(caBytes)
			tlsCfg.RootCAs = pool
		}
	}
	d.client = &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   10 * time.Second,
	}
	return d, nil
}

// Start lance la boucle de surveillance et bloque jusqu'à ctx.Done().
func (d *Discovery) Start(ctx context.Context) {
	d.log.Info("k8s discovery: démarrage", "api_server", d.apiServer)
	for {
		if err := d.watchAll(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			d.log.Warn("k8s discovery: watch interrompu, retry dans 15s", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(15 * time.Second):
			}
		}
	}
}

// --- Types K8s minimaux -------------------------------------------------------

type k8sServiceList struct {
	Items []k8sService `json:"items"`
}

type k8sService struct {
	Metadata k8sMeta `json:"metadata"`
	Spec     struct {
		ClusterIP string    `json:"clusterIP"`
		Ports     []k8sPort `json:"ports"`
	} `json:"spec"`
}

type k8sPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type k8sMeta struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Annotations map[string]string `json:"annotations"`
	Labels      map[string]string `json:"labels"`
}

type k8sWatchEvent struct {
	Type   string          `json:"type"` // ADDED | MODIFIED | DELETED
	Object json.RawMessage `json:"object"`
}

// k8sIngress représente un Ingress Kubernetes minimal.
type k8sIngress struct {
	Metadata k8sMeta    `json:"metadata"`
	Spec     ingressSpec `json:"spec"`
}

type ingressSpec struct {
	Rules []ingressRule `json:"rules"`
	TLS   []ingressTLS  `json:"tls"`
}

type ingressRule struct {
	Host string      `json:"host"`
	HTTP *httpPaths  `json:"http"`
}

type httpPaths struct {
	Paths []ingressPath `json:"paths"`
}

type ingressPath struct {
	Path    string         `json:"path"`
	Backend ingressBackend `json:"backend"`
}

type ingressBackend struct {
	Service *ingressService `json:"service"`
}

type ingressService struct {
	Name string         `json:"name"`
	Port ingressSvcPort `json:"port"`
}

type ingressSvcPort struct {
	Number int `json:"number"`
}

type ingressTLS struct {
	Hosts []string `json:"hosts"`
}

// watchAll surveille Services et Ingress en parallèle.
// Si l'un des watchers se termine (erreur ou ctx annulé), l'autre est annulé aussi.
func (d *Discovery) watchAll(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 2)
	go func() { errCh <- d.watchServices(ctx) }()
	go func() { errCh <- d.watchIngresses(ctx) }()

	// La première erreur annule l'autre goroutine via cancel().
	err := <-errCh
	return err
}

// watchServices utilise le watch API K8s pour maintenir la liste à jour.
func (d *Discovery) watchServices(ctx context.Context) error {
	ns := d.cfg.Kubernetes.Namespace
	path := "/api/v1/services?watch=1&labelSelector=" +
		labelSelectorEscape(d.labelPrefix+"enabled=true")
	if ns != "" {
		path = "/api/v1/namespaces/" + ns + "/services?watch=1&labelSelector=" +
			labelSelectorEscape(d.labelPrefix+"enabled=true")
	}
	return d.watchStream(ctx, path, func(ev k8sWatchEvent) {
		var svc k8sService
		if err := json.Unmarshal(ev.Object, &svc); err != nil {
			return
		}
		switch ev.Type {
		case "ADDED", "MODIFIED":
			d.upsertService(ctx, svc)
		case "DELETED":
			d.deleteByKey(ctx, svcKey(svc.Metadata))
		}
	})
}

// watchIngresses surveille les Ingress annotés goproxify.enabled=true.
func (d *Discovery) watchIngresses(ctx context.Context) error {
	ns := d.cfg.Kubernetes.Namespace
	path := "/apis/networking.k8s.io/v1/ingresses?watch=1&labelSelector=" +
		labelSelectorEscape(d.labelPrefix+"enabled=true")
	if ns != "" {
		path = "/apis/networking.k8s.io/v1/namespaces/" + ns + "/ingresses?watch=1&labelSelector=" +
			labelSelectorEscape(d.labelPrefix+"enabled=true")
	}
	return d.watchStream(ctx, path, func(ev k8sWatchEvent) {
		var ing k8sIngress
		if err := json.Unmarshal(ev.Object, &ing); err != nil {
			return
		}
		switch ev.Type {
		case "ADDED", "MODIFIED":
			d.upsertIngress(ctx, ing)
		case "DELETED":
			d.deleteByKey(ctx, ingKey(ing.Metadata))
		}
	})
}

// watchStream ouvre un watch stream K8s et appelle fn pour chaque événement.
func (d *Discovery) watchStream(ctx context.Context, path string, fn func(k8sWatchEvent)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.apiServer+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.k8sToken)

	watchClient := &http.Client{Transport: d.client.Transport}
	resp, err := watchClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("k8s watch %s: %d %s", path, resp.StatusCode, b)
	}

	dec := json.NewDecoder(resp.Body)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		var ev k8sWatchEvent
		if err := dec.Decode(&ev); err != nil {
			return err
		}
		fn(ev)
	}
}

// upsertService traduit un Service K8s en route proxy et la pousse à la passerelle.
func (d *Discovery) upsertService(ctx context.Context, svc k8sService) {
	ann := svc.Metadata.Annotations
	if ann == nil {
		ann = map[string]string{}
	}
	p := d.labelPrefix

	host := ann[p+"host"]
	if host == "" {
		host = ann[p+"domain"]
	}
	if host == "" {
		return
	}

	backendPort := 80
	if len(svc.Spec.Ports) > 0 {
		backendPort = svc.Spec.Ports[0].Port
	}
	if ann[p+"port"] != "" {
		fmt.Sscanf(ann[p+"port"], "%d", &backendPort)
	}
	backendURL := fmt.Sprintf("http://%s:%d", svc.Spec.ClusterIP, backendPort)
	if ann[p+"backend"] != "" {
		backendURL = ann[p+"backend"]
	}

	d.pushRoute(ctx, svcKey(svc.Metadata), ann, host, backendURL, ann[p+"tls"] == "true")
}

// upsertIngress traduit un Ingress K8s en routes proxy et les pousse à la passerelle.
func (d *Discovery) upsertIngress(ctx context.Context, ing k8sIngress) {
	ann := ing.Metadata.Annotations
	if ann == nil {
		ann = map[string]string{}
	}
	p := d.labelPrefix

	// Ensemble des hosts TLS déclarés dans spec.tls[].hosts
	tlsHosts := map[string]bool{}
	for _, t := range ing.Spec.TLS {
		for _, h := range t.Hosts {
			tlsHosts[h] = true
		}
	}

	// Override TLS global via annotation
	tlsForced := ann[p+"tls"] == "true"

	for _, rule := range ing.Spec.Rules {
		host := rule.Host
		if host == "" {
			continue
		}
		tls := tlsForced || tlsHosts[host]

		// Backend : annotation > première règle HTTP
		backendURL := ann[p+"backend"]
		if backendURL == "" && rule.HTTP != nil && len(rule.HTTP.Paths) > 0 {
			svcName := ""
			svcPort := 80
			if be := rule.HTTP.Paths[0].Backend.Service; be != nil {
				svcName = be.Name
				if be.Port.Number > 0 {
					svcPort = be.Port.Number
				}
			}
			if svcName != "" {
				ns := ing.Metadata.Namespace
				if ns == "" {
					ns = "default"
				}
				backendURL = fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", svcName, ns, svcPort)
			}
		}
		if backendURL == "" {
			continue
		}

		d.pushRoute(ctx, ingKey(ing.Metadata)+":"+host, ann, host, backendURL, tls)
	}
}

// routePayload construit le payload Agent→Passerelle d'une route. Les annotations suivent exactement la
// sémantique des labels Docker (waf, rate_limit, jwt, mtls, backpressure…) : elles passent par le même
// parseur, préfixe configurable normalisé vers "goproxify.". Retourne nil si l'hôte est invalide.
func (d *Discovery) routePayload(key string, ann map[string]string, host, backendURL string, tls bool) (map[string]any, *docker.ProxySpec) {
	labels := make(map[string]string, len(ann)+4)
	for k, v := range ann {
		if rest, ok := strings.CutPrefix(k, d.labelPrefix); ok {
			labels["goproxify."+rest] = v
		}
	}
	// Les valeurs déduites de la ressource K8s l'emportent sur les annotations.
	labels[docker.LabelEnable] = "true"
	labels[docker.LabelHost] = host
	labels[docker.LabelBackendURL] = backendURL
	if tls {
		labels[docker.LabelTLS] = "true"
	}
	spec := docker.ParseLabels("k8s:"+key, key, "", "", labels, nil, "")
	if spec == nil {
		return nil, nil
	}
	payload := map[string]any{
		"host":         spec.Host,
		"aliases":      spec.Aliases,
		"paths":        spec.Paths,
		"route_type":   spec.Type,
		"backends":     []string{backendURL},
		"tls_enabled":  spec.TLS,
		"passthrough":  spec.Passthrough,
		"source":       "k8s",
		"container_id": "k8s:" + key,
		"agent_name":   d.cfg.Identity.NodeName,
		"role":         spec.Role,
	}
	if spec.Role == docker.RoleCanary {
		payload["canary_weight"] = spec.CanaryWeight
	}
	docker.AttachSecurityPayload(payload, spec)
	return payload, spec
}

// pushRoute envoie un payload agentContainerPayload compatible à la passerelle.
func (d *Discovery) pushRoute(ctx context.Context, key string, ann map[string]string, host, backendURL string, tls bool) {
	payload, spec := d.routePayload(key, ann, host, backendURL, tls)
	if payload == nil {
		d.log.Warn("k8s discovery: hôte invalide, route ignorée", "host", host, "key", key)
		return
	}
	d.mu.Lock()
	d.hostByKey[key] = spec.Host
	d.mu.Unlock()
	host = spec.Host
	tls = spec.TLS
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		d.adminURL+"/internal/v1/agent/containers", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+d.authToken)
	resp, err := d.client.Do(req)
	if err != nil {
		d.log.Warn("k8s discovery: push route", "host", host, "err", err)
		return
	}
	resp.Body.Close()
	d.log.Info("k8s discovery: route enregistrée", "host", host, "backend", backendURL, "tls", tls)
}

// deleteByKey supprime la route associée à une clé namespace/name.
func (d *Discovery) deleteByKey(ctx context.Context, key string) {
	d.mu.Lock()
	host := d.hostByKey[key]
	delete(d.hostByKey, key)
	// Supprimer aussi les sous-clés Ingress (key + ":" + host)
	for k := range d.hostByKey {
		if strings.HasPrefix(k, key+":") {
			if h := d.hostByKey[k]; h != "" && host == "" {
				host = h
			}
			delete(d.hostByKey, k)
		}
	}
	d.mu.Unlock()

	if host == "" {
		return
	}
	// La passerelle génère l'ID de route "docker-host:{host}" via handleAgentContainerStart.
	routeID := "docker-host:" + host
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		d.adminURL+"/internal/v1/routes/"+url.PathEscape(routeID), nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+d.authToken)
	resp, err := d.client.Do(req)
	if err != nil {
		d.log.Warn("k8s discovery: suppression route", "host", host, "err", err)
		return
	}
	resp.Body.Close()
	d.log.Info("k8s discovery: route supprimée", "host", host)
}

func svcKey(m k8sMeta) string {
	return m.Namespace + "/" + m.Name
}

func ingKey(m k8sMeta) string {
	return "ing:" + m.Namespace + "/" + m.Name
}

func labelSelectorEscape(s string) string {
	return strings.ReplaceAll(s, " ", "%20")
}
