// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package k8s fournit la découverte de services Kubernetes pour l'Agent Goproxify.
// Il surveille les Pods/Services annotés et les enregistre comme routes proxy.
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
	"os"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/config"
)

const (
	inClusterAPIServer = "https://kubernetes.default.svc"
	inClusterTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	inClusterCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// Discovery surveille les Services Kubernetes portant le label goproxify.enabled=true
// et pousse les routes correspondantes vers l'Administration.
type Discovery struct {
	cfg         *config.AgentConfig
	adminURL    string
	authToken   string
	labelPrefix string
	log         *slog.Logger
	client      *http.Client
	apiServer   string
	k8sToken    string
}

// New crée une Discovery K8s. Retourne une erreur si la configuration est invalide.
func New(cfg *config.AgentConfig, log *slog.Logger) (*Discovery, error) {
	d := &Discovery{
		cfg:         cfg,
		adminURL:    cfg.ControlPlane.CoreEndpoint,
		authToken:   cfg.ControlPlane.AuthToken,
		labelPrefix: cfg.Kubernetes.LabelPrefix,
		log:         log,
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
		// Chemin fichier ou PEM inline
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
		if err := d.watchServices(ctx); err != nil {
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
		ClusterIP string      `json:"clusterIP"`
		Ports     []k8sPort   `json:"ports"`
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

// watchServices utilise le watch API K8s pour maintenir la liste à jour.
func (d *Discovery) watchServices(ctx context.Context) error {
	ns := d.cfg.Kubernetes.Namespace
	path := "/api/v1/services?watch=1&labelSelector=" +
		labelSelectorEscape(d.labelPrefix+"enabled=true")
	if ns != "" {
		path = "/api/v1/namespaces/" + ns + "/services?watch=1&labelSelector=" +
			labelSelectorEscape(d.labelPrefix+"enabled=true")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.apiServer+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.k8sToken)

	// Pas de timeout global pour le watch stream
	watchClient := &http.Client{Transport: d.client.Transport}
	resp, err := watchClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("k8s watch: %d %s", resp.StatusCode, b)
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
		var svc k8sService
		if err := json.Unmarshal(ev.Object, &svc); err != nil {
			continue
		}
		switch ev.Type {
		case "ADDED", "MODIFIED":
			d.upsertRoute(ctx, svc)
		case "DELETED":
			d.deleteRoute(ctx, svc)
		}
	}
}

// upsertRoute traduit un Service K8s en route proxy et la pousse à l'Admin.
func (d *Discovery) upsertRoute(ctx context.Context, svc k8sService) {
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
		// Pas d'hôte configuré → skip
		return
	}

	// Backend : ClusterIP + premier port
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

	route := map[string]any{
		"host":     host,
		"type":     "http",
		"backends": []map[string]any{{"url": backendURL, "weight": 1}},
		"lb":       "round_robin",
		"tls_enabled": ann[p+"tls"] == "true",
	}
	if svc.Metadata.Namespace != "" {
		route["_k8s_namespace"] = svc.Metadata.Namespace
		route["_k8s_name"] = svc.Metadata.Name
	}

	d.pushToAdmin(ctx, "POST", "/internal/v1/containers", map[string]any{
		"source":    "k8s",
		"namespace": svc.Metadata.Namespace,
		"name":      svc.Metadata.Name,
		"host":      host,
		"backend":   backendURL,
		"tls":       ann[p+"tls"] == "true",
		"labels":    ann,
		"route":     route,
	})
}

func (d *Discovery) deleteRoute(ctx context.Context, svc k8sService) {
	d.pushToAdmin(ctx, "DELETE", "/internal/v1/containers", map[string]any{
		"source":    "k8s",
		"namespace": svc.Metadata.Namespace,
		"name":      svc.Metadata.Name,
	})
}

func (d *Discovery) pushToAdmin(ctx context.Context, method, path string, payload any) {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, method,
		d.adminURL+path, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+d.authToken)
	resp, err := d.client.Do(req)
	if err != nil {
		d.log.Warn("k8s discovery: push admin", "err", err)
		return
	}
	resp.Body.Close()
}

func labelSelectorEscape(s string) string {
	return strings.ReplaceAll(s, " ", "%20")
}
