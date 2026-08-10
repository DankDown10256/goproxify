// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// DigestWatcher surveille les nouvelles versions d'images Docker et déclenche les mises à jour.
type DigestWatcher struct {
	dockerClient *Client
	lifecycle    *LifecycleManager
	log          *slog.Logger
	// onUpdate est appelé quand une nouvelle version est détectée (containerID, image)
	onUpdate func(containerID, image string)
}

// NewDigestWatcher crée un DigestWatcher.
func NewDigestWatcher(client *Client, lifecycle *LifecycleManager, log *slog.Logger, onUpdate func(string, string)) *DigestWatcher {
	return &DigestWatcher{
		dockerClient: client,
		lifecycle:    lifecycle,
		log:          log,
		onUpdate:     onUpdate,
	}
}

// Start lance la boucle de vérification à intervalles réguliers.
func (w *DigestWatcher) Start(ctx context.Context, intervalS int) {
	if intervalS <= 0 {
		intervalS = 3600
	}
	go func() {
		w.checkAll(ctx)
		ticker := time.NewTicker(time.Duration(intervalS) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				w.checkAll(ctx)
			}
		}
	}()
}

// checkAll parcourt tous les conteneurs goproxify et vérifie les digests.
func (w *DigestWatcher) checkAll(ctx context.Context) {
	var containers []ContainerSummary
	if err := w.dockerClient.Get(ctx, "/containers/json?all=false", &containers); err != nil {
		return
	}
	for _, c := range containers {
		if !boolLabel(c.Labels, LabelEnable) {
			continue
		}
		if !boolLabel(c.Labels, LabelUpdateAuto) {
			continue
		}
		w.checkContainer(ctx, c.ID, c.Image)
	}
}

// checkContainer compare le digest local à celui du registre.
func (w *DigestWatcher) checkContainer(ctx context.Context, containerID, image string) {
	localDigest, err := w.localDigest(ctx, image)
	if err != nil {
		return
	}
	remoteDigest, err := fetchRemoteDigest(ctx, image)
	if err != nil {
		w.log.Debug("digest: impossible de vérifier le registre", "image", image, "err", err)
		return
	}
	if localDigest == remoteDigest || remoteDigest == "" {
		return
	}
	w.log.Info("digest: nouvelle version détectée", "image", image,
		"local", shortDigest(localDigest), "remote", shortDigest(remoteDigest))
	if w.onUpdate != nil {
		w.onUpdate(containerID, image)
	}
}

// localDigest retourne le digest de l'image locale via l'API Docker.
func (w *DigestWatcher) localDigest(ctx context.Context, image string) (string, error) {
	var info struct {
		RepoDigests []string `json:"RepoDigests"`
	}
	name := strings.ReplaceAll(image, "/", "%2F")
	name = strings.ReplaceAll(name, ":", "%3A")
	if err := w.dockerClient.Get(ctx, "/images/"+name+"/json", &info); err != nil {
		return "", err
	}
	if len(info.RepoDigests) == 0 {
		return "", fmt.Errorf("pas de digest local")
	}
	// format: image@sha256:abcdef...
	parts := strings.SplitN(info.RepoDigests[0], "@", 2)
	if len(parts) == 2 {
		return parts[1], nil
	}
	return info.RepoDigests[0], nil
}

// fetchRemoteDigest interroge le registre Docker pour obtenir le digest de l'image.
// Supporte Docker Hub (image officielle et user/image) et les registres privés.
func fetchRemoteDigest(ctx context.Context, image string) (string, error) {
	ref := parseImageRef(image)
	url := fmt.Sprintf("https://%s/v2/%s/manifests/%s", ref.registry, ref.name, ref.tag)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Certains registres nécessitent auth — on ignore silencieusement les 401/403
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		// Tentative avec token anonyme Docker Hub
		token, err := dockerHubToken(ctx, ref.name)
		if err != nil {
			return "", nil
		}
		req2, _ := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
		req2.Header.Set("Accept", "application/vnd.docker.distribution.manifest.v2+json")
		req2.Header.Set("Authorization", "Bearer "+token)
		resp2, err := client.Do(req2)
		if err != nil {
			return "", nil
		}
		defer resp2.Body.Close()
		return resp2.Header.Get("Docker-Content-Digest"), nil
	}
	if resp.StatusCode != http.StatusOK {
		return "", nil
	}
	return resp.Header.Get("Docker-Content-Digest"), nil
}

func dockerHubToken(ctx context.Context, name string) (string, error) {
	// name peut être "library/nginx" ou "user/image"
	scope := "repository:" + name + ":pull"
	url := "https://auth.docker.io/token?service=registry.docker.io&scope=" + scope
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var t struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(b, &t); err != nil {
		return "", err
	}
	return t.Token, nil
}

type imageRef struct {
	registry string
	name     string
	tag      string
}

func parseImageRef(image string) imageRef {
	ref := imageRef{registry: "registry-1.docker.io", tag: "latest"}

	// Sépare le tag
	if idx := strings.LastIndex(image, ":"); idx > strings.LastIndex(image, "/") {
		ref.tag = image[idx+1:]
		image = image[:idx]
	}

	// Registre privé ?
	parts := strings.SplitN(image, "/", 2)
	if len(parts) == 2 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":")) {
		ref.registry = parts[0]
		ref.name = parts[1]
	} else {
		// Docker Hub
		if !strings.Contains(image, "/") {
			// image officielle (ex: nginx → library/nginx)
			ref.name = "library/" + image
		} else {
			ref.name = image
		}
	}
	return ref
}

func shortDigest(d string) string {
	if len(d) > 19 {
		return d[:19] + "..."
	}
	return d
}
