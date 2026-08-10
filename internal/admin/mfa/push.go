// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mfa

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// PushConfig est la configuration d'un canal push pour la 2FA.
type PushConfig struct {
	Provider string `json:"provider"` // ntfy | gotify
	URL      string `json:"url"`
	Topic    string `json:"topic"`    // ntfy seulement
	Token    string `json:"token"`
}

// SendPushMFA envoie une notification push demandant l'approbation de connexion.
func SendPushMFA(ctx context.Context, cfg PushConfig, code, userAgent, ip string) error {
	msg := fmt.Sprintf("Code de connexion : %s\n\nIP : %s\nNavigateur : %s\n\nCe code expire dans 5 minutes.",
		code, ip, userAgent)
	switch cfg.Provider {
	case "ntfy":
		return sendNtfyMFA(ctx, cfg, "Connexion Goproxify", msg)
	case "gotify":
		return sendGotifyMFA(ctx, cfg, "Connexion Goproxify", msg)
	default:
		return fmt.Errorf("push: provider inconnu %q", cfg.Provider)
	}
}

func sendNtfyMFA(ctx context.Context, cfg PushConfig, title, body string) error {
	base := strings.TrimRight(cfg.URL, "/")
	if base == "" {
		base = "https://ntfy.sh"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/"+cfg.Topic, bytes.NewBufferString(body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", title)
	req.Header.Set("Priority", "high")
	req.Header.Set("Tags", "lock")
	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("ntfy push: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy push: statut %d", resp.StatusCode)
	}
	return nil
}

func sendGotifyMFA(ctx context.Context, cfg PushConfig, title, body string) error {
	base := strings.TrimRight(cfg.URL, "/")
	payload := fmt.Sprintf(`{"title":%q,"message":%q,"priority":8}`, title, body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/message", bytes.NewBufferString(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gotify-Key", cfg.Token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("gotify push: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("gotify push: statut %d", resp.StatusCode)
	}
	return nil
}
