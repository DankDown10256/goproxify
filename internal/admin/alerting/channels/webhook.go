// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/vincamok/goproxify/internal/ssrf"
)

// WebhookSender envoie une notification JSON vers une URL arbitraire.
// Compatible Slack (incoming webhook), Discord, Teams, n8n, etc.
type WebhookSender struct {
	URL    string
	Secret string // HMAC-SHA256 sur le corps si non vide (header X-Goproxify-Signature)
}

func (s *WebhookSender) Send(ctx context.Context, msg Message) error {
	if err := ssrf.ValidateHTTPURL(s.URL, ssrf.AllowPrivateEnv("GPX_WEBHOOK_ALLOW_PRIVATE")); err != nil {
		return fmt.Errorf("webhook: URL refusée: %w", err)
	}
	payload := map[string]any{
		"rule":      msg.RuleName,
		"trigger":   string(msg.Trigger),
		"severity":  string(msg.Severity),
		"title":     msg.Title,
		"body":      msg.Body,
		"detail":    msg.Detail,
		"fired_at":  msg.FiredAt.Format(time.RFC3339),
	}

	// Enveloppe Slack-compatible si le corps contient "text"
	slackBody := map[string]any{
		"text": fmt.Sprintf("*[%s]* %s\n%s", msg.Severity, msg.Title, msg.Body),
		"attachments": []map[string]any{{
			"color": severityColor(msg.Severity),
			"fields": []map[string]any{
				{"title": "Déclencheur", "value": string(msg.Trigger), "short": true},
				{"title": "Sévérité", "value": string(msg.Severity), "short": true},
			},
		}},
		"_goproxify": payload,
	}

	b, err := json.Marshal(slackBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.Secret != "" {
		mac := hmac.New(sha256.New, []byte(s.Secret))
		mac.Write(b)
		req.Header.Set("X-Goproxify-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook: statut HTTP %d", resp.StatusCode)
	}
	return nil
}

func severityColor(s string) string {
	switch s {
	case "critical":
		return "#ef4444"
	case "warning":
		return "#f59e0b"
	default:
		return "#6366f1"
	}
}
