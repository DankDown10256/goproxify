// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/vincamok/goproxify/internal/ssrf"
)

// SlackSender envoie une notification via un webhook entrant Slack
// (https://api.slack.com/messaging/webhooks).
type SlackSender struct {
	WebhookURL string
}

func (s *SlackSender) Send(ctx context.Context, msg Message) error {
	if err := ssrf.ValidateHTTPURL(s.WebhookURL, ssrf.AllowPrivateEnv("GPX_WEBHOOK_ALLOW_PRIVATE")); err != nil {
		return fmt.Errorf("slack: URL refusée: %w", err)
	}
	body := map[string]any{
		"text": fmt.Sprintf("*[%s]* %s", msg.Severity, msg.Title),
		"blocks": []map[string]any{
			{"type": "section", "text": map[string]string{"type": "mrkdwn", "text": fmt.Sprintf("*[%s] %s*\n%s", msg.Severity, msg.Title, msg.Body)}},
			{"type": "context", "elements": []map[string]string{{"type": "mrkdwn", "text": fmt.Sprintf("Règle : %s · Déclencheur : %s", msg.RuleName, string(msg.Trigger))}}},
		},
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.WebhookURL, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("slack: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("slack: statut HTTP %d", resp.StatusCode)
	}
	return nil
}
