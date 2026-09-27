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

// TeamsSender envoie une notification via un webhook entrant Microsoft Teams
// (connecteur "Incoming Webhook" ou flux Power Automate).
type TeamsSender struct {
	WebhookURL string
}

func (s *TeamsSender) Send(ctx context.Context, msg Message) error {
	if err := ssrf.ValidateHTTPURL(s.WebhookURL, ssrf.AllowPrivateEnv("GPX_WEBHOOK_ALLOW_PRIVATE")); err != nil {
		return fmt.Errorf("teams: URL refusée: %w", err)
	}
	body := map[string]any{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": severityColor(msg.Severity),
		"summary":    msg.Title,
		"sections": []map[string]any{{
			"activityTitle": msg.Title,
			"text":          msg.Body,
			"facts": []map[string]string{
				{"name": "Règle", "value": msg.RuleName},
				{"name": "Déclencheur", "value": string(msg.Trigger)},
				{"name": "Sévérité", "value": string(msg.Severity)},
			},
		}},
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
		return fmt.Errorf("teams: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("teams: statut HTTP %d", resp.StatusCode)
	}
	return nil
}
