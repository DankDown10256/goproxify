// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	
)

// ZammadSender crée un ticket Zammad via l'API REST.
type ZammadSender struct {
	URL     string
	Token   string
	GroupID string
}

func (s *ZammadSender) Send(ctx context.Context, msg Message) error {
	groupID := s.GroupID
	if groupID == "" {
		groupID = "1"
	}
	body := fmt.Sprintf("%s\n\nDéclencheur: %s\nSévérité: %s\nDate: %s",
		msg.Body, msg.Trigger, msg.Severity, msg.FiredAt.Format(time.RFC3339))
	payload := map[string]any{
		"title":   msg.Title,
		"group":   groupID,
		"article": map[string]any{"subject": msg.Title, "body": body, "type": "note"},
	}
	b, _ := json.Marshal(payload)
	url := strings.TrimRight(s.URL, "/") + "/api/v1/tickets"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Token token="+s.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("zammad: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("zammad: statut HTTP %d", resp.StatusCode)
	}
	return nil
}
