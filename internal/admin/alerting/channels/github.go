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

	
)

// GitHubSender crée une issue GitHub via l'API REST.
type GitHubSender struct {
	Token string
	Owner string
	Repo  string
}

func (s *GitHubSender) Send(ctx context.Context, msg Message) error {
	labels := []string{"goproxify", "alert", string(msg.Severity)}
	body := fmt.Sprintf("%s\n\n**Déclencheur:** %s  \n**Sévérité:** %s  \n**Date:** %s",
		msg.Body, msg.Trigger, msg.Severity, msg.FiredAt.Format(time.RFC3339))
	payload := map[string]any{
		"title":  msg.Title,
		"body":   body,
		"labels": labels,
	}
	b, _ := json.Marshal(payload)
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues", s.Owner, s.Repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("github: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("github: statut HTTP %d", resp.StatusCode)
	}
	return nil
}
