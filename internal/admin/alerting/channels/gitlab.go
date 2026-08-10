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

// GitLabSender crée une issue GitLab via l'API REST v4.
type GitLabSender struct {
	URL       string
	Token     string
	ProjectID string
}

func (s *GitLabSender) Send(ctx context.Context, msg Message) error {
	base := strings.TrimRight(s.URL, "/")
	if base == "" {
		base = "https://gitlab.com"
	}
	url := fmt.Sprintf("%s/api/v4/projects/%s/issues", base, s.ProjectID)
	desc := fmt.Sprintf("%s\n\nDéclencheur: %s\nSévérité: %s\nDate: %s",
		msg.Body, msg.Trigger, msg.Severity, msg.FiredAt.Format(time.RFC3339))
	payload := map[string]any{
		"title":       msg.Title,
		"description": desc,
		"labels":      "goproxify,alert," + string(msg.Severity),
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("PRIVATE-TOKEN", s.Token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("gitlab: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("gitlab: statut HTTP %d", resp.StatusCode)
	}
	return nil
}
