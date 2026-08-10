// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	
)

// NtfySender pousse des notifications via ntfy.sh (ou instance self-hosted).
type NtfySender struct {
	URL   string // ex: https://ntfy.sh
	Topic string
	Token string // optionnel — accès protégé
}

func (s *NtfySender) Send(ctx context.Context, msg Message) error {
	if s.Topic == "" {
		return fmt.Errorf("ntfy: topic vide")
	}
	base := strings.TrimRight(s.URL, "/")
	if base == "" {
		base = "https://ntfy.sh"
	}
	url := base + "/" + s.Topic

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBufferString(msg.Body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", msg.Title)
	req.Header.Set("Priority", ntfyPriority(msg.Severity))
	req.Header.Set("Tags", string(msg.Trigger))
	if s.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.Token)
	}

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("ntfy: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy: statut HTTP %d", resp.StatusCode)
	}
	return nil
}

func ntfyPriority(s string) string {
	switch s {
	case "critical":
		return "urgent"
	case "warning":
		return "high"
	default:
		return "default"
	}
}
