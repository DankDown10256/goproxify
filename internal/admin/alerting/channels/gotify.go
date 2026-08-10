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

// GotifySender envoie des notifications push via Gotify.
type GotifySender struct {
	URL   string
	Token string
}

func (s *GotifySender) Send(ctx context.Context, msg Message) error {
	url := strings.TrimRight(s.URL, "/") + "/message?token=" + s.Token
	payload := map[string]any{
		"title":    msg.Title,
		"message":  msg.Body,
		"priority": gotifyPriority(msg.Severity),
	}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("gotify: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("gotify: statut HTTP %d", resp.StatusCode)
	}
	return nil
}

func gotifyPriority(s string) int {
	switch s {
	case "critical":
		return 10
	case "warning":
		return 5
	default:
		return 1
	}
}
