// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	
)

// JiraSender crée une issue Jira via l'API REST v3.
type JiraSender struct {
	URL       string
	Username  string
	Token     string
	Project   string
	IssueType string
}

func (s *JiraSender) Send(ctx context.Context, msg Message) error {
	issueType := s.IssueType
	if issueType == "" {
		issueType = "Bug"
	}
	payload := map[string]any{
		"fields": map[string]any{
			"project":   map[string]string{"key": s.Project},
			"summary":   msg.Title,
			"issuetype": map[string]string{"name": issueType},
			"description": map[string]any{
				"type":    "doc",
				"version": 1,
				"content": []map[string]any{{
					"type": "paragraph",
					"content": []map[string]any{{
						"type": "text",
						"text": fmt.Sprintf("%s\n\nDéclencheur: %s\nSévérité: %s\nDate: %s",
							msg.Body, msg.Trigger, msg.Severity, msg.FiredAt.Format(time.RFC3339)),
					}},
				}},
			},
			"priority": map[string]string{"name": jiraPriority(msg.Severity)},
		},
	}
	b, _ := json.Marshal(payload)
	url := strings.TrimRight(s.URL, "/") + "/rest/api/3/issue"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(s.Username+":"+s.Token)))
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("jira: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("jira: statut HTTP %d", resp.StatusCode)
	}
	return nil
}

func jiraPriority(s string) string {
	switch s {
	case "critical":
		return "Highest"
	case "warning":
		return "High"
	default:
		return "Medium"
	}
}
