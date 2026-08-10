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

// LinearSender crée une issue Linear via l'API GraphQL.
type LinearSender struct {
	APIKey string
	TeamID string
}

func (s *LinearSender) Send(ctx context.Context, msg Message) error {
	query := `mutation CreateIssue($title:String!,$description:String!,$teamId:String!,$priority:Int!) {
		issueCreate(input:{title:$title,description:$description,teamId:$teamId,priority:$priority}) {
			success issue { id }
		}
	}`
	vars := map[string]any{
		"title":       msg.Title,
		"description": fmt.Sprintf("%s\n\nDéclencheur: %s | Sévérité: %s | Date: %s", msg.Body, msg.Trigger, msg.Severity, msg.FiredAt.Format(time.RFC3339)),
		"teamId":      s.TeamID,
		"priority":    linearPriority(msg.Severity),
	}
	payload := map[string]any{"query": query, "variables": vars}
	b, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.linear.app/graphql", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", s.APIKey)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("linear: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("linear: statut HTTP %d", resp.StatusCode)
	}
	return nil
}

func linearPriority(s string) int {
	switch s {
	case "critical":
		return 1
	case "warning":
		return 2
	default:
		return 3
	}
}
