// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package channels implémente les adaptateurs de notification pour chaque canal.
// Il ne doit pas importer le package parent alerting pour éviter les cycles.
package channels

import (
	"context"
	"fmt"
	"time"
)

// Message est le payload envoyé à un canal de notification.
// Les champs Trigger et Severity sont des chaînes brutes pour éviter le cycle d'import.
type Message struct {
	RuleName string
	Trigger  string
	Severity string
	Title    string
	Body     string
	Detail   map[string]any
	FiredAt  time.Time
}

// Channel décrit un canal de notification stocké en DB.
type Channel struct {
	ID      string
	Name    string
	Type    string
	Config  map[string]any
	Enabled bool
}

// Sender envoie un message via un canal spécifique.
type Sender interface {
	Send(ctx context.Context, msg Message) error
}

// Build instancie le bon Sender selon le type de canal.
func Build(ch Channel) (Sender, error) {
	cfg := ch.Config
	switch ch.Type {
	case "email":
		return &EmailSender{
			Host:     str(cfg, "host"),
			Port:     intv(cfg, "port", 587),
			Username: str(cfg, "username"),
			Password: str(cfg, "password"),
			From:     str(cfg, "from"),
			To:       strSlice(cfg, "to"),
		}, nil
	case "webhook":
		return &WebhookSender{URL: str(cfg, "url"), Secret: str(cfg, "secret")}, nil
	case "ntfy":
		return &NtfySender{URL: str(cfg, "url"), Topic: str(cfg, "topic"), Token: str(cfg, "token")}, nil
	case "gotify":
		return &GotifySender{URL: str(cfg, "url"), Token: str(cfg, "token")}, nil
	case "jira":
		return &JiraSender{
			URL: str(cfg, "url"), Username: str(cfg, "username"), Token: str(cfg, "token"),
			Project: str(cfg, "project"), IssueType: str(cfg, "issue_type"),
		}, nil
	case "linear":
		return &LinearSender{APIKey: str(cfg, "api_key"), TeamID: str(cfg, "team_id")}, nil
	case "github":
		return &GitHubSender{Token: str(cfg, "token"), Owner: str(cfg, "owner"), Repo: str(cfg, "repo")}, nil
	case "gitlab":
		return &GitLabSender{URL: str(cfg, "url"), Token: str(cfg, "token"), ProjectID: str(cfg, "project_id")}, nil
	case "zammad":
		return &ZammadSender{URL: str(cfg, "url"), Token: str(cfg, "token"), GroupID: str(cfg, "group_id")}, nil
	case "glpi":
		return &GLPISender{URL: str(cfg, "url"), AppToken: str(cfg, "app_token"), UserToken: str(cfg, "user_token")}, nil
	default:
		return nil, fmt.Errorf("type de canal inconnu : %q", ch.Type)
	}
}

func str(cfg map[string]any, k string) string {
	if v, ok := cfg[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func intv(cfg map[string]any, k string, def int) int {
	if v, ok := cfg[k]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case int:
			return n
		}
	}
	return def
}

func strSlice(cfg map[string]any, k string) []string {
	v, ok := cfg[k]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return t
	case []any:
		out := make([]string, 0, len(t))
		for _, s := range t {
			if sv, ok := s.(string); ok {
				out = append(out, sv)
			}
		}
		return out
	}
	return nil
}
