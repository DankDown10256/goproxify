// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	
)

// GLPISender crée un ticket GLPI via l'API REST.
type GLPISender struct {
	URL       string
	AppToken  string
	UserToken string
}

func (s *GLPISender) Send(ctx context.Context, msg Message) error {
	base := strings.TrimRight(s.URL, "/")

	// Initier une session GLPI
	sesReq, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/apirest.php/initSession", nil)
	if err != nil {
		return err
	}
	sesReq.Header.Set("App-Token", s.AppToken)
	sesReq.Header.Set("Authorization", "user_token "+s.UserToken)
	client := &http.Client{Timeout: 15 * time.Second}
	sesResp, err := client.Do(sesReq)
	if err != nil {
		return fmt.Errorf("glpi: init session : %w", err)
	}
	defer sesResp.Body.Close()
	var sesData struct {
		SessionToken string `json:"session_token"`
	}
	if err := json.NewDecoder(sesResp.Body).Decode(&sesData); err != nil || sesData.SessionToken == "" {
		return fmt.Errorf("glpi: token de session invalide")
	}

	// Créer le ticket
	content := fmt.Sprintf("%s\n\nDéclencheur: %s\nSévérité: %s\nDate: %s",
		msg.Body, msg.Trigger, msg.Severity, msg.FiredAt.Format(time.RFC3339))
	payload := map[string]any{
		"input": map[string]any{
			"name":    msg.Title,
			"content": content,
			"urgency": glpiUrgency(msg.Severity),
			"type":    1, // Incident
		},
	}
	b, _ := json.Marshal(payload)
	tickReq, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/apirest.php/Ticket", bytes.NewReader(b))
	if err != nil {
		return err
	}
	tickReq.Header.Set("App-Token", s.AppToken)
	tickReq.Header.Set("Session-Token", sesData.SessionToken)
	tickReq.Header.Set("Content-Type", "application/json")
	tickResp, err := client.Do(tickReq)
	if err != nil {
		return fmt.Errorf("glpi: création ticket : %w", err)
	}
	io.Copy(io.Discard, tickResp.Body)
	tickResp.Body.Close()

	// Clore la session
	killReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/apirest.php/killSession", nil)
	killReq.Header.Set("App-Token", s.AppToken)
	killReq.Header.Set("Session-Token", sesData.SessionToken)
	killResp, _ := client.Do(killReq)
	if killResp != nil {
		killResp.Body.Close()
	}

	if tickResp.StatusCode >= 300 {
		return fmt.Errorf("glpi: statut HTTP %d", tickResp.StatusCode)
	}
	return nil
}

func glpiUrgency(s string) int {
	switch s {
	case "critical":
		return 5
	case "warning":
		return 3
	default:
		return 1
	}
}
