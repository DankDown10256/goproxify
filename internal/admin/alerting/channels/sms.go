// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SMSSender envoie un SMS via l'API Twilio
// (https://www.twilio.com/docs/sms/api/message-resource).
type SMSSender struct {
	AccountSID string
	AuthToken  string
	From       string // numéro Twilio expéditeur, format E.164
	To         string // numéro destinataire, format E.164
}

func (s *SMSSender) Send(ctx context.Context, msg Message) error {
	if s.AccountSID == "" || s.AuthToken == "" || s.From == "" || s.To == "" {
		return fmt.Errorf("sms: account_sid, auth_token, from et to requis")
	}
	// Un SMS n'a pas de mise en forme : message compact, sévérité en préfixe.
	text := fmt.Sprintf("[%s] %s — %s", strings.ToUpper(string(msg.Severity)), msg.Title, msg.Body)
	if len(text) > 480 {
		text = text[:477] + "…"
	}
	apiURL := "https://api.twilio.com/2010-04-01/Accounts/" + url.PathEscape(s.AccountSID) + "/Messages.json"
	form := url.Values{"From": {s.From}, "To": {s.To}, "Body": {text}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(s.AccountSID, s.AuthToken)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("sms: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("sms: statut HTTP %d", resp.StatusCode)
	}
	return nil
}
