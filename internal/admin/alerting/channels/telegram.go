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

// TelegramSender envoie une notification via l'API Bot Telegram
// (https://core.telegram.org/bots/api#sendmessage).
type TelegramSender struct {
	BotToken string
	ChatID   string
}

func (s *TelegramSender) Send(ctx context.Context, msg Message) error {
	if s.BotToken == "" || s.ChatID == "" {
		return fmt.Errorf("telegram: bot_token et chat_id requis")
	}
	text := fmt.Sprintf("*[%s]* %s\n%s\n\n_Règle : %s · Déclencheur : %s_",
		string(msg.Severity), msg.Title, msg.Body, msg.RuleName, string(msg.Trigger))
	apiURL := "https://api.telegram.org/bot" + url.PathEscape(s.BotToken) + "/sendMessage"
	form := url.Values{
		"chat_id":    {s.ChatID},
		"text":       {text},
		"parse_mode": {"Markdown"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("telegram: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram: statut HTTP %d", resp.StatusCode)
	}
	return nil
}
