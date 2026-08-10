// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mfa

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SMSConfig est la configuration d'un provider SMS stockée dans settings.
type SMSConfig struct {
	Provider  string `json:"provider"`   // twilio | ovh | vonage
	AccountID string `json:"account_id"` // Twilio AccountSID / OVH serviceName / Vonage APIKey
	APIKey    string `json:"api_key"`    // Twilio AuthToken / OVH appKey / Vonage APISecret
	APISecret string `json:"api_secret"` // OVH appSecret + consumerKey (format "secret:consumer")
	From      string `json:"from"`       // numéro expéditeur
	Enabled   bool   `json:"enabled"`
}

// SendSMS envoie un SMS selon le provider configuré.
func SendSMS(ctx context.Context, cfg SMSConfig, to, message string) error {
	client := &http.Client{Timeout: 15 * time.Second}
	switch cfg.Provider {
	case "twilio":
		return sendTwilio(ctx, client, cfg, to, message)
	case "ovh":
		return sendOVH(ctx, client, cfg, to, message)
	case "vonage":
		return sendVonage(ctx, client, cfg, to, message)
	default:
		return fmt.Errorf("sms: provider inconnu %q", cfg.Provider)
	}
}

func sendTwilio(ctx context.Context, client *http.Client, cfg SMSConfig, to, message string) error {
	endpoint := fmt.Sprintf("https://api.twilio.com/2010-04-01/Accounts/%s/Messages.json", cfg.AccountID)
	body := url.Values{
		"To":   {to},
		"From": {cfg.From},
		"Body": {message},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(body.Encode()))
	if err != nil {
		return err
	}
	req.SetBasicAuth(cfg.AccountID, cfg.APIKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("twilio: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("twilio: statut HTTP %d", resp.StatusCode)
	}
	return nil
}

func sendOVH(ctx context.Context, client *http.Client, cfg SMSConfig, to, message string) error {
	// OVH SMS API v1 (nécessite appKey + appSecret + consumerKey)
	// cfg.APIKey = appKey, cfg.APISecret = "appSecret:consumerKey"
	parts := strings.SplitN(cfg.APISecret, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("ovh: api_secret doit être 'appSecret:consumerKey'")
	}
	endpoint := fmt.Sprintf("https://eu.api.ovh.com/1.0/sms/%s/jobs", cfg.AccountID)
	payload, _ := json.Marshal(map[string]any{
		"message":    message,
		"receivers":  []string{to},
		"sender":     cfg.From,
		"noStopClause": true,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ovh-Application", cfg.APIKey)
	req.Header.Set("X-Ovh-Consumer", parts[1])
	// Signature OVH simplifiée — en production, utiliser la lib OVH officielle
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ovh: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ovh: statut HTTP %d", resp.StatusCode)
	}
	return nil
}

func sendVonage(ctx context.Context, client *http.Client, cfg SMSConfig, to, message string) error {
	payload, _ := json.Marshal(map[string]any{
		"from": cfg.From,
		"to":   to,
		"text": message,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://rest.nexmo.com/sms/json", strings.NewReader(string(payload)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Basic "+vonageBasicAuth(cfg.AccountID, cfg.APIKey))
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("vonage: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("vonage: statut HTTP %d", resp.StatusCode)
	}
	return nil
}

func vonageBasicAuth(key, secret string) string {
	return base64.StdEncoding.EncodeToString([]byte(key + ":" + secret))
}
