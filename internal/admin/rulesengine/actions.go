// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rulesengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

func (e *Engine) execDisableProxy(ctx context.Context, ac ActionContext) error {
	if e.deps.DisableProxy == nil {
		return fmt.Errorf("DisableProxy non configuré")
	}
	proxyID := ac.Rule.Action.ProxyID
	if proxyID == "" {
		// utiliser le proxy issu de la condition
		if id, ok := ac.Detail["proxy_id"].(string); ok {
			proxyID = id
		}
	}
	if proxyID == "" {
		return fmt.Errorf("aucun proxy_id résolu pour l'action disable_proxy")
	}
	return e.deps.DisableProxy(ctx, proxyID)
}

func (e *Engine) execBanIP(ctx context.Context, ac ActionContext) error {
	if e.deps.CreateBan == nil {
		return fmt.Errorf("CreateBan non configuré")
	}
	ip, _ := ac.Detail["ip"].(string)
	if ip == "" {
		return fmt.Errorf("aucune IP dans le contexte d'action")
	}
	reason := ac.Rule.Action.BanReason
	if reason == "" {
		reason = fmt.Sprintf("règle automatique: %s", ac.Rule.Name)
	}
	var durationSec int
	if ac.Rule.Action.BanDuration != "" {
		dur, err := time.ParseDuration(ac.Rule.Action.BanDuration)
		if err == nil {
			durationSec = int(dur.Seconds())
		}
	}
	return e.deps.CreateBan(ctx, ip, reason, durationSec)
}

func (e *Engine) execNotify(ac ActionContext) {
	if e.deps.EmitAlert == nil {
		return
	}
	sev := ac.Rule.Action.NotifySeverity
	if sev == "" {
		sev = "warning"
	}
	msg := ac.Rule.Action.NotifyMessage
	if msg == "" {
		msg = fmt.Sprintf("Règle déclenchée: %s", ac.Rule.Name)
	}
	e.deps.EmitAlert(
		"rules_engine_fired",
		sev,
		fmt.Sprintf("[Moteur de règles] %s", ac.Rule.Name),
		msg,
		ac.Detail,
	)
}

func (e *Engine) execWebhookCall(ctx context.Context, ac ActionContext) error {
	rawURL := ac.Rule.Action.WebhookURL
	if rawURL == "" {
		return fmt.Errorf("aucune webhook_url configurée pour l'action webhook_call")
	}
	if _, err := url.ParseRequestURI(rawURL); err != nil {
		return fmt.Errorf("webhook_url invalide: %w", err)
	}
	payload := map[string]any{
		"rule":        ac.Rule.Name,
		"rule_id":     ac.Rule.ID,
		"description": ac.Rule.Description,
		"condition":   ac.Rule.Condition.Type,
		"action":      ac.Rule.Action.Type,
		"detail":      ac.Detail,
		"fired_at":    time.Now().UTC().Format(time.RFC3339),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook_call: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook_call: statut HTTP %d", resp.StatusCode)
	}
	return nil
}

func (e *Engine) execRunBackup(ctx context.Context, ac ActionContext) error {
	if e.deps.RunBackup == nil {
		return fmt.Errorf("RunBackup non configuré")
	}
	name := fmt.Sprintf("rule-auto-%s", ac.Rule.Name)
	return e.deps.RunBackup(ctx, name, ac.Rule.Action.BackupRetention)
}

func (e *Engine) execEnableStrict(ctx context.Context, ac ActionContext) error {
	// Réduire max_errors Fail2Ban temporairement via la DB
	_, err := e.db.ExecContext(ctx, `
		UPDATE fail2ban_config SET value=json_set(value,
			'$.max_errors', 5,
			'$.strict_until', datetime('now', '+' || ? || ' minutes')
		)`, func() int {
		if ac.Rule.Action.StrictDuration != "" {
			d, err := time.ParseDuration(ac.Rule.Action.StrictDuration)
			if err == nil {
				return int(d.Minutes())
			}
		}
		return 30
	}(),
	)
	return err
}
