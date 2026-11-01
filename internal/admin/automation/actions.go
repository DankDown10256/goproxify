// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/alerting"
	"github.com/vincamok/goproxify/internal/modules"
)

// ActionCall est ce que reçoit une action : sa configuration (variables déjà résolues) et le contexte.
type ActionCall struct {
	FlowID      string
	FlowName    string
	Description string
	RunID       string
	Config      map[string]any
	Detail      map[string]any
	Chain       []string
}

// ActionRun exécute une action ; ses sorties sont disponibles aux étapes suivantes en {{steps.<id>.x}}.
type ActionRun func(ctx context.Context, s *Service, call ActionCall) (map[string]any, error)

type actionModule struct {
	run   ActionRun
	check func(cfg map[string]any) error
}

var actionRegistry = modules.NewRegistry[actionModule]()

// RegisterAction déclare une action. Attributs reconnus : « edge » (la passerelle sait l'exécuter),
// « outputs », « category ».
func RegisterAction(m modules.Manifest, run ActionRun, check func(map[string]any) error) {
	actionRegistry.Register(m, actionModule{run: run, check: check})
}

// ActionManifests retourne les manifestes des actions, dans l'ordre d'affichage.
func ActionManifests() []modules.Manifest { return actionRegistry.Manifests() }

func checkHTTPURL(key string) func(map[string]any) error {
	return func(cfg map[string]any) error {
		raw := cfgStr(cfg, key)
		if isVar(raw) {
			return nil
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("%s : %q n'est pas une URL http(s)", key, raw)
		}
		return nil
	}
}

func isVar(s string) bool { return strings.Contains(s, "{{") }

func init() {
	RegisterAction(modules.Manifest{Type: "disable_proxy", Label: "Désactiver un proxy",
		Attrs: attrs(true, "remediation", "proxy_id"),
		Fields: []modules.Field{{Key: "proxy_id", Label: "Proxy", Kind: modules.KindSelect, Source: "proxies",
			Default: "{{detail.proxy_id}}", Help: "Par défaut, le proxy trouvé par la condition."}}},
		actDisableProxy, nil)

	RegisterAction(modules.Manifest{Type: "ban_ip", Label: "Bannir une IP",
		Attrs: attrs(true, "remediation", "ip"),
		Fields: []modules.Field{
			{Key: "ip", Label: "IP", Kind: modules.KindText, Default: "{{detail.ip}}", Help: "Par défaut, l'IP trouvée par la condition."},
			{Key: "ban_reason", Label: "Motif", Kind: modules.KindText},
			{Key: "ban_duration", Label: "Durée (vide = permanent)", Kind: modules.KindDuration},
		}},
		actBanIP, nil)

	RegisterAction(modules.Manifest{Type: "notify", Label: "Notifier",
		Attrs: attrs(true, "notification"),
		Fields: []modules.Field{
			{Key: "notify_severity", Label: "Gravité", Kind: modules.KindSelect, Default: "warning", Options: []modules.Option{
				{Value: "info", Label: "Info"}, {Value: "warning", Label: "Avertissement"}, {Value: "critical", Label: "Critique"}}},
			{Key: "notify_message", Label: "Message", Kind: modules.KindText, Help: "Variables acceptées : {{detail.ip}}, {{flow.name}}…"},
		}},
		actNotify, nil)

	RegisterAction(modules.Manifest{Type: "enable_strict", Label: "Mode strict (temporaire)",
		Attrs:  attrs(true, "remediation"),
		Fields: []modules.Field{dur("strict_duration", "Durée", "30m")}},
		actEnableStrict, nil)

	RegisterAction(modules.Manifest{Type: "webhook_call", Label: "Appeler un webhook",
		Attrs:  attrs(false, "integration", "status"),
		Fields: []modules.Field{{Key: "webhook_url", Label: "URL du webhook", Kind: modules.KindText, Required: true}}},
		actWebhookCall, checkHTTPURL("webhook_url"))

	RegisterAction(modules.Manifest{Type: "webhook_signed", Label: "Webhook signé (HMAC-SHA256)",
		Attrs: attrs(false, "integration", "status"),
		Fields: []modules.Field{
			{Key: "url", Label: "URL du webhook", Kind: modules.KindText, Required: true},
			{Key: "secret", Label: "Secret de signature", Kind: modules.KindPassword, Secret: true, Required: true},
		}},
		actWebhookSigned, checkHTTPURL("url"))

	RegisterAction(modules.Manifest{Type: "pagerduty", Label: "PagerDuty (Events API v2)",
		Attrs: attrs(false, "integration", "status"),
		Fields: []modules.Field{
			{Key: "routing_key", Label: "Clé d'intégration (routing key)", Kind: modules.KindPassword, Secret: true, Required: true},
			{Key: "severity", Label: "Gravité", Kind: modules.KindSelect, Default: "error", Options: []modules.Option{
				{Value: "critical", Label: "Critique"}, {Value: "error", Label: "Erreur"}, {Value: "warning", Label: "Avertissement"}, {Value: "info", Label: "Info"}}},
			{Key: "url", Label: "URL de l'API (défaut : events.pagerduty.com)", Kind: modules.KindText},
		}},
		actPagerDuty, func(cfg map[string]any) error {
			if cfgStr(cfg, "url") == "" {
				return nil
			}
			return checkHTTPURL("url")(cfg)
		})

	RegisterAction(modules.Manifest{Type: "run_backup", Label: "Déclencher une sauvegarde",
		Attrs:  attrs(false, "maintenance", "name"),
		Fields: []modules.Field{num("backup_retention", "Rétention (0 = pas de purge)", 0)}},
		actRunBackup, nil)
}

func actDisableProxy(ctx context.Context, s *Service, c ActionCall) (map[string]any, error) {
	if s.deps.DisableProxy == nil {
		return nil, fmt.Errorf("désactivation de proxy indisponible")
	}
	id := cfgStr(c.Config, "proxy_id")
	if id == "" {
		return nil, fmt.Errorf("aucun proxy à désactiver (proxy_id vide)")
	}
	return map[string]any{"proxy_id": id}, s.deps.DisableProxy(ctx, id)
}

func actBanIP(ctx context.Context, s *Service, c ActionCall) (map[string]any, error) {
	if s.deps.CreateBan == nil {
		return nil, fmt.Errorf("bannissement indisponible")
	}
	ip := cfgStr(c.Config, "ip")
	if ip == "" {
		return nil, fmt.Errorf("aucune IP à bannir (ip vide)")
	}
	reason := cfgStr(c.Config, "ban_reason")
	if reason == "" {
		reason = "flux d'automatisation : " + c.FlowName
	}
	var seconds int
	if raw := cfgStr(c.Config, "ban_duration"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("ban_duration : durée invalide %q", raw)
		}
		seconds = int(d.Seconds())
	}
	return map[string]any{"ip": ip}, s.deps.CreateBan(ctx, ip, reason, seconds)
}

func severity(s string) alerting.Severity {
	switch s {
	case "critical":
		return alerting.SevCritical
	case "info":
		return alerting.SevInfo
	}
	return alerting.SevWarning
}

func actNotify(_ context.Context, s *Service, c ActionCall) (map[string]any, error) {
	msg := cfgStr(c.Config, "notify_message")
	if msg == "" {
		msg = "Flux déclenché : " + c.FlowName
	}
	s.emitNotify(c.FlowID, c.FlowName, cfgStr(c.Config, "notify_severity"), msg, c.Detail, c.Chain)
	return nil, nil
}

// emitNotify publie l'événement automation_notify, routé par les règles d'alerte vers les canaux. La chaîne
// des flux l'accompagne : un flux déclenché par cet événement ne relance pas un flux déjà dans la chaîne.
func (s *Service) emitNotify(flowID, flowName, sev, msg string, detail map[string]any, chain []string) {
	if s.deps.Emit == nil {
		return
	}
	d := map[string]any{}
	for k, v := range detail {
		if k != "flow_chain" {
			d[k] = v
		}
	}
	d["flow_id"], d["flow_name"], d["message"] = flowID, flowName, msg
	d["flow_chain"] = append(append([]string{}, chain...), flowID)
	s.deps.Emit(alerting.Event{Trigger: alerting.TriggerAutomationNotify, Severity: severity(sev), Component: "admin", Detail: d})
}

func actEnableStrict(ctx context.Context, s *Service, c ActionCall) (map[string]any, error) {
	d, _, err := cfgDur(c.Config, "strict_duration", "30m")
	if err != nil {
		return nil, err
	}
	_, err = s.db.ExecContext(ctx, `
		UPDATE fleet_config SET value=json_set(value, '$.max_errors', 5,
			'$.strict_until', datetime('now', '+' || ? || ' minutes'))`, int(d.Minutes()))
	return nil, err
}

func actRunBackup(ctx context.Context, s *Service, c ActionCall) (map[string]any, error) {
	if s.deps.RunBackup == nil {
		return nil, fmt.Errorf("sauvegarde indisponible")
	}
	name := "flux-" + c.FlowName
	return map[string]any{"name": name}, s.deps.RunBackup(ctx, name, cfgInt(c.Config, "backup_retention", 0))
}

// webhookPayload est le corps JSON des actions webhook.
func webhookPayload(c ActionCall) ([]byte, error) {
	return json.Marshal(map[string]any{
		"flow":        c.FlowName,
		"flow_id":     c.FlowID,
		"run_id":      c.RunID,
		"description": c.Description,
		"detail":      c.Detail,
		"fired_at":    time.Now().UTC().Format(time.RFC3339),
	})
}

func httpPost(ctx context.Context, rawURL string, body []byte, headers map[string]string, ok func(int) bool, label string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s : %w", label, err)
	}
	defer resp.Body.Close()
	out := map[string]any{"status": resp.StatusCode}
	if !ok(resp.StatusCode) {
		return out, fmt.Errorf("%s : statut HTTP %d", label, resp.StatusCode)
	}
	return out, nil
}

func actWebhookCall(ctx context.Context, _ *Service, c ActionCall) (map[string]any, error) {
	target := cfgStr(c.Config, "webhook_url")
	if err := checkHTTPURL("webhook_url")(c.Config); err != nil {
		return nil, err
	}
	body, err := webhookPayload(c)
	if err != nil {
		return nil, err
	}
	return httpPost(ctx, target, body, nil, func(code int) bool { return code < 300 }, "webhook_call")
}

func actWebhookSigned(ctx context.Context, _ *Service, c ActionCall) (map[string]any, error) {
	target, secret := cfgStr(c.Config, "url"), cfgStr(c.Config, "secret")
	if target == "" || secret == "" {
		return nil, fmt.Errorf("webhook_signed : url et secret requis")
	}
	body, err := webhookPayload(c)
	if err != nil {
		return nil, err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "." + string(body)))
	return httpPost(ctx, target, body, map[string]string{
		"X-GPX-Timestamp": ts,
		"X-GPX-Signature": "sha256=" + hex.EncodeToString(mac.Sum(nil)),
	}, func(code int) bool { return code < 300 }, "webhook_signed")
}

const pagerDutyDefaultURL = "https://events.pagerduty.com/v2/enqueue"

func actPagerDuty(ctx context.Context, _ *Service, c ActionCall) (map[string]any, error) {
	key := cfgStr(c.Config, "routing_key")
	if key == "" {
		return nil, fmt.Errorf("pagerduty : routing_key requis")
	}
	endpoint := cfgStr(c.Config, "url")
	if endpoint == "" {
		endpoint = pagerDutyDefaultURL
	}
	sev := cfgStr(c.Config, "severity")
	if sev == "" {
		sev = "error"
	}
	summary := "[GoProxify] " + c.FlowName
	if c.Description != "" {
		summary += " — " + c.Description
	}
	dedup := c.FlowID
	if dedup == "" {
		dedup = c.FlowName
	}
	body, err := json.Marshal(map[string]any{
		"routing_key":  key,
		"event_action": "trigger",
		"dedup_key":    dedup,
		"payload": map[string]any{
			"summary": summary, "source": "goproxify", "severity": sev, "custom_details": c.Detail,
		},
	})
	if err != nil {
		return nil, err
	}
	return httpPost(ctx, endpoint, body, nil, func(code int) bool { return code == http.StatusAccepted || code == http.StatusOK }, "pagerduty")
}
