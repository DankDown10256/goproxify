// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rulesengine

import (
	"fmt"
	"time"
)

func (e *Engine) execDisableProxy(ac ActionContext) error {
	if e.deps.DisableProxy == nil {
		return fmt.Errorf("DisableProxy non configuré")
	}
	proxyID := ac.Rule.Action.ProxyID
	if proxyID == "" {
		if id, ok := ac.Detail["proxy_id"].(string); ok {
			proxyID = id
		}
	}
	if proxyID == "" {
		return fmt.Errorf("aucun proxy_id résolu pour l'action disable_proxy")
	}
	return e.deps.DisableProxy(proxyID)
}

func (e *Engine) execBanIP(ac ActionContext) error {
	if e.deps.BanIP == nil {
		return fmt.Errorf("BanIP non configuré")
	}
	ip, _ := ac.Detail["ip"].(string)
	if ip == "" {
		return fmt.Errorf("aucune IP dans le contexte d'action")
	}
	reason := ac.Rule.Action.BanReason
	if reason == "" {
		reason = fmt.Sprintf("règle automatique: %s", ac.Rule.Name)
	}
	var dur time.Duration
	if ac.Rule.Action.BanDuration != "" {
		dur, _ = time.ParseDuration(ac.Rule.Action.BanDuration)
	}
	return e.deps.BanIP(ip, reason, dur)
}

func (e *Engine) execNotify(ac ActionContext) {
	if e.deps.EmitNotify == nil {
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
	e.deps.EmitNotify(
		ac.Rule.ID,
		sev,
		fmt.Sprintf("[Moteur de règles] %s", ac.Rule.Name),
		msg,
		ac.Detail,
	)
}

func (e *Engine) execEnableStrict(ac ActionContext) error {
	if e.deps.EnableStrictF2B == nil {
		return fmt.Errorf("EnableStrictF2B non configuré")
	}
	dur := 30 * time.Minute
	if ac.Rule.Action.StrictDuration != "" {
		if d, err := time.ParseDuration(ac.Rule.Action.StrictDuration); err == nil && d > 0 {
			dur = d
		}
	}
	return e.deps.EnableStrictF2B(dur)
}
