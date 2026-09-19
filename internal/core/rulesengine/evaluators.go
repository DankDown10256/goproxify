// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rulesengine

import (
	"fmt"
	"time"
)

func (e *Engine) evalBanSpike(c Condition) (bool, map[string]any, error) {
	window := c.BanWindow
	if window == "" {
		window = "1h"
	}
	threshold := c.BanCount
	if threshold <= 0 {
		threshold = 20
	}
	dur, err := time.ParseDuration(window)
	if err != nil {
		return false, nil, fmt.Errorf("ban_window invalide: %s", window)
	}
	if e.deps.GetRecentBanCount == nil {
		return false, nil, nil
	}
	count := e.deps.GetRecentBanCount(time.Now().Add(-dur), c.BanSource)
	if count < threshold {
		return false, nil, nil
	}
	return true, map[string]any{
		"ban_count": count,
		"window":    window,
		"source":    c.BanSource,
	}, nil
}

func (e *Engine) evalEngineSilent(c Condition) (bool, map[string]any, error) {
	silentMin := c.SilentMinutes
	if silentMin <= 0 {
		silentMin = 10
	}
	threshold := time.Duration(silentMin) * time.Minute

	var lastActivity time.Time
	switch c.EngineType {
	case "fail2ban":
		if e.deps.GetF2BLastActivity != nil {
			lastActivity = e.deps.GetF2BLastActivity()
		}
	case "crowdsec":
		if e.deps.GetCrowdSecLastSync != nil {
			lastActivity = e.deps.GetCrowdSecLastSync()
		}
	default:
		return false, nil, fmt.Errorf("engine_type doit être 'fail2ban' ou 'crowdsec'")
	}

	if lastActivity.IsZero() {
		return false, nil, nil
	}
	if time.Since(lastActivity) <= threshold {
		return false, nil, nil
	}
	return true, map[string]any{
		"engine_type":   c.EngineType,
		"last_activity": lastActivity.Format(time.RFC3339),
		"silent_for":    time.Since(lastActivity).Round(time.Second).String(),
	}, nil
}

func (e *Engine) evalProxyErrorRate(c Condition) (bool, map[string]any, error) {
	window := c.ErrorRateWindow
	if window == "" {
		window = "5m"
	}
	threshold := c.ErrorRateThreshold
	if threshold <= 0 {
		threshold = 20.0
	}
	dur, err := time.ParseDuration(window)
	if err != nil {
		return false, nil, fmt.Errorf("error_rate_window invalide: %s", window)
	}
	if e.deps.GetProxyErrorRate == nil {
		return false, nil, nil
	}
	rate, host := e.deps.GetProxyErrorRate(time.Now().Add(-dur))
	if rate < threshold {
		return false, nil, nil
	}
	return true, map[string]any{
		"proxy_id":   host,
		"proxy_name": host,
		"error_rate": rate,
		"window":     window,
	}, nil
}

func (e *Engine) evalBanRepeat(c Condition) (bool, map[string]any, error) {
	window := c.RepeatWindow
	if window == "" {
		window = "24h"
	}
	count := c.RepeatCount
	if count <= 0 {
		count = 3
	}
	dur, err := time.ParseDuration(window)
	if err != nil {
		return false, nil, fmt.Errorf("repeat_window invalide: %s", window)
	}
	if e.deps.GetRepeatBanIP == nil {
		return false, nil, nil
	}
	ip, n := e.deps.GetRepeatBanIP(time.Now().Add(-dur), count)
	if ip == "" {
		return false, nil, nil
	}
	return true, map[string]any{
		"ip":     ip,
		"count":  n,
		"window": window,
	}, nil
}
