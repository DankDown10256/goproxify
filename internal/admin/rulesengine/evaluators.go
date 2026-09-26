// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rulesengine

import (
	"context"
	"fmt"
	"time"
)

// evalCVECritical : CVE avec CVSS ≥ seuil sur au moins un proxy actif.
// Retourne le premier proxy affecté dans detail.
func (e *Engine) evalCVECritical(ctx context.Context, c Condition) (bool, map[string]any, error) {
	threshold := c.CVSSThreshold
	if threshold <= 0 {
		threshold = 9.0
	}

	query := `
		SELECT cv.id, cv.cve_id, cv.cvss_score, cv.backend_url,
		       p.id AS proxy_id, p.name AS proxy_name
		FROM security_cves cv
		LEFT JOIN proxies p ON p.enabled=1
		  AND json_extract(p.config, '$.backend') LIKE '%' || cv.backend_url || '%'
		WHERE cv.status='open' AND cv.cvss_score >= ?
		ORDER BY cv.cvss_score DESC
		LIMIT 1`
	args := []any{threshold}

	if c.ProxyID != "" {
		query = `
			SELECT cv.id, cv.cve_id, cv.cvss_score, cv.backend_url,
			       p.id AS proxy_id, p.name AS proxy_name
			FROM security_cves cv
			JOIN proxies p ON p.id=? AND p.enabled=1
			  AND json_extract(p.config, '$.backend') LIKE '%' || cv.backend_url || '%'
			WHERE cv.status='open' AND cv.cvss_score >= ?
			ORDER BY cv.cvss_score DESC
			LIMIT 1`
		args = []any{c.ProxyID, threshold}
	}

	var cveID, backendURL, proxyID, proxyName string
	var cvssScore float64
	var cveRowID int64
	err := e.db.QueryRowContext(ctx, query, args...).Scan(
		&cveRowID, &cveID, &cvssScore, &backendURL, &proxyID, &proxyName,
	)
	if err != nil {
		// sql.ErrNoRows = aucune CVE critique — pas une erreur
		return false, nil, nil
	}
	return true, map[string]any{
		"cve_id":      cveID,
		"cvss_score":  cvssScore,
		"backend_url": backendURL,
		"proxy_id":    proxyID,
		"proxy_name":  proxyName,
	}, nil
}

// evalBanSpike : nombre de bans dans la fenêtre > seuil.
func (e *Engine) evalBanSpike(ctx context.Context, c Condition) (bool, map[string]any, error) {
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
	since := time.Now().Add(-dur).UTC().Format("2006-01-02 15:04:05")

	query := `SELECT COUNT(*) FROM security_bans WHERE created_at >= ?`
	args := []any{since}
	if c.BanSource != "" {
		query += ` AND source=?`
		args = append(args, c.BanSource)
	}

	var count int
	if err := e.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return false, nil, err
	}
	if count < threshold {
		return false, nil, nil
	}
	return true, map[string]any{
		"ban_count": count,
		"window":    window,
		"source":    c.BanSource,
	}, nil
}

// evalEngineSilent : moteur IPS sans activité depuis plus de SilentMinutes.
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
	silent := time.Since(lastActivity) > threshold
	if !silent {
		return false, nil, nil
	}
	return true, map[string]any{
		"engine_type":   c.EngineType,
		"last_activity": lastActivity.Format(time.RFC3339),
		"silent_for":    time.Since(lastActivity).Round(time.Second).String(),
	}, nil
}

// evalProxyErrorRate : taux d'erreurs HTTP > seuil sur la fenêtre.
func (e *Engine) evalProxyErrorRate(ctx context.Context, c Condition) (bool, map[string]any, error) {
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
	since := time.Now().Add(-dur).UTC().Format("2006-01-02 15:04:05")

	type row struct {
		proxyID    string
		proxyName  string
		total      int
		errors     int
		errorRate  float64
	}

	query := `
		SELECT p.id, p.name,
		       COUNT(*) AS total,
		       SUM(CASE WHEN l.status >= 500 THEN 1 ELSE 0 END) AS errors
		FROM logs l
		JOIN proxies p ON p.enabled=1
		  AND (l.domain='' OR l.domain=json_extract(p.config,'$.domain'))
		WHERE l.ts >= ? AND l.status > 0`
	args := []any{since}
	if c.ProxyID != "" {
		query += ` AND p.id=?`
		args = append(args, c.ProxyID)
	}
	query += ` GROUP BY p.id HAVING total > 10`

	rows, err := e.db.QueryContext(ctx, query, args...)
	if err != nil {
		return false, nil, nil // logs table may not exist yet
	}
	defer rows.Close()

	var worst row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.proxyID, &r.proxyName, &r.total, &r.errors); err != nil {
			continue
		}
		if r.total > 0 {
			r.errorRate = float64(r.errors) / float64(r.total) * 100
		}
		if r.errorRate > worst.errorRate {
			worst = r
		}
	}
	if worst.errorRate < threshold {
		return false, nil, nil
	}
	return true, map[string]any{
		"proxy_id":   worst.proxyID,
		"proxy_name": worst.proxyName,
		"error_rate": worst.errorRate,
		"window":     window,
	}, nil
}

// evalBanRepeat : même IP bannie ≥ RepeatCount fois dans la fenêtre.
func (e *Engine) evalBanRepeat(ctx context.Context, c Condition) (bool, map[string]any, error) {
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
	since := time.Now().Add(-dur).UTC().Format("2006-01-02 15:04:05")

	var ip string
	var n int
	err = e.db.QueryRowContext(ctx, `
		SELECT ip, COUNT(*) AS n FROM security_bans
		WHERE created_at >= ?
		GROUP BY ip HAVING n >= ?
		ORDER BY n DESC LIMIT 1`,
		since, count,
	).Scan(&ip, &n)
	if err != nil {
		return false, nil, nil
	}
	return true, map[string]any{
		"ip":     ip,
		"count":  n,
		"window": window,
	}, nil
}

// evalNodeOffline : une passerelle/Agent sans heartbeat depuis plus de OfflineMinutes.
func (e *Engine) evalNodeOffline(ctx context.Context, c Condition) (bool, map[string]any, error) {
	offlineMin := c.OfflineMinutes
	if offlineMin <= 0 {
		offlineMin = 5
	}
	threshold := time.Now().Add(-time.Duration(offlineMin) * time.Minute).UTC().Format("2006-01-02 15:04:05")

	query := `SELECT node_name, role, last_seen_at FROM nodes WHERE last_seen_at < ?`
	args := []any{threshold}
	if c.NodeName != "" {
		query += ` AND node_name = ?`
		args = append(args, c.NodeName)
	}
	query += ` ORDER BY last_seen_at ASC LIMIT 1`

	var nodeName, role, lastSeen string
	err := e.db.QueryRowContext(ctx, query, args...).Scan(&nodeName, &role, &lastSeen)
	if err != nil {
		return false, nil, nil
	}
	return true, map[string]any{
		"node_name":    nodeName,
		"role":         role,
		"last_seen_at": lastSeen,
	}, nil
}

// evalCertExpiring : un certificat TLS expire dans moins de DaysLeft jours.
func (e *Engine) evalCertExpiring(ctx context.Context, c Condition) (bool, map[string]any, error) {
	daysLeft := c.DaysLeft
	if daysLeft <= 0 {
		daysLeft = 15
	}

	query := `SELECT domain, expires_at FROM certs WHERE julianday(expires_at) - julianday('now') <= ?`
	args := []any{daysLeft}
	if c.Domain != "" {
		query += ` AND domain = ?`
		args = append(args, c.Domain)
	}
	query += ` ORDER BY expires_at ASC LIMIT 1`

	var domain, expiresAt string
	err := e.db.QueryRowContext(ctx, query, args...).Scan(&domain, &expiresAt)
	if err != nil {
		return false, nil, nil
	}
	return true, map[string]any{
		"domain":     domain,
		"expires_at": expiresAt,
	}, nil
}
