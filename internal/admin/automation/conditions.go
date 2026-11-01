// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/logs"
	"github.com/vincamok/goproxify/internal/modules"
	"github.com/vincamok/goproxify/internal/sqltime"
)

// CondEval évalue une condition simple. detail porte le contexte trouvé (IP, proxy…), repris par les étapes
// suivantes en {{detail.x}}.
type CondEval func(ctx context.Context, s *Service, cfg map[string]any) (matched bool, detail map[string]any, err error)

type condModule struct {
	eval  CondEval
	check func(cfg map[string]any) error
}

var condRegistry = modules.NewRegistry[condModule]()

// RegisterCondition déclare une condition. Attributs reconnus : « edge » (la passerelle sait l'évaluer
// sur ses données locales), « outputs » (clés de detail), « category ».
func RegisterCondition(m modules.Manifest, eval CondEval, check func(map[string]any) error) {
	condRegistry.Register(m, condModule{eval: eval, check: check})
}

// ConditionManifests retourne les manifestes des conditions, dans l'ordre d'affichage.
func ConditionManifests() []modules.Manifest { return condRegistry.Manifests() }

func cfgStr(cfg map[string]any, key string) string {
	switch v := cfg[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case nil:
		return ""
	default:
		return text(v)
	}
}

func cfgFloat(cfg map[string]any, key string, def float64) float64 {
	switch v := cfg[key].(type) {
	case float64:
		if v > 0 {
			return v
		}
	case int:
		if v > 0 {
			return float64(v)
		}
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil && f > 0 {
			return f
		}
	}
	return def
}

func cfgInt(cfg map[string]any, key string, def int) int {
	return int(cfgFloat(cfg, key, float64(def)))
}

// cfgDur lit une durée (défaut def si absente) ; retourne aussi le texte d'origine pour le détail.
func cfgDur(cfg map[string]any, key, def string) (time.Duration, string, error) {
	raw := cfgStr(cfg, key)
	if raw == "" {
		raw = def
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return 0, raw, fmt.Errorf("%s : durée invalide %q", key, raw)
	}
	return d, raw, nil
}

func since(d time.Duration) string { return sqltime.Format(time.Now().Add(-d)) }

func num(key, label string, def float64) modules.Field {
	return modules.Field{Key: key, Label: label, Kind: modules.KindNumber, Default: def}
}

func dur(key, label, def string) modules.Field {
	return modules.Field{Key: key, Label: label, Kind: modules.KindDuration, Default: def}
}

func pick(key, label, source string) modules.Field {
	return modules.Field{Key: key, Label: label, Kind: modules.KindSelect, Source: source}
}

func attrs(edge bool, category string, outputs ...string) map[string]any {
	return map[string]any{"edge": edge, "category": category, "outputs": outputs}
}

func init() {
	RegisterCondition(modules.Manifest{Type: "cve_critical", Label: "CVE critique sur un backend",
		Attrs: attrs(false, "security", "cve_id", "cvss_score", "backend_url", "proxy_id", "proxy_name"),
		Fields: []modules.Field{
			num("cvss_threshold", "Score CVSS minimal", 9),
			pick("proxy_id", "Proxy (vide = tous)", "proxies"),
		}}, evalCVECritical, nil)

	RegisterCondition(modules.Manifest{Type: "ban_spike", Label: "Pic de bans",
		Attrs: attrs(true, "security", "ban_count", "window", "source"),
		Fields: []modules.Field{
			num("ban_count", "Nombre de bans", 20),
			dur("ban_window", "Fenêtre", "1h"),
			{Key: "ban_source", Label: "Source (vide = toutes)", Kind: modules.KindText, Placeholder: "fleet, crowdsec, threat…"},
		}}, evalBanSpike, nil)

	RegisterCondition(modules.Manifest{Type: "engine_silent", Label: "Moteur IPS silencieux",
		Attrs: attrs(true, "reliability", "engine_type", "last_activity", "silent_for"),
		Fields: []modules.Field{
			{Key: "engine_type", Label: "Moteur", Kind: modules.KindSelect, Required: true,
				Options: []modules.Option{{Value: "fleet", Label: "Seuils multi-passerelles"}, {Value: "crowdsec", Label: "CrowdSec"}}},
			num("silent_minutes", "Silence depuis (minutes)", 10),
		}}, evalEngineSilent, nil)

	RegisterCondition(modules.Manifest{Type: "proxy_error_rate", Label: "Taux d'erreurs d'un proxy",
		Attrs: attrs(true, "reliability", "proxy_id", "proxy_name", "error_rate", "window"),
		Fields: []modules.Field{
			num("error_rate_threshold", "Seuil (% de réponses 5xx)", 20),
			dur("error_rate_window", "Fenêtre", "5m"),
			pick("proxy_id", "Proxy (vide = tous)", "proxies"),
		}}, evalProxyErrorRate, nil)

	RegisterCondition(modules.Manifest{Type: "ban_repeat", Label: "IP bannie à répétition",
		Attrs: attrs(true, "security", "ip", "count", "window"),
		Fields: []modules.Field{
			num("repeat_count", "Nombre de bans de la même IP", 3),
			dur("repeat_window", "Fenêtre", "24h"),
		}}, evalBanRepeat, nil)

	RegisterCondition(modules.Manifest{Type: "node_offline", Label: "Nœud hors ligne",
		Attrs: attrs(false, "reliability", "node_name", "role", "last_seen_at"),
		Fields: []modules.Field{
			pick("node_name", "Nœud (vide = tous)", "nodes"),
			num("offline_minutes", "Sans nouvelles depuis (minutes)", 5),
		}}, evalNodeOffline, nil)

	RegisterCondition(modules.Manifest{Type: "cert_expiring", Label: "Certificat bientôt expiré",
		Attrs: attrs(false, "compliance", "domain", "expires_at"),
		Fields: []modules.Field{
			pick("domain", "Domaine (vide = tous)", "domains"),
			num("days_left", "Jours restants", 15),
		}}, evalCertExpiring, nil)

	registerMetricCondition()
}

// evalCVECritical : CVE ouverte avec CVSS ≥ seuil sur un backend d'un proxy actif.
func evalCVECritical(ctx context.Context, s *Service, cfg map[string]any) (bool, map[string]any, error) {
	threshold := cfgFloat(cfg, "cvss_threshold", 9)
	query := `
		SELECT cv.cve_id, cv.cvss_score, cv.backend_url, COALESCE(p.id,''), COALESCE(p.name,'')
		FROM security_cves cv
		LEFT JOIN proxies p ON p.enabled=1
		  AND json_extract(p.config, '$.backend') LIKE '%' || cv.backend_url || '%'
		WHERE cv.status='open' AND cv.cvss_score >= ?`
	args := []any{threshold}
	if id := cfgStr(cfg, "proxy_id"); id != "" {
		query += ` AND p.id=?`
		args = append(args, id)
	}
	query += ` ORDER BY cv.cvss_score DESC LIMIT 1`
	var cveID, backendURL, proxyID, proxyName string
	var score float64
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&cveID, &score, &backendURL, &proxyID, &proxyName); err != nil {
		return false, nil, nil
	}
	return true, map[string]any{"cve_id": cveID, "cvss_score": score, "backend_url": backendURL,
		"proxy_id": proxyID, "proxy_name": proxyName}, nil
}

// evalBanSpike : nombre de bans dans la fenêtre ≥ seuil.
func evalBanSpike(ctx context.Context, s *Service, cfg map[string]any) (bool, map[string]any, error) {
	d, window, err := cfgDur(cfg, "ban_window", "1h")
	if err != nil {
		return false, nil, err
	}
	threshold := cfgInt(cfg, "ban_count", 20)
	query := `SELECT COUNT(*) FROM security_bans WHERE created_at >= ?`
	args := []any{since(d)}
	source := cfgStr(cfg, "ban_source")
	if source != "" {
		query += ` AND source=?`
		args = append(args, source)
	}
	var count int
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return false, nil, err
	}
	if count < threshold {
		return false, nil, nil
	}
	return true, map[string]any{"ban_count": count, "window": window, "source": source}, nil
}

// evalEngineSilent : moteur IPS sans activité depuis plus de silent_minutes.
func evalEngineSilent(_ context.Context, s *Service, cfg map[string]any) (bool, map[string]any, error) {
	minutes := cfgInt(cfg, "silent_minutes", 10)
	var last time.Time
	switch engine := cfgStr(cfg, "engine_type"); engine {
	case "fleet":
		if s.deps.FleetLastActivity != nil {
			last = s.deps.FleetLastActivity()
		}
	case "crowdsec":
		if s.deps.CrowdSecLastSync != nil {
			last = s.deps.CrowdSecLastSync()
		}
	default:
		return false, nil, fmt.Errorf("engine_type doit valoir fleet ou crowdsec")
	}
	if last.IsZero() || time.Since(last) <= time.Duration(minutes)*time.Minute {
		return false, nil, nil
	}
	return true, map[string]any{
		"engine_type":   cfgStr(cfg, "engine_type"),
		"last_activity": last.Format(time.RFC3339),
		"silent_for":    time.Since(last).Round(time.Second).String(),
	}, nil
}

// evalProxyErrorRate : part de réponses 5xx d'un proxy ≥ seuil sur la fenêtre (au moins 10 requêtes).
func evalProxyErrorRate(ctx context.Context, s *Service, cfg map[string]any) (bool, map[string]any, error) {
	d, window, err := cfgDur(cfg, "error_rate_window", "5m")
	if err != nil {
		return false, nil, err
	}
	threshold := cfgFloat(cfg, "error_rate_threshold", 20)
	// Lus dans les cumuls par minute que calculent les passerelles : la fenêtre commence à la minute qui contient son début.
	query := `
		SELECT p.id, p.name, SUM(l.requests) AS total, SUM(CASE WHEN l.status >= 500 THEN l.requests ELSE 0 END)
		FROM logs_minute l
		JOIN proxies p ON p.enabled=1 AND (l.domain='' OR l.domain=json_extract(p.config,'$.domain'))
		WHERE l.minute >= ?`
	args := []any{logs.MinuteKey(time.Now().Add(-d))}
	if id := cfgStr(cfg, "proxy_id"); id != "" {
		query += ` AND p.id=?`
		args = append(args, id)
	}
	query += ` GROUP BY p.id HAVING total > 10`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return false, nil, nil
	}
	defer rows.Close()
	var worstID, worstName string
	worst := -1.0
	for rows.Next() {
		var id, name string
		var total, errs int
		if rows.Scan(&id, &name, &total, &errs) != nil || total == 0 {
			continue
		}
		if rate := float64(errs) / float64(total) * 100; rate > worst {
			worst, worstID, worstName = rate, id, name
		}
	}
	if worst < threshold {
		return false, nil, nil
	}
	return true, map[string]any{"proxy_id": worstID, "proxy_name": worstName, "error_rate": worst, "window": window}, nil
}

// evalBanRepeat : une même IP bannie au moins repeat_count fois dans la fenêtre.
func evalBanRepeat(ctx context.Context, s *Service, cfg map[string]any) (bool, map[string]any, error) {
	d, window, err := cfgDur(cfg, "repeat_window", "24h")
	if err != nil {
		return false, nil, err
	}
	var ip string
	var n int
	err = s.db.QueryRowContext(ctx, `
		SELECT ip, COUNT(*) AS n FROM security_bans WHERE created_at >= ?
		GROUP BY ip HAVING n >= ? ORDER BY n DESC LIMIT 1`, since(d), cfgInt(cfg, "repeat_count", 3)).Scan(&ip, &n)
	if err != nil {
		return false, nil, nil
	}
	return true, map[string]any{"ip": ip, "count": n, "window": window}, nil
}

// evalNodeOffline : un nœud sans nouvelles depuis plus de offline_minutes.
func evalNodeOffline(ctx context.Context, s *Service, cfg map[string]any) (bool, map[string]any, error) {
	query := `SELECT node_name, role, last_seen_at FROM nodes WHERE last_seen_at < ?`
	args := []any{since(time.Duration(cfgInt(cfg, "offline_minutes", 5)) * time.Minute)}
	if n := cfgStr(cfg, "node_name"); n != "" {
		query += ` AND node_name = ?`
		args = append(args, n)
	}
	query += ` ORDER BY last_seen_at ASC LIMIT 1`
	var node, role, lastSeen string
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&node, &role, &lastSeen); err != nil {
		return false, nil, nil
	}
	return true, map[string]any{"node_name": node, "role": role, "last_seen_at": lastSeen}, nil
}

// evalCertExpiring : un certificat expire dans moins de days_left jours.
func evalCertExpiring(ctx context.Context, s *Service, cfg map[string]any) (bool, map[string]any, error) {
	query := `SELECT domain, expires_at FROM certs WHERE julianday(expires_at) - julianday('now') <= ?`
	args := []any{cfgInt(cfg, "days_left", 15)}
	if d := cfgStr(cfg, "domain"); d != "" {
		query += ` AND domain = ?`
		args = append(args, d)
	}
	query += ` ORDER BY expires_at ASC LIMIT 1`
	var domain, expiresAt string
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&domain, &expiresAt); err != nil {
		return false, nil, nil
	}
	return true, map[string]any{"domain": domain, "expires_at": expiresAt}, nil
}
