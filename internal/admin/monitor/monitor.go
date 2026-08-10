// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package monitor surveille périodiquement les métriques d'accès et émet des alertes.
package monitor

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/vincamok/goproxify/internal/admin/alerting"
)

// Config paramètre les seuils de surveillance.
type Config struct {
	ErrorRatePct  float64 // ex: 10.0 → alerte si >10% d'erreurs 4xx/5xx
	LatencyMsP95  int64   // ex: 2000 → alerte si latence moyenne >2s
	WindowSec     int     // fenêtre d'observation (défaut 300s)
}

func DefaultConfig() Config {
	return Config{ErrorRatePct: 10.0, LatencyMsP95: 2000, WindowSec: 300}
}

// Monitor surveille les logs et déclenche des alertes.
type Monitor struct {
	db     *sql.DB
	log    *slog.Logger
	engine *alerting.Engine
	cfg    Config
}

// New crée un Monitor.
func New(db *sql.DB, log *slog.Logger, engine *alerting.Engine, cfg Config) *Monitor {
	return &Monitor{db: db, log: log, engine: engine, cfg: cfg}
}

// Start lance la boucle de surveillance (toutes les 5 minutes).
func (m *Monitor) Start(ctx context.Context) {
	go func() {
		m.scan()
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.scan()
			}
		}
	}()
}

func (m *Monitor) scan() {
	window := m.cfg.WindowSec
	if window <= 0 {
		window = 300
	}
	rows, err := m.db.Query(fmt.Sprintf(
		`SELECT domain,
		        COUNT(*) AS total,
		        SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END) AS errors,
		        AVG(latency_ms) AS avg_lat
		 FROM logs
		 WHERE ts > datetime('now','-%d seconds') AND status > 0 AND domain != ''
		 GROUP BY domain
		 HAVING total >= 10`, window))
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var domain string
		var total, errors int64
		var avgLat float64
		if rows.Scan(&domain, &total, &errors, &avgLat) != nil {
			continue
		}
		errorRate := 100.0 * float64(errors) / float64(total)

		if m.cfg.ErrorRatePct > 0 && errorRate > m.cfg.ErrorRatePct {
			m.engine.Emit(alerting.Event{
				Trigger:   alerting.TriggerHighErrorRate,
				Severity:  alerting.SevWarning,
				Domain:    domain,
				Component: "admin",
				Detail: map[string]any{
					"domain":     domain,
					"error_rate": fmt.Sprintf("%.1f%%", errorRate),
					"errors":     errors,
					"total":      total,
					"window_sec": window,
				},
			})
		}

		if m.cfg.LatencyMsP95 > 0 && int64(avgLat) > m.cfg.LatencyMsP95 {
			m.engine.Emit(alerting.Event{
				Trigger:   alerting.TriggerHighLatency,
				Severity:  alerting.SevWarning,
				Domain:    domain,
				Component: "admin",
				Detail: map[string]any{
					"domain":     domain,
					"avg_lat_ms": int64(avgLat),
					"threshold":  m.cfg.LatencyMsP95,
					"window_sec": window,
				},
			})
		}
	}
}
