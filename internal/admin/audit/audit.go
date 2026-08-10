// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package audit fournit un journal d'audit structuré pour l'Administration.
package audit

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Severity classe l'importance d'un événement d'audit.
type Severity string

const (
	Info     Severity = "info"
	Warning  Severity = "warning"
	Critical Severity = "critical"
)

// Event décrit un événement à journaliser.
type Event struct {
	Component    string   // admin | core | agent
	Action       string   // login, logout, create_proxy, delete_token, …
	Actor        string   // email de l'utilisateur ou nom du nœud
	UserID       string
	IP           string
	ResourceType string // proxy | token | user | snippet | cert | node
	ResourceID   string
	Detail       string
	Severity     Severity
}

// Logger écrit dans la table audit_log de SQLite.
type Logger struct {
	db            *sql.DB
	retentionDays int
}

// New crée un Logger. retentionDays = 0 → 90 jours par défaut.
func New(db *sql.DB, retentionDays int) *Logger {
	if retentionDays == 0 {
		retentionDays = 90
	}
	l := &Logger{db: db, retentionDays: retentionDays}
	go l.purgeLoop()
	return l
}

// Log enregistre un événement de façon non-bloquante (best-effort).
func (l *Logger) Log(ctx context.Context, e Event) {
	if e.Severity == "" {
		e.Severity = Info
	}
	if e.Component == "" {
		e.Component = "admin"
	}
	_, _ = l.db.ExecContext(ctx,
		`INSERT INTO audit_log
		 (component, actor, user_id, ip, action, resource_type, resource_id, detail, severity)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Component, e.Actor, e.UserID, e.IP,
		e.Action, e.ResourceType, e.ResourceID, e.Detail, string(e.Severity),
	)
}

// IPFrom extrait l'IP cliente d'une requête HTTP.
func IPFrom(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.SplitN(fwd, ",", 2)[0]
	}
	return r.RemoteAddr
}

// Entry représente une ligne du journal d'audit.
type Entry struct {
	ID           int64     `json:"id"`
	Component    string    `json:"component"`
	Actor        string    `json:"actor"`
	UserID       string    `json:"user_id"`
	IP           string    `json:"ip"`
	Action       string    `json:"action"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	Detail       string    `json:"detail"`
	Severity     string    `json:"severity"`
	CreatedAt    time.Time `json:"created_at"`
}

// SearchParams filtre la recherche dans le journal.
type SearchParams struct {
	Component string
	Action    string
	Actor     string
	Severity  string
	From      time.Time
	To        time.Time
	Limit     int
	Offset    int
}

// Search retourne les entrées filtrées et le total correspondant.
func (l *Logger) Search(p SearchParams) ([]Entry, int, error) {
	if p.Limit == 0 {
		p.Limit = 50
	}
	conds, args := []string{"1=1"}, []any{}
	if p.Component != "" {
		conds = append(conds, "component=?")
		args = append(args, p.Component)
	}
	if p.Action != "" {
		conds = append(conds, "action LIKE ?")
		args = append(args, "%"+p.Action+"%")
	}
	if p.Actor != "" {
		conds = append(conds, "actor LIKE ?")
		args = append(args, "%"+p.Actor+"%")
	}
	if p.Severity != "" {
		conds = append(conds, "severity=?")
		args = append(args, p.Severity)
	}
	if !p.From.IsZero() {
		conds = append(conds, "created_at >= ?")
		args = append(args, p.From.Format(time.RFC3339))
	}
	if !p.To.IsZero() {
		conds = append(conds, "created_at <= ?")
		args = append(args, p.To.Format(time.RFC3339))
	}
	where := strings.Join(conds, " AND ")

	var total int
	_ = l.db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE "+where, args...).Scan(&total)

	rows, err := l.db.Query(
		"SELECT id, COALESCE(component,'admin'), COALESCE(actor,''), COALESCE(user_id,''), "+
			"COALESCE(ip,''), action, COALESCE(resource_type,''), COALESCE(resource_id,''), "+
			"COALESCE(detail,''), COALESCE(severity,'info'), created_at "+
			"FROM audit_log WHERE "+where+
			" ORDER BY created_at DESC LIMIT ? OFFSET ?",
		append(args, p.Limit, p.Offset)...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []Entry
	for rows.Next() {
		var e Entry
		var ts string
		if err := rows.Scan(
			&e.ID, &e.Component, &e.Actor, &e.UserID, &e.IP,
			&e.Action, &e.ResourceType, &e.ResourceID, &e.Detail, &e.Severity, &ts,
		); err != nil {
			continue
		}
		e.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", ts)
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []Entry{}
	}
	return entries, total, nil
}

// Export sérialise les entrées au format csv ou json.
func (l *Logger) Export(p SearchParams, format string) ([]byte, string, error) {
	p.Limit = 10000
	p.Offset = 0
	entries, _, err := l.Search(p)
	if err != nil {
		return nil, "", err
	}
	if format == "csv" {
		var sb strings.Builder
		w := csv.NewWriter(&sb)
		_ = w.Write([]string{"id", "component", "actor", "user_id", "ip", "action",
			"resource_type", "resource_id", "detail", "severity", "created_at"})
		for _, e := range entries {
			_ = w.Write([]string{
				fmt.Sprintf("%d", e.ID), e.Component, e.Actor, e.UserID, e.IP,
				e.Action, e.ResourceType, e.ResourceID, e.Detail, e.Severity,
				e.CreatedAt.Format(time.RFC3339),
			})
		}
		w.Flush()
		return []byte(sb.String()), "text/csv", nil
	}
	b, err := json.Marshal(entries)
	return b, "application/json", err
}

func (l *Logger) purgeLoop() {
	for {
		time.Sleep(24 * time.Hour)
		_, _ = l.db.Exec(
			`DELETE FROM audit_log WHERE created_at < datetime('now', ? || ' days')`,
			fmt.Sprintf("-%d", l.retentionDays),
		)
	}
}
