// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package logs fournit le stockage et la diffusion en temps réel des logs.
package logs

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Entry représente une ligne de log.
type Entry struct {
	ID        int64     `json:"id"`
	Ts        time.Time `json:"ts"`
	Level     string    `json:"level"`
	Component string    `json:"component"`
	NodeName  string    `json:"node_name,omitempty"`
	Domain    string    `json:"domain"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	Status    int       `json:"status"`
	IP        string    `json:"ip"`
	LatencyMs int64     `json:"latency_ms"`
	Bytes     int64     `json:"bytes"`
	Message   string    `json:"message"`
	Referrer  string    `json:"referrer,omitempty"`
}

// SearchParams filtre les entrées de log.
type SearchParams struct {
	Level     string
	Component string
	NodeName  string
	Domain    string
	IP        string
	Method    string
	Status    string
	Path      string
	Search    string
	DateFrom  string
	DateTo    string
	// Kind : "access" (status>0, requêtes HTTP) | "system" (status=0, événements process) | "" (tous).
	Kind     string
	Page     int
	PageSize int
}

// Store gère la persistance et la diffusion des logs.
type Store struct {
	db          *sql.DB
	mu          sync.RWMutex
	subscribers map[int64]chan Entry
	nextID      int64
}

// New crée un Store et s'assure que la table logs existe.
func New(db *sql.DB) *Store {
	s := &Store{
		db:          db,
		subscribers: make(map[int64]chan Entry),
	}
	return s
}

// Write insère une entrée et la diffuse aux abonnés SSE.
func (s *Store) Write(e Entry) {
	if e.Ts.IsZero() {
		e.Ts = time.Now()
	}
	res, err := s.db.Exec(
		`INSERT INTO logs (ts, level, component, node_name, domain, method, path, status, ip, latency_ms, bytes, message, referrer)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Ts.UTC().Format(time.RFC3339Nano),
		nvl(e.Level, "info"), nvl(e.Component, "admin"), e.NodeName,
		e.Domain, e.Method, e.Path, e.Status, e.IP, e.LatencyMs, e.Bytes, e.Message, e.Referrer,
	)
	if err == nil {
		if id, err2 := res.LastInsertId(); err2 == nil {
			e.ID = id
		}
	}
	s.broadcast(e)
}

func (s *Store) broadcast(e Entry) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, ch := range s.subscribers {
		select {
		case ch <- e:
		default:
		}
	}
}

// Subscribe retourne un canal qui recevra les nouvelles entrées en temps réel.
// Appeler cancel pour se désabonner.
func (s *Store) Subscribe() (id int64, ch <-chan Entry, cancel func()) {
	buf := make(chan Entry, 128)
	s.mu.Lock()
	s.nextID++
	id = s.nextID
	s.subscribers[id] = buf
	s.mu.Unlock()
	return id, buf, func() {
		s.mu.Lock()
		delete(s.subscribers, id)
		s.mu.Unlock()
		close(buf)
	}
}

// Search retourne les entrées paginées selon les filtres.
func (s *Store) Search(p SearchParams) ([]Entry, int, error) {
	if p.PageSize <= 0 {
		p.PageSize = 50
	}
	if p.Page <= 0 {
		p.Page = 1
	}
	where, args := buildWhere(p)
	countQ := "SELECT COUNT(*) FROM logs" + where
	var total int
	if err := s.db.QueryRow(countQ, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	offset := (p.Page - 1) * p.PageSize
	q := "SELECT id, ts, level, component, COALESCE(node_name,''), domain, method, path, status, ip, latency_ms, bytes, message FROM logs" +
		where + " ORDER BY id DESC LIMIT ? OFFSET ?"
	rows, err := s.db.Query(q, append(args, p.PageSize, offset)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Level, &e.Component, &e.NodeName, &e.Domain, &e.Method, &e.Path,
			&e.Status, &e.IP, &e.LatencyMs, &e.Bytes, &e.Message); err != nil {
			continue
		}
		e.Ts, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, e)
	}
	if out == nil {
		out = []Entry{}
	}
	return out, total, nil
}

// Export retourne les logs au format csv ou json.
func (s *Store) Export(p SearchParams, format string) ([]byte, string, error) {
	p.Page = 1
	p.PageSize = 100000
	entries, _, err := s.Search(p)
	if err != nil {
		return nil, "", err
	}
	if format == "csv" {
		var sb strings.Builder
		w := csv.NewWriter(&sb)
		w.Write([]string{"id", "ts", "level", "component", "node_name", "domain", "method", "path", "status", "ip", "latency_ms", "bytes", "message"}) //nolint:errcheck
		for _, e := range entries {
			w.Write([]string{ //nolint:errcheck
				strconv.FormatInt(e.ID, 10),
				e.Ts.Format(time.RFC3339),
				e.Level, e.Component, e.NodeName, e.Domain, e.Method, e.Path,
				strconv.Itoa(e.Status), e.IP,
				strconv.FormatInt(e.LatencyMs, 10),
				strconv.FormatInt(e.Bytes, 10),
				e.Message,
			})
		}
		w.Flush()
		return []byte(sb.String()), "text/csv", nil
	}
	b, err := json.MarshalIndent(entries, "", "  ")
	return b, "application/json", err
}

// StreamSSE diffuse les nouvelles entrées en SSE jusqu'à la fermeture de r.Context.
func (s *Store) StreamSSE(w http.ResponseWriter, r *http.Request, filter SearchParams) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE non supporté", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	_, ch, cancel := s.Subscribe()
	defer cancel()

	// Keep-alive : évite les coupures proxy / load-balancer sur flux silencieux.
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		case e, ok := <-ch:
			if !ok {
				return
			}
			if !matchesFilter(e, filter) {
				continue
			}
			b, _ := json.Marshal(e)
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		}
	}
}

func buildWhere(p SearchParams) (string, []any) {
	var clauses []string
	var args []any
	if p.Level != "" {
		clauses = append(clauses, "level=?")
		args = append(args, p.Level)
	}
	if p.Component != "" {
		clauses = append(clauses, "component=?")
		args = append(args, p.Component)
	}
	if p.NodeName != "" {
		clauses = append(clauses, "node_name=?")
		args = append(args, p.NodeName)
	}
	if p.Domain != "" {
		clauses = append(clauses, "domain=?")
		args = append(args, p.Domain)
	}
	if p.IP != "" {
		clauses = append(clauses, "ip=?")
		args = append(args, p.IP)
	}
	if p.Method != "" {
		clauses = append(clauses, "method=?")
		args = append(args, p.Method)
	}
	if p.Status != "" {
		if lo, hi, ok := statusRange(p.Status); ok {
			clauses = append(clauses, "status >= ? AND status < ?")
			args = append(args, lo, hi)
		} else {
			clauses = append(clauses, "status=?")
			args = append(args, p.Status)
		}
	}
	if p.Path != "" {
		clauses = append(clauses, "path LIKE ?")
		args = append(args, "%"+p.Path+"%")
	}
	if p.Search != "" {
		clauses = append(clauses, "(message LIKE ? OR path LIKE ? OR ip LIKE ? OR domain LIKE ?)")
		q := "%" + p.Search + "%"
		args = append(args, q, q, q, q)
	}
	if p.DateFrom != "" {
		clauses = append(clauses, "ts >= ?")
		args = append(args, p.DateFrom)
	}
	if p.DateTo != "" {
		clauses = append(clauses, "ts <= ?")
		args = append(args, p.DateTo)
	}
	switch strings.ToLower(p.Kind) {
	case "access":
		clauses = append(clauses, "status > 0")
	case "system":
		clauses = append(clauses, "status = 0")
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

func matchesFilter(e Entry, p SearchParams) bool {
	if p.Level != "" && e.Level != p.Level {
		return false
	}
	if p.Component != "" && e.Component != p.Component {
		return false
	}
	if p.NodeName != "" && e.NodeName != p.NodeName {
		return false
	}
	if p.Domain != "" && e.Domain != p.Domain {
		return false
	}
	if p.IP != "" && e.IP != p.IP {
		return false
	}
	if p.Method != "" && e.Method != p.Method {
		return false
	}
	if p.Status != "" && !statusMatches(e.Status, p.Status) {
		return false
	}
	if p.Path != "" && !strings.Contains(e.Path, p.Path) {
		return false
	}
	switch strings.ToLower(p.Kind) {
	case "access":
		if e.Status <= 0 {
			return false
		}
	case "system":
		if e.Status != 0 {
			return false
		}
	}
	if p.Search != "" {
		q := strings.ToLower(p.Search)
		if !strings.Contains(strings.ToLower(e.Message), q) &&
			!strings.Contains(strings.ToLower(e.Path), q) &&
			!strings.Contains(e.IP, q) &&
			!strings.Contains(e.Domain, q) {
			return false
		}
	}
	return true
}

// Correlate retourne les logs système/agent proches dans le temps pour un domaine.
// Les logs Agent stockent le nom du conteneur dans domain (pas le host proxy) :
// on matche aussi le message et des variantes du nom (dots → tirets).
func (s *Store) Correlate(domain string, at time.Time, windowSec int) []Entry {
	if windowSec <= 0 {
		windowSec = 30
	}
	from := at.Add(-time.Duration(windowSec) * time.Second).UTC().Format(time.RFC3339Nano)
	to := at.Add(time.Duration(windowSec) * time.Second).UTC().Format(time.RFC3339Nano)
	domainDash := strings.ReplaceAll(domain, ".", "-")
	domainFlat := strings.ReplaceAll(domain, ".", "")
	rows, err := s.db.Query(
		`SELECT id, ts, level, component, node_name, domain, method, path, status, ip, latency_ms, bytes, message
		 FROM logs
		 WHERE ts BETWEEN ? AND ?
		   AND status = 0
		   AND (
		     domain = ? OR domain = '/' || ?
		     OR instr(lower(coalesce(message,'')), lower(?)) > 0
		     OR instr(lower(replace(coalesce(domain,''), '/', '')), lower(?)) > 0
		     OR instr(lower(replace(coalesce(domain,''), '/', '')), lower(?)) > 0
		     OR instr(lower(replace(coalesce(domain,''), '/', '')), lower(?)) > 0
		   )
		 ORDER BY ts DESC LIMIT 100`,
		from, to, domain, domain, domain, domain, domainDash, domainFlat)
	if err != nil {
		return []Entry{}
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var ts string
		if rows.Scan(&e.ID, &ts, &e.Level, &e.Component, &e.NodeName, &e.Domain, &e.Method,
			&e.Path, &e.Status, &e.IP, &e.LatencyMs, &e.Bytes, &e.Message) != nil {
			continue
		}
		e.Ts, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, e)
	}
	if out == nil {
		out = []Entry{}
	}
	return out
}

// StartRetentionLoop lance un nettoyage quotidien des logs anciens.
func (s *Store) StartRetentionLoop(ctx context.Context, getRetentionDays func() int) {
	go func() {
		purge := func() {
			days := getRetentionDays()
			if days <= 0 {
				return
			}
			s.db.Exec( //nolint:errcheck
				`DELETE FROM logs WHERE ts < datetime('now', ?)`,
				fmt.Sprintf("-%d days", days))
		}
		purge()
		t := time.NewTicker(24 * time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				purge()
			}
		}
	}()
}

func nvl(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// statusRange interprète "5xx", "5" ou "502" → [lo, hi).
func statusRange(s string) (lo, hi int, ok bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) == 3 && strings.HasSuffix(s, "xx") {
		base, err := strconv.Atoi(string(s[0]) + "00")
		if err != nil {
			return 0, 0, false
		}
		return base, base + 100, true
	}
	if len(s) == 1 && s[0] >= '1' && s[0] <= '5' {
		base := int(s[0]-'0') * 100
		return base, base + 100, true
	}
	return 0, 0, false
}

func statusMatches(code int, filter string) bool {
	if lo, hi, ok := statusRange(filter); ok {
		return code >= lo && code < hi
	}
	return strconv.Itoa(code) == filter
}
