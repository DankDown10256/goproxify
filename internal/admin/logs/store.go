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

	"github.com/vincamok/goproxify/internal/admin/gdpr"
)

// Durées de rétention par défaut — modifiables via settings DB (clés logs.retention_access_days,
// logs.retention_system_days, logs.retention_ban_days).
const (
	DefaultRetentionAccessDays  = 365 // logs HTTP (RGPD : 1 an max recommandé)
	DefaultRetentionSystemDays  = 90  // logs système/agent
	DefaultRetentionBanDays     = 730 // entrées de ban (2 ans)
)

// Entry représente une ligne de log.
type Entry struct {
	ID            int64      `json:"id"`
	Ts            time.Time  `json:"ts"`
	Level         string     `json:"level"`
	Component     string     `json:"component"`
	NodeName      string     `json:"node_name,omitempty"`
	Domain        string     `json:"domain"`
	Method        string     `json:"method"`
	Path          string     `json:"path"`
	Status        int        `json:"status"`
	IP            string     `json:"ip"`
	LatencyMs     int64      `json:"latency_ms"`
	Bytes         int64      `json:"bytes"`
	Message       string     `json:"message"`
	Referrer      string     `json:"referrer,omitempty"`
	UserID        string     `json:"user_id,omitempty"`
	RequestID     string     `json:"request_id,omitempty"`
	RetainedUntil *time.Time `json:"retained_until,omitempty"`
	// RealIP est l'IP réelle fournie par le Core en mode pseudonymisation.
	// Elle n'est JAMAIS renvoyée dans les réponses API — uniquement chiffrée en DB.
	RealIP string `json:"-"`
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
	// BeforeID active la pagination par curseur (keyset) : retourne les entrées avec id < BeforeID.
	// Quand > 0, Page est ignoré et aucun COUNT n'est exécuté.
	BeforeID int64
}

// Store gère la persistance et la diffusion des logs.
type Store struct {
	db          *sql.DB
	mu          sync.RWMutex
	subscribers map[int64]chan Entry
	nextID      int64

	// Durées de rétention actives (modifiables sans redémarrage).
	retentionMu         sync.RWMutex
	retentionAccessDays int
	retentionSystemDays int

	// Pseudonymisation RGPD (AES-GCM) — nil si désactivée.
	pseudoMu  sync.RWMutex
	pseudoKey []byte
}

// New crée un Store avec les durées de rétention par défaut.
func New(db *sql.DB) *Store {
	return &Store{
		db:                  db,
		subscribers:         make(map[int64]chan Entry),
		retentionAccessDays: DefaultRetentionAccessDays,
		retentionSystemDays: DefaultRetentionSystemDays,
	}
}

// SetRetention met à jour les durées de rétention sans redémarrage.
// accessDays : logs HTTP (status > 0) ; systemDays : logs système/agent.
// Passer 0 pour laisser la valeur inchangée.
func (s *Store) SetRetention(accessDays, systemDays int) {
	s.retentionMu.Lock()
	defer s.retentionMu.Unlock()
	if accessDays > 0 {
		s.retentionAccessDays = accessDays
	}
	if systemDays > 0 {
		s.retentionSystemDays = systemDays
	}
}

// SetPseudonymizeKey active la pseudonymisation RGPD (AES-GCM).
// Passer nil pour désactiver (les IPs sont alors stockées en clair ou anonymisées côté Core).
func (s *Store) SetPseudonymizeKey(key []byte) {
	s.pseudoMu.Lock()
	s.pseudoKey = key
	s.pseudoMu.Unlock()
}

// RevealIP retourne l'IP réelle d'une entrée pseudonymisée.
// Retourne une erreur si l'entrée n'est pas pseudonymisée ou si le déchiffrement échoue.
func (s *Store) RevealIP(entryID int64) (string, error) {
	var enc string
	err := s.db.QueryRow(`SELECT ip_enc FROM logs WHERE id = ?`, entryID).Scan(&enc)
	if err != nil {
		return "", fmt.Errorf("entrée introuvable : %w", err)
	}
	if enc == "" {
		return "", fmt.Errorf("cette entrée n'est pas pseudonymisée")
	}
	s.pseudoMu.RLock()
	key := s.pseudoKey
	s.pseudoMu.RUnlock()
	if key == nil {
		return "", fmt.Errorf("clé de pseudonymisation non chargée")
	}
	return gdpr.Decrypt(key, enc)
}

func (s *Store) retainedUntil(isAccess bool) time.Time {
	s.retentionMu.RLock()
	defer s.retentionMu.RUnlock()
	days := s.retentionSystemDays
	if isAccess {
		days = s.retentionAccessDays
	}
	return time.Now().UTC().AddDate(0, 0, days)
}

// Write insère une entrée et la diffuse aux abonnés SSE.
func (s *Store) Write(e Entry) {
	if e.Ts.IsZero() {
		e.Ts = time.Now()
	}
	retained := s.retainedUntil(e.Status > 0)
	e.RetainedUntil = &retained

	// Pseudonymisation : chiffrer l'IP réelle si disponible et clé chargée.
	ipEnc := ""
	s.pseudoMu.RLock()
	key := s.pseudoKey
	s.pseudoMu.RUnlock()
	if key != nil && e.RealIP != "" {
		if enc, err := gdpr.Encrypt(key, e.RealIP); err == nil {
			ipEnc = enc
			e.IP = "[pseudonymisé]"
		}
	}

	res, err := s.db.Exec(
		`INSERT INTO logs (ts, level, component, node_name, domain, method, path, status, ip, latency_ms, bytes, message, referrer, user_id, request_id, retained_until, ip_enc)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.Ts.UTC().Format(time.RFC3339Nano),
		nvl(e.Level, "info"), nvl(e.Component, "admin"), e.NodeName,
		e.Domain, e.Method, e.Path, e.Status, e.IP, e.LatencyMs, e.Bytes, e.Message, e.Referrer,
		e.UserID, e.RequestID, retained.Format(time.RFC3339), ipEnc,
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
// Quand p.BeforeID > 0, la pagination est par curseur (keyset) : pas de COUNT, résultat O(1).
// Sinon, un COUNT plafonné à 10 001 est exécuté pour la première page.
// Retourne (entries, hasMore, error).
func (s *Store) Search(p SearchParams) ([]Entry, bool, error) {
	if p.PageSize <= 0 {
		p.PageSize = 50
	}
	where, args := buildWhere(p)

	var q string
	var qArgs []any
	if p.BeforeID > 0 {
		// Keyset : pas d'OFFSET, on filtre directement sur l'id.
		cursorClause := " AND id < ?"
		if where == "" {
			cursorClause = " WHERE id < ?"
		}
		q = "SELECT id, ts, level, component, COALESCE(node_name,''), domain, method, path, status, ip, latency_ms, bytes, message, COALESCE(request_id,'') FROM logs" +
			where + cursorClause + " ORDER BY id DESC LIMIT ?"
		qArgs = append(args, p.BeforeID, p.PageSize)
	} else {
		if p.Page <= 0 {
			p.Page = 1
		}
		offset := (p.Page - 1) * p.PageSize
		q = "SELECT id, ts, level, component, COALESCE(node_name,''), domain, method, path, status, ip, latency_ms, bytes, message, COALESCE(request_id,'') FROM logs" +
			where + " ORDER BY id DESC LIMIT ? OFFSET ?"
		qArgs = append(args, p.PageSize, offset)
	}

	rows, err := s.db.Query(q, qArgs...)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Level, &e.Component, &e.NodeName, &e.Domain, &e.Method, &e.Path,
			&e.Status, &e.IP, &e.LatencyMs, &e.Bytes, &e.Message, &e.RequestID); err != nil {
			continue
		}
		e.Ts, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, e)
	}
	if out == nil {
		out = []Entry{}
	}
	hasMore := len(out) == p.PageSize
	return out, hasMore, nil
}

// Export retourne les logs au format csv ou json.
func (s *Store) Export(p SearchParams, format string) ([]byte, string, error) {
	p.Page = 1
	p.PageSize = 100000
	p.BeforeID = 0
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

// CorrelateByRequestID retourne tous les logs portant le même request_id.
// C'est la corrélation exacte : une requête HTTP → ses logs système associés.
func (s *Store) CorrelateByRequestID(requestID string) []Entry {
	if requestID == "" {
		return []Entry{}
	}
	rows, err := s.db.Query(
		`SELECT id, ts, level, component, COALESCE(node_name,''), domain, method, path, status, ip, latency_ms, bytes, message, COALESCE(request_id,'')
		 FROM logs
		 WHERE request_id = ?
		 ORDER BY ts ASC LIMIT 200`,
		requestID)
	if err != nil {
		return []Entry{}
	}
	defer rows.Close()
	return scanEntries(rows)
}

// Correlate retourne les logs système/agent proches dans le temps pour un domaine.
// Fallback temporel utilisé quand aucun request_id n'est disponible.
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
		`SELECT id, ts, level, component, COALESCE(node_name,''), domain, method, path, status, ip, latency_ms, bytes, message, COALESCE(request_id,'')
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
	return scanEntries(rows)
}

func scanEntries(rows interface {
	Next() bool
	Scan(...any) error
	Close() error
}) []Entry {
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		var ts string
		if rows.Scan(&e.ID, &ts, &e.Level, &e.Component, &e.NodeName, &e.Domain, &e.Method,
			&e.Path, &e.Status, &e.IP, &e.LatencyMs, &e.Bytes, &e.Message, &e.RequestID) != nil {
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

// StartRetentionLoop lance un nettoyage quotidien basé sur retained_until (RGPD).
// onUpdate est appelé à chaque cycle pour récupérer les durées de rétention courantes
// (accessDays, systemDays) depuis les settings — 0 = conserver la valeur actuelle.
func (s *Store) StartRetentionLoop(ctx context.Context, onUpdate func() (accessDays, systemDays int)) {
	go func() {
		purge := func() {
			if onUpdate != nil {
				a, sys := onUpdate()
				s.SetRetention(a, sys)
			}
			// Supprime les entrées dont la date de rétention est dépassée.
			s.db.Exec(`DELETE FROM logs WHERE retained_until IS NOT NULL AND retained_until < datetime('now')`) //nolint:errcheck
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

// DeleteByIP supprime tous les logs d'une IP (droit à l'effacement RGPD).
// Retourne le nombre de lignes supprimées.
func (s *Store) DeleteByIP(ip string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM logs WHERE ip = ?`, ip)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteByUserID supprime tous les logs d'un utilisateur (droit à l'effacement RGPD).
// Retourne le nombre de lignes supprimées.
func (s *Store) DeleteByUserID(userID string) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM logs WHERE user_id = ?`, userID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// RetentionInfo retourne les durées de rétention actives.
func (s *Store) RetentionInfo() (accessDays, systemDays int) {
	s.retentionMu.RLock()
	defer s.retentionMu.RUnlock()
	return s.retentionAccessDays, s.retentionSystemDays
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
