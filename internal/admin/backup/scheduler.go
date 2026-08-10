// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package backup gère les snapshots planifiés et la rétention de l'Administration.
package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/importer"
)

// MaxSchedules est le nombre maximum de planifications distinctes.
const MaxSchedules = 5

// Fréquences lisibles (stockées en JSON, converties en cron à l'exécution).
const (
	FreqDaily   = "daily"
	FreqWeekly  = "weekly"
	FreqMonthly = "monthly"
	FreqYearly  = "yearly"
	FreqCustom  = "custom" // expression cron libre (avancé)
)

// Schedule configure une planification + rétention associée.
type Schedule struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	Frequency string `json:"frequency"` // daily|weekly|monthly|yearly|custom
	Hour      int    `json:"hour"`      // 0–23
	Minute    int    `json:"minute"`    // 0–59
	Weekday   int    `json:"weekday"`   // 0=dim … 6=sam (weekly)
	MonthDay  int    `json:"month_day"` // 1–28 (monthly / yearly)
	Month     int    `json:"month"`     // 1–12 (yearly)
	Cron      string `json:"cron"`      // utilisé si frequency=custom
	Retention int    `json:"retention"` // max snapshots pour CETTE planification (0 = illimité)
}

// ScheduleConfig regroupe jusqu'à MaxSchedules planifications.
type ScheduleConfig struct {
	Schedules []Schedule `json:"schedules"`
	Max       int        `json:"max"`
}

// DefaultSchedule retourne une planification quotidienne désactivée.
func DefaultSchedule() Schedule {
	return Schedule{
		ID:        uuid.New().String(),
		Name:      "Quotidienne",
		Enabled:   false,
		Frequency: FreqDaily,
		Hour:      3,
		Minute:    0,
		Weekday:   0,
		MonthDay:  1,
		Month:     1,
		Retention: 7,
	}
}

// DefaultConfig retourne une config vide (l'utilisateur ajoute des planifications).
func DefaultConfig() ScheduleConfig {
	return ScheduleConfig{Schedules: []Schedule{}, Max: MaxSchedules}
}

// Snapshot représente une sauvegarde stockée.
type Snapshot struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	ScheduleID string    `json:"schedule_id,omitempty"`
	SizeBytes  int64     `json:"size_bytes"`
	CreatedAt  time.Time `json:"created_at"`
}

// Scheduler orchestre les sauvegardes planifiées.
type Scheduler struct {
	db   *sql.DB
	log  *slog.Logger
	mu   sync.Mutex
	wake chan struct{}
}

// New crée un Scheduler.
func New(db *sql.DB, log *slog.Logger) *Scheduler {
	return &Scheduler{
		db:   db,
		log:  log,
		wake: make(chan struct{}, 1),
	}
}

// Start lance la boucle de planification en arrière-plan.
func (s *Scheduler) Start(ctx context.Context) {
	go s.loop(ctx)
}

func (s *Scheduler) notify() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Scheduler) loop(ctx context.Context) {
	lastFired := map[string]time.Time{}
	for {
		cfg := s.GetConfig()
		now := time.Now()
		var (
			nextAt  time.Time
			hasNext bool
		)

		for _, sch := range cfg.Schedules {
			if !sch.Enabled {
				continue
			}
			cronExpr, err := sch.CronExpr()
			if err != nil || cronExpr == "" {
				if err != nil {
					s.log.Warn("backup: planification invalide", "id", sch.ID, "name", sch.Name, "err", err)
				}
				continue
			}
			from := now
			if t, ok := lastFired[sch.ID]; ok && t.After(from.Add(-time.Second)) {
				from = t
			}
			next, err := nextCron(cronExpr, from)
			if err != nil {
				s.log.Warn("backup: cron invalide", "id", sch.ID, "cron", cronExpr, "err", err)
				continue
			}
			if !hasNext || next.Before(nextAt) {
				nextAt = next
				hasNext = true
			}
		}

		if !hasNext {
			select {
			case <-ctx.Done():
				return
			case <-s.wake:
				continue
			case <-time.After(time.Minute):
				continue
			}
		}

		wait := time.Until(nextAt)
		if wait < 0 {
			wait = 0
		}
		s.log.Info("backup: prochaine sauvegarde planifiée", "at", nextAt.Format(time.RFC3339))

		select {
		case <-ctx.Done():
			return
		case <-s.wake:
			continue
		case <-time.After(wait):
		}

		// Recharge et déclenche toutes les planifications dues à cette minute.
		fireAt := time.Now()
		cfg = s.GetConfig()
		for _, sch := range cfg.Schedules {
			if !sch.Enabled {
				continue
			}
			cronExpr, err := sch.CronExpr()
			if err != nil || cronExpr == "" {
				continue
			}
			from := fireAt.Add(-time.Second)
			if t, ok := lastFired[sch.ID]; ok {
				from = t
			}
			next, err := nextCron(cronExpr, from)
			if err != nil {
				continue
			}
			// Dû si la prochaine occurrence calculée depuis le dernier tir est ≤ maintenant.
			if next.After(fireAt) {
				continue
			}
			name := snapshotName(sch, fireAt)
			if err := s.TakeSnapshot(name, sch.ID, sch.Retention); err != nil {
				s.log.Error("backup: snapshot planifié échoué", "schedule", sch.Name, "err", err)
			} else {
				lastFired[sch.ID] = fireAt.Truncate(time.Minute)
			}
		}
	}
}

func snapshotName(sch Schedule, t time.Time) string {
	slug := slugify(sch.Name)
	if slug == "" {
		slug = "auto"
	}
	return fmt.Sprintf("%s-%s", slug, t.Format("20060102-150405"))
}

func slugify(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	prevDash := false
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

// CronExpr construit l'expression cron 5 champs à partir de la fréquence lisible.
func (sch Schedule) CronExpr() (string, error) {
	h, m := sch.Hour, sch.Minute
	if h < 0 || h > 23 {
		return "", fmt.Errorf("heure invalide (%d)", h)
	}
	if m < 0 || m > 59 {
		return "", fmt.Errorf("minute invalide (%d)", m)
	}
	switch sch.Frequency {
	case FreqDaily, "":
		return fmt.Sprintf("%d %d * * *", m, h), nil
	case FreqWeekly:
		wd := sch.Weekday
		if wd < 0 || wd > 6 {
			return "", fmt.Errorf("jour de semaine invalide (%d)", wd)
		}
		return fmt.Sprintf("%d %d * * %d", m, h, wd), nil
	case FreqMonthly:
		dom := sch.MonthDay
		if dom < 1 || dom > 28 {
			return "", fmt.Errorf("jour du mois invalide (%d), utiliser 1–28", dom)
		}
		return fmt.Sprintf("%d %d %d * *", m, h, dom), nil
	case FreqYearly:
		dom := sch.MonthDay
		mon := sch.Month
		if dom < 1 || dom > 28 {
			return "", fmt.Errorf("jour du mois invalide (%d), utiliser 1–28", dom)
		}
		if mon < 1 || mon > 12 {
			return "", fmt.Errorf("mois invalide (%d)", mon)
		}
		return fmt.Sprintf("%d %d %d %d *", m, h, dom, mon), nil
	case FreqCustom:
		expr := strings.TrimSpace(sch.Cron)
		if expr == "" {
			return "", fmt.Errorf("expression cron manquante")
		}
		if _, err := nextCron(expr, time.Now()); err != nil {
			return "", err
		}
		return expr, nil
	default:
		return "", fmt.Errorf("fréquence inconnue %q", sch.Frequency)
	}
}

// GetConfig retourne la configuration courante (migre l'ancien format mono-planning).
func (s *Scheduler) GetConfig() ScheduleConfig {
	var raw string
	s.db.QueryRow(`SELECT value FROM backup_schedule WHERE key='schedule'`).Scan(&raw) //nolint:errcheck
	cfg := DefaultConfig()
	if raw == "" || raw == "{}" {
		return cfg
	}

	// Nouveau format : {"schedules":[...]}
	var modern struct {
		Schedules []Schedule `json:"schedules"`
	}
	if err := json.Unmarshal([]byte(raw), &modern); err == nil && modern.Schedules != nil {
		cfg.Schedules = normalizeSchedules(modern.Schedules)
		return cfg
	}

	// Ancien format : {"enabled":…,"cron":…,"retention":…}
	var legacy struct {
		Enabled   bool   `json:"enabled"`
		Cron      string `json:"cron"`
		Retention int    `json:"retention"`
	}
	if err := json.Unmarshal([]byte(raw), &legacy); err == nil && legacy.Cron != "" {
		sch := migrateLegacy(legacy.Enabled, legacy.Cron, legacy.Retention)
		cfg.Schedules = []Schedule{sch}
		return cfg
	}

	return cfg
}

func migrateLegacy(enabled bool, cron string, retention int) Schedule {
	sch := DefaultSchedule()
	sch.Enabled = enabled
	sch.Cron = cron
	if retention > 0 {
		sch.Retention = retention
	}
	h, m, freq, wd, dom, mon := parseCronToReadable(cron)
	sch.Hour, sch.Minute = h, m
	sch.Frequency = freq
	sch.Weekday = wd
	sch.MonthDay = dom
	sch.Month = mon
	switch freq {
	case FreqDaily:
		sch.Name = "Quotidienne"
	case FreqWeekly:
		sch.Name = "Hebdomadaire"
	case FreqMonthly:
		sch.Name = "Mensuelle"
	case FreqYearly:
		sch.Name = "Annuelle"
	default:
		sch.Name = "Personnalisée"
		sch.Frequency = FreqCustom
	}
	return sch
}

// parseCronToReadable tente de reconnaître un cron simple (quotidien/hebdo/mensuel/annuel).
func parseCronToReadable(cron string) (hour, minute int, freq string, weekday, monthDay, month int) {
	hour, minute = 3, 0
	freq = FreqCustom
	weekday, monthDay, month = 0, 1, 1
	fields := strings.Fields(cron)
	if len(fields) != 5 {
		return
	}
	mi, err1 := strconv.Atoi(fields[0])
	ho, err2 := strconv.Atoi(fields[1])
	if err1 != nil || err2 != nil {
		return
	}
	minute, hour = mi, ho
	dom, mon, dow := fields[2], fields[3], fields[4]
	switch {
	case dom == "*" && mon == "*" && dow == "*":
		freq = FreqDaily
	case dom == "*" && mon == "*" && dow != "*":
		wd, err := strconv.Atoi(dow)
		if err != nil {
			return
		}
		if wd == 7 {
			wd = 0
		}
		if wd < 0 || wd > 6 {
			return
		}
		freq = FreqWeekly
		weekday = wd
	case dom != "*" && mon == "*" && dow == "*":
		d, err := strconv.Atoi(dom)
		if err != nil || d < 1 || d > 28 {
			return
		}
		freq = FreqMonthly
		monthDay = d
	case dom != "*" && mon != "*" && dow == "*":
		d, err1 := strconv.Atoi(dom)
		m, err2 := strconv.Atoi(mon)
		if err1 != nil || err2 != nil || d < 1 || d > 28 || m < 1 || m > 12 {
			return
		}
		freq = FreqYearly
		monthDay = d
		month = m
	}
	return
}

func normalizeSchedules(in []Schedule) []Schedule {
	out := make([]Schedule, 0, len(in))
	for _, sch := range in {
		if len(out) >= MaxSchedules {
			break
		}
		if sch.ID == "" {
			sch.ID = uuid.New().String()
		}
		if sch.Frequency == "" {
			if sch.Cron != "" {
				sch.Frequency = FreqCustom
			} else {
				sch.Frequency = FreqDaily
			}
		}
		if sch.Name == "" {
			sch.Name = "Planification"
		}
		if sch.MonthDay == 0 {
			sch.MonthDay = 1
		}
		if sch.Month == 0 {
			sch.Month = 1
		}
		if sch.Retention < 0 {
			sch.Retention = 0
		}
		out = append(out, sch)
	}
	return out
}

// GetSchedule est conservé pour compat : retourne la première planification ou un défaut.
func (s *Scheduler) GetSchedule() Schedule {
	cfg := s.GetConfig()
	if len(cfg.Schedules) == 0 {
		return DefaultSchedule()
	}
	return cfg.Schedules[0]
}

// SaveConfig persiste jusqu'à MaxSchedules planifications et réveille le scheduler.
func (s *Scheduler) SaveConfig(cfg ScheduleConfig) error {
	if len(cfg.Schedules) > MaxSchedules {
		return fmt.Errorf("maximum %d planifications", MaxSchedules)
	}
	normalized := normalizeSchedules(cfg.Schedules)
	for i := range normalized {
		if _, err := normalized[i].CronExpr(); err != nil {
			return fmt.Errorf("planification %q : %w", normalized[i].Name, err)
		}
	}
	payload := ScheduleConfig{Schedules: normalized, Max: MaxSchedules}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR REPLACE INTO backup_schedule (key, value) VALUES ('schedule', ?)`, string(b))
	if err != nil {
		return err
	}
	s.notify()
	return nil
}

// SaveSchedule persiste une config mono-planning (compat) en la convertissant.
func (s *Scheduler) SaveSchedule(sched Schedule) error {
	if sched.ID == "" {
		sched.ID = uuid.New().String()
	}
	if sched.Frequency == "" && sched.Cron != "" {
		sched.Frequency = FreqCustom
	}
	return s.SaveConfig(ScheduleConfig{Schedules: []Schedule{sched}})
}

// TakeSnapshot crée un snapshot immédiat. scheduleID/retention optionnels (manuel = "", 0).
func (s *Scheduler) TakeSnapshot(name string, scheduleID string, retention int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	bk, err := importer.ExportBackup(s.db)
	if err != nil {
		return fmt.Errorf("export: %w", err)
	}
	importer.RedactSecrets(bk)
	data, err := json.Marshal(bk)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	data, err = sealSnapshot(data)
	if err != nil {
		return fmt.Errorf("chiffrer: %w", err)
	}

	id := uuid.New().String()
	_, err = s.db.Exec(
		`INSERT INTO backup_snapshots (id, name, schedule_id, size, data) VALUES (?, ?, ?, ?, ?)`,
		id, name, scheduleID, len(data), string(data))
	if err != nil {
		return fmt.Errorf("insert: %w", err)
	}

	if scheduleID != "" && retention > 0 {
		s.pruneSchedule(scheduleID, retention)
	}

	s.log.Info("backup: snapshot créé", "id", id, "name", name, "bytes", len(data), "schedule_id", scheduleID)
	return nil
}

func (s *Scheduler) pruneSchedule(scheduleID string, keep int) {
	// Sous-requête imbriquée : SQLite exige cela pour DELETE + LIMIT sur la même table.
	_, err := s.db.Exec(
		`DELETE FROM backup_snapshots WHERE schedule_id = ? AND id NOT IN (
			SELECT id FROM (
				SELECT id FROM backup_snapshots WHERE schedule_id = ? ORDER BY created_at DESC LIMIT ?
			)
		)`, scheduleID, scheduleID, keep)
	if err != nil {
		s.log.Warn("backup: prune échoué", "schedule_id", scheduleID, "err", err)
	}
}

// ListSnapshots retourne la liste des snapshots (sans les données).
func (s *Scheduler) ListSnapshots() []Snapshot {
	rows, err := s.db.Query(
		`SELECT id, name, COALESCE(schedule_id,''), size, created_at FROM backup_snapshots ORDER BY created_at DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Snapshot
	for rows.Next() {
		var snap Snapshot
		var ts string
		if rows.Scan(&snap.ID, &snap.Name, &snap.ScheduleID, &snap.SizeBytes, &ts) != nil {
			continue
		}
		snap.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", ts)
		if snap.CreatedAt.IsZero() {
			snap.CreatedAt, _ = time.Parse(time.RFC3339, ts)
		}
		out = append(out, snap)
	}
	if out == nil {
		out = []Snapshot{}
	}
	return out
}

// GetSnapshotData retourne le JSON brut d'un snapshot (déchiffré si besoin).
func (s *Scheduler) GetSnapshotData(id string) ([]byte, string, error) {
	var data, name string
	err := s.db.QueryRow(`SELECT data, name FROM backup_snapshots WHERE id=?`, id).Scan(&data, &name)
	if err == sql.ErrNoRows {
		return nil, "", fmt.Errorf("snapshot introuvable")
	}
	if err != nil {
		return nil, "", err
	}
	plain, err := openSnapshot([]byte(data))
	if err != nil {
		return nil, "", err
	}
	return plain, name, nil
}

// DeleteSnapshot supprime un snapshot.
func (s *Scheduler) DeleteSnapshot(id string) error {
	res, err := s.db.Exec(`DELETE FROM backup_snapshots WHERE id=?`, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("snapshot introuvable")
	}
	return nil
}

// ── Proxy history ─────────────────────────────────────────────────────────────

// ProxyVersion représente une version sauvegardée d'un proxy.
type ProxyVersion struct {
	ID        string    `json:"id"`
	ProxyID   string    `json:"proxy_id"`
	Config    string    `json:"config"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
}

// SaveProxyVersion enregistre la config courante d'un proxy dans l'historique.
func (s *Scheduler) SaveProxyVersion(db *sql.DB, proxyID, configJSON, note string) {
	id := uuid.New().String()
	db.Exec( //nolint:errcheck
		`INSERT INTO proxy_history (id, proxy_id, config, note) VALUES (?, ?, ?, ?)`,
		id, proxyID, configJSON, note)
	db.Exec( //nolint:errcheck
		`DELETE FROM proxy_history WHERE proxy_id=? AND id NOT IN (
			SELECT id FROM (
				SELECT id FROM proxy_history WHERE proxy_id=? ORDER BY created_at DESC LIMIT 50
			)
		)`, proxyID, proxyID)
}

// ListProxyVersions retourne l'historique d'un proxy (sans la config complète).
func (s *Scheduler) ListProxyVersions(db *sql.DB, proxyID string) []ProxyVersion {
	rows, err := db.Query(
		`SELECT id, proxy_id, note, created_at FROM proxy_history WHERE proxy_id=? ORDER BY created_at DESC LIMIT 50`,
		proxyID)
	if err != nil {
		return []ProxyVersion{}
	}
	defer rows.Close()
	var out []ProxyVersion
	for rows.Next() {
		var v ProxyVersion
		var ts string
		if rows.Scan(&v.ID, &v.ProxyID, &v.Note, &ts) != nil {
			continue
		}
		v.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", ts)
		if v.CreatedAt.IsZero() {
			v.CreatedAt, _ = time.Parse(time.RFC3339, ts)
		}
		out = append(out, v)
	}
	if out == nil {
		out = []ProxyVersion{}
	}
	return out
}

// GetProxyVersion retourne une version spécifique avec sa config.
func (s *Scheduler) GetProxyVersion(db *sql.DB, versionID string) (*ProxyVersion, error) {
	var v ProxyVersion
	var ts string
	err := db.QueryRow(
		`SELECT id, proxy_id, config, note, created_at FROM proxy_history WHERE id=?`, versionID,
	).Scan(&v.ID, &v.ProxyID, &v.Config, &v.Note, &ts)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("version introuvable")
	}
	v.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", ts)
	return &v, err
}

// ── Cron minimal ─────────────────────────────────────────────────────────────

// nextCron calcule la prochaine occurrence d'une expression cron 5-champs depuis `from`.
func nextCron(expr string, from time.Time) (time.Time, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return time.Time{}, fmt.Errorf("cron: 5 champs requis")
	}
	type cronField struct {
		vals []int
		any  bool
	}
	parse := func(field string, min, max int) (cronField, error) {
		if field == "*" {
			return cronField{any: true}, nil
		}
		var cf cronField
		for _, part := range strings.Split(field, ",") {
			if strings.Contains(part, "-") {
				bounds := strings.SplitN(part, "-", 2)
				lo, err1 := strconv.Atoi(bounds[0])
				hi, err2 := strconv.Atoi(bounds[1])
				if err1 != nil || err2 != nil || lo < min || hi > max {
					return cronField{}, fmt.Errorf("cron: plage invalide %q", part)
				}
				for v := lo; v <= hi; v++ {
					cf.vals = append(cf.vals, v)
				}
			} else if strings.Contains(part, "*/") {
				step, err := strconv.Atoi(strings.TrimPrefix(part, "*/"))
				if err != nil || step <= 0 {
					return cronField{}, fmt.Errorf("cron: pas invalide %q", part)
				}
				for v := min; v <= max; v += step {
					cf.vals = append(cf.vals, v)
				}
			} else {
				v, err := strconv.Atoi(part)
				if err != nil || v < min || v > max {
					return cronField{}, fmt.Errorf("cron: valeur invalide %q", part)
				}
				cf.vals = append(cf.vals, v)
			}
		}
		return cf, nil
	}
	match := func(cf cronField, v int) bool {
		if cf.any {
			return true
		}
		for _, x := range cf.vals {
			if x == v {
				return true
			}
		}
		return false
	}
	matchDow := func(cf cronField, weekday int) bool {
		if cf.any {
			return true
		}
		for _, x := range cf.vals {
			// Cron : 0 et 7 = dimanche
			if x == 7 {
				x = 0
			}
			if x == weekday {
				return true
			}
		}
		return false
	}
	mins, err := parse(fields[0], 0, 59)
	if err != nil {
		return time.Time{}, err
	}
	hours, err := parse(fields[1], 0, 23)
	if err != nil {
		return time.Time{}, err
	}
	doms, err := parse(fields[2], 1, 31)
	if err != nil {
		return time.Time{}, err
	}
	months, err := parse(fields[3], 1, 12)
	if err != nil {
		return time.Time{}, err
	}
	dows, err := parse(fields[4], 0, 7)
	if err != nil {
		return time.Time{}, err
	}

	t := from.Truncate(time.Minute).Add(time.Minute)
	for i := 0; i < 525601; i++ {
		dow := int(t.Weekday()) // 0=Sunday
		if match(months, int(t.Month())) &&
			match(doms, t.Day()) &&
			matchDow(dows, dow) &&
			match(hours, t.Hour()) &&
			match(mins, t.Minute()) {
			return t, nil
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}, fmt.Errorf("cron: aucune occurrence trouvée dans l'année à venir")
}
