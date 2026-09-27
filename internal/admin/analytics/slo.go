// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

import (
	"context"
	"database/sql"
	"strconv"
	"time"
)

// DefaultSLOTarget : objectif de disponibilité (%) tant qu'aucun n'est enregistré.
const DefaultSLOTarget = 99.9

const sloTargetKey = "slo.target"

// sloTargetKeyFor : clé du réglage settings pour une passerelle (override) ou globale (node vide).
func sloTargetKeyFor(node string) string {
	if node == "" {
		return sloTargetKey
	}
	return sloTargetKey + "." + node
}

func loadSetting(ctx context.Context, db *sql.DB, key string) (float64, bool) {
	var raw string
	if db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&raw) != nil {
		return 0, false
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil || !ValidSLOTarget(v) {
		return 0, false
	}
	return v, true
}

// LoadSLOTarget lit l'objectif SLO enregistré (table settings), 99,9 % par défaut.
// node, s'il est fourni, lit d'abord l'objectif propre à cette passerelle (slo.target.<node>),
// avec repli sur l'objectif global si elle n'en a pas.
func LoadSLOTarget(ctx context.Context, db *sql.DB, node ...string) float64 {
	if len(node) > 0 && node[0] != "" {
		if v, ok := loadSetting(ctx, db, sloTargetKeyFor(node[0])); ok {
			return v
		}
	}
	if v, ok := loadSetting(ctx, db, sloTargetKey); ok {
		return v
	}
	return DefaultSLOTarget
}

// HasSLOTargetOverride indique si une passerelle a son propre objectif (distinct du global).
func HasSLOTargetOverride(ctx context.Context, db *sql.DB, node string) bool {
	if node == "" {
		return false
	}
	_, ok := loadSetting(ctx, db, sloTargetKeyFor(node))
	return ok
}

// ValidSLOTarget : entre 90 % et 99,999 % (exclus 100 : un objectif de 100 % n'a pas de budget).
func ValidSLOTarget(v float64) bool { return v >= 90 && v <= 99.999 }

// SaveSLOTarget enregistre l'objectif SLO, global ou propre à une passerelle (node non vide).
func SaveSLOTarget(ctx context.Context, db *sql.DB, v float64, node ...string) error {
	key := sloTargetKey
	if len(node) > 0 && node[0] != "" {
		key = sloTargetKeyFor(node[0])
	}
	_, err := db.ExecContext(ctx,
		`INSERT INTO settings (key, value, updated_at) VALUES (?,?,CURRENT_TIMESTAMP)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP`,
		key, strconv.FormatFloat(v, 'f', -1, 64))
	return err
}

// ClearSLOTarget supprime l'objectif propre à une passerelle (retour à l'objectif global).
func ClearSLOTarget(ctx context.Context, db *sql.DB, node string) error {
	if node == "" {
		return nil
	}
	_, err := db.ExecContext(ctx, `DELETE FROM settings WHERE key=?`, sloTargetKeyFor(node))
	return err
}

// SLO disponibilité (réponses non-5xx) sur une fenêtre glissante, avec budget d'erreur et vitesse de consommation.
type SLO struct {
	Target       float64 `json:"target"` // objectif en % (ex. 99.9)
	Days         int     `json:"days"`
	Requests     int64   `json:"requests"`
	Errors       int64   `json:"errors"` // réponses 5xx
	Availability float64 `json:"availability"`
	BudgetTotal  float64 `json:"budget_total"`     // erreurs tolérées sur la fenêtre
	BudgetLeft   float64 `json:"budget_left_pct"` // 0-100, 0 = épuisé
	Burn1h       float64 `json:"burn_1h"`          // 1 = consommation au rythme exact de l'objectif
	Burn6h       float64 `json:"burn_6h"`
	State        string  `json:"state"` // ok | warning | critical | exhausted
}

func countReqErr(ctx context.Context, db *sql.DB, p Params) (reqs, errs int64) {
	w, args := where(p)
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END),0) FROM logs `+w, args...).Scan(&reqs, &errs)
	return
}

// GetSLO calcule l'SLO sur `days` jours (p.Proxy et p.NodeName filtrent ; p.From/p.To sont ignorés).
// États : critical si la consommation dépasse 14,4× sur 1 h et 6× sur 6 h (budget de 30 j épuisé en ~2 jours),
// warning à 3× sur 6 h, exhausted quand le budget est consommé.
func GetSLO(ctx context.Context, db *sql.DB, p Params, target float64, days int) SLO {
	if target <= 0 {
		target = LoadSLOTarget(ctx, db, p.NodeName)
	} else if !ValidSLOTarget(target) {
		target = DefaultSLOTarget
	}
	if days <= 0 || days > 90 {
		days = 30
	}
	now := time.Now()
	win := p
	win.From, win.To = now.AddDate(0, 0, -days), now
	reqs, errs := countReqErr(ctx, db, win)

	allowed := 1 - target/100
	s := SLO{Target: target, Days: days, Requests: reqs, Errors: errs, Availability: 100, BudgetLeft: 100, BudgetTotal: float64(reqs) * allowed}
	if reqs > 0 {
		s.Availability = 100 - float64(errs)/float64(reqs)*100
		if s.BudgetTotal > 0 {
			s.BudgetLeft = max(0, 100-float64(errs)/s.BudgetTotal*100)
		} else if errs > 0 {
			s.BudgetLeft = 0
		}
	}
	burn := func(d time.Duration) float64 {
		w := p
		w.From, w.To = now.Add(-d), now
		r, e := countReqErr(ctx, db, w)
		if r == 0 {
			return 0
		}
		return float64(e) / float64(r) / allowed
	}
	s.Burn1h, s.Burn6h = burn(time.Hour), burn(6*time.Hour)
	switch {
	case reqs > 0 && s.BudgetLeft == 0:
		s.State = "exhausted"
	case s.Burn1h >= 14.4 && s.Burn6h >= 6:
		s.State = "critical"
	case s.Burn6h >= 3:
		s.State = "warning"
	default:
		s.State = "ok"
	}
	return s
}
