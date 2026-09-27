// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package scheduler évalue des expressions cron (5 champs : minute heure
// jour-du-mois mois jour-de-semaine) et déclenche des actions du moteur de
// règles à heure fixe, indépendamment de toute condition.
package scheduler

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// field est l'ensemble des valeurs valides pour une position cron (bitset simple).
type field map[int]bool

// Expr est une expression cron 5 champs déjà analysée.
type Expr struct {
	minute, hour, dom, month, dow field
	raw                           string
}

// ParseExpr analyse une expression cron standard à 5 champs :
// minute(0-59) heure(0-23) jour-du-mois(1-31) mois(1-12) jour-de-semaine(0-6, 0=dimanche).
// Chaque champ accepte `*`, une valeur, une liste `a,b,c`, une plage `a-b` et un
// pas `*/n` ou `a-b/n`.
func ParseExpr(expr string) (*Expr, error) {
	parts := strings.Fields(strings.TrimSpace(expr))
	if len(parts) != 5 {
		return nil, fmt.Errorf("expression cron invalide (5 champs attendus, %d reçus) : %q", len(parts), expr)
	}
	minute, err := parseField(parts[0], 0, 59)
	if err != nil {
		return nil, fmt.Errorf("minute : %w", err)
	}
	hour, err := parseField(parts[1], 0, 23)
	if err != nil {
		return nil, fmt.Errorf("heure : %w", err)
	}
	dom, err := parseField(parts[2], 1, 31)
	if err != nil {
		return nil, fmt.Errorf("jour du mois : %w", err)
	}
	month, err := parseField(parts[3], 1, 12)
	if err != nil {
		return nil, fmt.Errorf("mois : %w", err)
	}
	dow, err := parseField(parts[4], 0, 6)
	if err != nil {
		return nil, fmt.Errorf("jour de semaine : %w", err)
	}
	return &Expr{minute: minute, hour: hour, dom: dom, month: month, dow: dow, raw: expr}, nil
}

// Matches indique si t (à la minute près) correspond à l'expression. Comme en
// cron standard, jour-du-mois et jour-de-semaine sont combinés en OR quand les
// deux sont restreints (ni l'un ni l'autre `*`), en AND sinon.
func (e *Expr) Matches(t time.Time) bool {
	if !e.month[int(t.Month())] || !e.minute[t.Minute()] || !e.hour[t.Hour()] {
		return false
	}
	domAll := len(e.dom) == 31
	dowAll := len(e.dow) == 7
	domOK := e.dom[t.Day()]
	dowOK := e.dow[int(t.Weekday())]
	if domAll || dowAll {
		return domOK && dowOK
	}
	return domOK || dowOK
}

// String retourne l'expression d'origine.
func (e *Expr) String() string { return e.raw }

func parseField(s string, min, max int) (field, error) {
	f := field{}
	for _, part := range strings.Split(s, ",") {
		step := 1
		base := part
		if i := strings.Index(part, "/"); i >= 0 {
			base = part[:i]
			n, err := strconv.Atoi(part[i+1:])
			if err != nil || n <= 0 {
				return nil, fmt.Errorf("pas invalide : %q", part)
			}
			step = n
		}
		lo, hi := min, max
		switch {
		case base == "*":
			// lo/hi déjà la plage complète
		case strings.Contains(base, "-"):
			bounds := strings.SplitN(base, "-", 2)
			a, err1 := strconv.Atoi(bounds[0])
			b, err2 := strconv.Atoi(bounds[1])
			if err1 != nil || err2 != nil || a > b {
				return nil, fmt.Errorf("plage invalide : %q", base)
			}
			lo, hi = a, b
		default:
			v, err := strconv.Atoi(base)
			if err != nil {
				return nil, fmt.Errorf("valeur invalide : %q", base)
			}
			lo, hi = v, v
		}
		if lo < min || hi > max {
			return nil, fmt.Errorf("valeur hors bornes [%d-%d] : %q", min, max, part)
		}
		for v := lo; v <= hi; v += step {
			f[v] = true
		}
	}
	return f, nil
}
