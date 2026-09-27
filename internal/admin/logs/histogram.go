// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logs

import "strings"

// HistPoint compte les entrées d'une tranche de temps, par niveau.
type HistPoint struct {
	Bucket string `json:"bucket"` // heure locale du serveur : AAAA-MM-JJTHH:MM (minute), THH:00 (heure) ou AAAA-MM-JJ (jour)
	Total  int64  `json:"total"`
	Warn   int64  `json:"warn"`
	Error  int64  `json:"error"`
}

// BucketFormat retourne le format strftime d'une tranche (« minute », « day » ou heure par défaut).
func BucketFormat(bucket string) string {
	switch strings.ToLower(bucket) {
	case "minute":
		return "%Y-%m-%dT%H:%M"
	case "day":
		return "%Y-%m-%d"
	}
	return "%Y-%m-%dT%H:00"
}

// Histogram répartit les entrées filtrées par tranche de temps et niveau (warn, error ; le reste = info/debug).
func (s *Store) Histogram(p SearchParams, bucket string) ([]HistPoint, error) {
	where, args := buildWhere(p)
	rows, err := s.db.Query(
		`SELECT strftime('`+BucketFormat(bucket)+`', ts, 'localtime') AS b, COUNT(*),
		        SUM(CASE WHEN level IN ('warn','warning') THEN 1 ELSE 0 END),
		        SUM(CASE WHEN level = 'error' THEN 1 ELSE 0 END)
		 FROM logs`+where+` GROUP BY b ORDER BY b`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HistPoint{}
	for rows.Next() {
		var h HistPoint
		if rows.Scan(&h.Bucket, &h.Total, &h.Warn, &h.Error) == nil && h.Bucket != "" {
			out = append(out, h)
		}
	}
	return out, nil
}
