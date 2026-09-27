// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logs

// FacetCount : une valeur d'un champ et son nombre d'entrées parmi les logs filtrés.
type FacetCount struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

var facetFields = map[string]string{
	"level":     "level",
	"component": "component",
	"node_name": "node_name",
	"domain":    "domain",
	"method":    "method",
}

// Facets compte les valeurs des champs demandés parmi les entrées filtrées par p (jusqu'à 12
// valeurs les plus fréquentes chacun, valeurs vides ignorées). Sert le panneau de facettes de
// l'explorateur de logs ; p.Level/Component/Domain/Method ne s'excluent pas eux-mêmes du calcul
// (facettage simplifié : les compteurs reflètent l'ensemble déjà filtré, pas les alternatives).
func (s *Store) Facets(p SearchParams, fields []string) (map[string][]FacetCount, error) {
	where, args := buildWhere(p)
	out := map[string][]FacetCount{}
	for _, f := range fields {
		col, ok := facetFields[f]
		if !ok {
			continue
		}
		clause := " WHERE " + col + " != ''"
		if where != "" {
			clause = where + " AND " + col + " != ''"
		}
		rows, err := s.db.Query(
			`SELECT `+col+`, COUNT(*) AS n FROM logs`+clause+
				` GROUP BY `+col+` ORDER BY n DESC LIMIT 12`, args...)
		if err != nil {
			return nil, err
		}
		var counts []FacetCount
		for rows.Next() {
			var c FacetCount
			if rows.Scan(&c.Value, &c.Count) == nil {
				counts = append(counts, c)
			}
		}
		rows.Close()
		out[f] = counts
	}
	return out, nil
}
