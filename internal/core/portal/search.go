// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import "strings"

// TargetSearchFields champs indexés par la recherche catalogue (R18).
type TargetSearchFields struct {
	Name      string
	Kind      string
	Source    string
	Host      string
	AgentName string
	Container string
}

// MatchTargetQuery true si q vide ou si un champ contient q (insensible à la casse).
func MatchTargetQuery(f TargetSearchFields, q string) bool {
	q = strings.TrimSpace(strings.ToLower(q))
	if q == "" {
		return true
	}
	hay := strings.ToLower(strings.Join([]string{
		f.Name, f.Kind, f.Source, f.Host, f.AgentName, f.Container,
	}, " "))
	return strings.Contains(hay, q)
}

// SortTargetsFavorites place les IDs favoris en tête (ordre favoris puis reste).
func SortTargetsFavorites[T any](items []T, idFn func(T) string, fav []string) []T {
	if len(items) == 0 || len(fav) == 0 {
		return items
	}
	favItems := make([]T, 0, len(fav))
	rest := make([]T, 0, len(items))
	placed := map[string]bool{}
	for _, id := range fav {
		for _, it := range items {
			if idFn(it) == id {
				favItems = append(favItems, it)
				placed[id] = true
				break
			}
		}
	}
	for _, it := range items {
		if !placed[idFn(it)] {
			rest = append(rest, it)
		}
	}
	return append(favItems, rest...)
}
