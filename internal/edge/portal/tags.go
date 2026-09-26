// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

// CatalogVisible applique R9–R10 :
// - destination sans tags → visible pour tout user authentifié ;
// - destination avec tags → visible ssi intersection non vide avec les tags user ;
// - user sans tags → uniquement les destinations sans tags.
func CatalogVisible(userTags, destTags []string) bool {
	if len(destTags) == 0 {
		return true
	}
	if len(userTags) == 0 {
		return false
	}
	set := make(map[string]struct{}, len(userTags))
	for _, t := range userTags {
		if t == "" {
			continue
		}
		set[t] = struct{}{}
	}
	if len(set) == 0 {
		return false
	}
	for _, t := range destTags {
		if t == "" {
			continue
		}
		if _, ok := set[t]; ok {
			return true
		}
	}
	return false
}

// FilterCatalog retourne les destinations visibles pour userTags.
func FilterCatalog(items []CatalogTarget, userTags []string) []CatalogTarget {
	out := make([]CatalogTarget, 0, len(items))
	for _, c := range items {
		if CatalogVisible(userTags, c.Tags) {
			out = append(out, c)
		}
	}
	return out
}
