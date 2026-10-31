// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package waf

import (
	"sort"
	"strings"
)

// PlatformIDs rend les règles qui se trompent d'habitude sur la plateforme, et faux si elle est inconnue.
func PlatformIDs(name string) ([]int, bool) {
	ids, ok := platformExcludeIDs[strings.ToLower(strings.TrimSpace(name))]
	return ids, ok
}

// PlatformNames liste les plateformes connues, par ordre alphabétique.
func PlatformNames() []string {
	out := make([]string, 0, len(platformExcludeIDs))
	for n := range platformExcludeIDs {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ResolveExclusions rend les règles exclues par une configuration : exclude_ids et les règles de chaque plateforme nommée. Les noms
// inconnus sont rendus à part.
func ResolveExclusions(excludeIDs []int, platforms []string) (ids []int, unknown []string) {
	seen := map[int]bool{}
	for _, id := range excludeIDs {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for _, p := range platforms {
		list, ok := PlatformIDs(p)
		if !ok {
			unknown = append(unknown, p)
			continue
		}
		for _, id := range list {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}
	sort.Ints(ids)
	return ids, unknown
}
