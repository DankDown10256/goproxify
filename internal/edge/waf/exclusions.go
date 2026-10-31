// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package waf

import (
	"fmt"
	"sort"
	"strings"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// Exclusions par chemin : exclude_ids retire des règles pour tout le proxy, ce qui laisse sans défense toute
// la partie de l'application où elles ne se trompaient pas. Une exclusion par chemin ne retire la règle que là où elle se trompe
// (l'éditeur de contenu d'un CMS, une console d'administration) et la laisse active partout ailleurs.

// pathExclusion est une exclusion compilée : les préfixes de chemin et les règles qu'elle retire sous eux.
type pathExclusion struct {
	paths []string
	ids   []int
}

// compileExclusions résout les règles de chaque exclusion (rule_ids et plateforme). Une exclusion sans chemin ou sans règle est
// ignorée : sans chemin elle vaudrait pour tout le proxy, ce que ValidateConfig refuse.
func compileExclusions(list []router.WAFExclusion) []pathExclusion {
	var out []pathExclusion
	for _, ex := range list {
		if len(ex.Paths) == 0 {
			continue
		}
		var platforms []string
		if ex.Platform != "" {
			platforms = []string{ex.Platform}
		}
		ids, _ := ResolveExclusions(ex.RuleIDs, platforms)
		if len(ids) == 0 {
			continue
		}
		out = append(out, pathExclusion{paths: ex.Paths, ids: ids})
	}
	return out
}

// MatchPath dit si path est sous le préfixe p, sur une frontière de segment.
func MatchPath(path, p string) bool {
	// « / » couvrirait tout le proxy : ce n'est pas une exclusion par chemin (la validation le refuse, le moteur l'ignore).
	if p == "" || p == "/" || p[0] != '/' {
		return false
	}
	if strings.HasSuffix(p, "/") {
		return strings.HasPrefix(path, p) || path == strings.TrimSuffix(p, "/")
	}
	return path == p || strings.HasPrefix(path, p+"/")
}

// excludeForPath rend les règles exclues pour ce chemin : celles du proxy entier plus celles des exclusions dont un préfixe le couvre.
// Sans exclusion par chemin, rend base telle quelle (aucun coût par requête).
func excludeForPath(base []int, excl []pathExclusion, path string) []int {
	if len(excl) == 0 {
		return base
	}
	var out []int
	for _, ex := range excl {
		for _, p := range ex.paths {
			if MatchPath(path, p) {
				if out == nil {
					out = append(out, base...)
				}
				out = append(out, ex.ids...)
				break
			}
		}
	}
	if out == nil {
		return base
	}
	return out
}

// ValidateConfig rend les erreurs de configuration du WAF d'un proxy que le moteur ne sait pas lire : une exclusion par chemin sans
// chemin (elle vaudrait pour tout le proxy), un chemin qui ne commence pas par /, une plateforme inconnue, une exclusion sans règle.
func ValidateConfig(cfg *router.WAFConfig) []string {
	if cfg == nil {
		return nil
	}
	var errs []string
	for i, ex := range cfg.Exclusions {
		where := fmt.Sprintf("waf.exclusions[%d]", i)
		if len(ex.Paths) == 0 {
			errs = append(errs, where+" : au moins un chemin est requis (sans chemin, utilisez exclude_ids, qui vaut pour tout le proxy)")
		}
		for _, p := range ex.Paths {
			if !strings.HasPrefix(p, "/") {
				errs = append(errs, fmt.Sprintf("%s : le chemin %q doit commencer par /", where, p))
			}
			if p == "/" {
				errs = append(errs, where+" : le chemin / couvre tout le proxy, utilisez exclude_ids")
			}
		}
		if ex.Platform != "" {
			if _, ok := PlatformIDs(ex.Platform); !ok {
				errs = append(errs, fmt.Sprintf("%s : plateforme %q inconnue (%s)", where, ex.Platform, strings.Join(PlatformNames(), ", ")))
			}
		}
		if len(ex.RuleIDs) == 0 && ex.Platform == "" {
			errs = append(errs, where+" : rule_ids ou platform est requis")
		}
		for _, id := range ex.RuleIDs {
			if id <= 0 {
				errs = append(errs, fmt.Sprintf("%s : identifiant de règle %d invalide", where, id))
			}
		}
	}
	sort.Strings(errs)
	return errs
}
