// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"regexp"
	"strings"
	"sync"
)

var locationRegexCache sync.Map // pattern -> *regexp.Regexp

func getLocationRegex(pattern string) (*regexp.Regexp, bool) {
	if v, ok := locationRegexCache.Load(pattern); ok {
		return v.(*regexp.Regexp), true
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, false
	}
	actual, _ := locationRegexCache.LoadOrStore(pattern, re)
	return actual.(*regexp.Regexp), true
}

func matchLocationRegex(pattern, path string) bool {
	re, ok := getLocationRegex(pattern)
	if !ok {
		return false
	}
	return re.MatchString(path)
}

// ApplyPathRewrite applies a regex replacement template to path.
// Template uses $1, $2 … for capture groups (nginx-style).
// Returns the original path if the pattern does not match or is invalid.
func ApplyPathRewrite(path, pattern, template string) string {
	re, ok := getLocationRegex(pattern)
	if !ok {
		return path
	}
	result := re.ReplaceAllString(path, template)
	if result == "" {
		return path
	}
	return result
}

// MatchLocation retourne la Location la plus spécifique pour le chemin donné,
// selon la priorité nginx : exact > préfixe le plus long > première regex.
// Retourne nil si aucune location ne correspond.
func MatchLocation(route *Route, path string) *Location {
	if route == nil || len(route.Locations) == 0 {
		return nil
	}
	var bestPrefix *Location
	bestPrefixLen := -1

	for i := range route.Locations {
		loc := &route.Locations[i]
		if loc.Path == "" {
			continue
		}
		switch loc.PathType {
		case "exact":
			if path == loc.Path {
				return loc // exact gagne toujours
			}
		case "regex":
			// collecté séparément, testé si aucun préfixe ne gagne
		default: // prefix
			if strings.HasPrefix(path, loc.Path) && len(loc.Path) > bestPrefixLen {
				bestPrefix = loc
				bestPrefixLen = len(loc.Path)
			}
		}
	}
	if bestPrefix != nil {
		return bestPrefix
	}
	// première regex qui correspond
	for i := range route.Locations {
		loc := &route.Locations[i]
		if loc.PathType == "regex" && loc.Path != "" {
			if matchLocationRegex(loc.Path, path) {
				return loc
			}
		}
	}
	return nil
}

// MergeLocation retourne une copie de la route avec les champs non nuls
// de la location appliqués en surcharge. La route originale n'est pas modifiée.
func MergeLocation(route *Route, loc *Location) *Route {
	merged := *route
	if len(loc.Backends) > 0 {
		merged.Backends = loc.Backends
	}
	if loc.RateLimit != nil {
		merged.RateLimit = loc.RateLimit
	}
	if loc.IPFilter != nil {
		merged.IPFilter = loc.IPFilter
	}
	if loc.Headers != nil {
		merged.Headers = loc.Headers
	}
	if loc.CORS != nil {
		merged.CORS = loc.CORS
	}
	if loc.Auth != nil {
		merged.SSO = loc.Auth
	}
	if loc.MaxBodySize > 0 {
		merged.MaxBodySize = loc.MaxBodySize
	}
	if loc.ConnectTimeout > 0 {
		merged.ConnectTimeout = loc.ConnectTimeout
	}
	if loc.ResponseTimeout > 0 {
		merged.ResponseTimeout = loc.ResponseTimeout
	}
	if loc.SendTimeout > 0 {
		merged.SendTimeout = loc.SendTimeout
	}
	if loc.Logging != nil {
		merged.Logging = loc.Logging
	}
	if loc.ErrorPages != nil {
		merged.ErrorPages = loc.ErrorPages
	}
	merged.StripPrefix = ""
	if loc.StripPrefix && loc.Path != "" && loc.PathType != "regex" {
		merged.StripPrefix = loc.Path
	}
	merged.PathRewrite = ""
	merged.PathRewritePattern = ""
	if loc.PathType == "regex" && loc.PathRewrite != "" {
		merged.PathRewrite = loc.PathRewrite
		merged.PathRewritePattern = loc.Path
	}
	return &merged
}

// StripPathPrefix removes a location prefix from an HTTP path.
// "/admin" + "/admin" → "/" ; "/admin/users" + "/admin" → "/users".
// Does not strip a longer segment ("/administrator" stays).
func StripPathPrefix(path, prefix string) string {
	if prefix == "" || prefix == "/" || path == "" {
		return path
	}
	prefix = strings.TrimSuffix(prefix, "/")
	if path == prefix {
		return "/"
	}
	if strings.HasPrefix(path, prefix+"/") {
		out := path[len(prefix):]
		if out == "" {
			return "/"
		}
		return out
	}
	return path
}
