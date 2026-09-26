// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/vincamok/goproxify/internal/edge/router"
)

type contextKey int

const varsKey contextKey = iota

var reCache sync.Map // map[string]*regexp.Regexp

func compileVar(pattern string) *regexp.Regexp {
	if v, ok := reCache.Load(pattern); ok {
		return v.(*regexp.Regexp)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}
	reCache.Store(pattern, re)
	return re
}

// ResolveRequestVars resolves RequestVars for a request and stores them in context.
func ResolveRequestVars(vars []router.RequestVar) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if len(vars) == 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resolved := make(map[string]string, len(vars))
			for _, v := range vars {
				resolved[v.Name] = resolveVar(r, v)
			}
			ctx := context.WithValue(r.Context(), varsKey, resolved)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func resolveVar(r *http.Request, v router.RequestVar) string {
	// Extract raw value from source
	var raw string
	switch v.Source {
	case "header":
		raw = r.Header.Get(v.Key)
	case "cookie":
		if c, err := r.Cookie(v.Key); err == nil {
			raw = c.Value
		}
	case "query":
		raw = r.URL.Query().Get(v.Key)
	case "method":
		raw = r.Method
	case "remote_ip":
		raw = clientIP(r)
	case "path":
		raw = r.URL.Path
	default:
		raw = ""
	}

	if len(v.Cases) == 0 {
		if raw == "" {
			return v.Default
		}
		return raw
	}

	for _, c := range v.Cases {
		if c.Regex {
			re := compileVar(c.Pattern)
			if re != nil && re.MatchString(raw) {
				// If Value contains $1/$2 captures, expand them; otherwise return literal.
				if strings.Contains(c.Value, "$") {
					return re.ReplaceAllString(raw, c.Value)
				}
				return c.Value
			}
		} else {
			if raw == c.Pattern {
				return c.Value
			}
		}
	}
	return v.Default
}

// GetRequestVars returns the resolved variables from the context.
func GetRequestVars(ctx context.Context) map[string]string {
	if v, ok := ctx.Value(varsKey).(map[string]string); ok {
		return v
	}
	return nil
}

// ExpandVars substitutes ${name} references in s using the provided vars map.
func ExpandVars(s string, vars map[string]string) string {
	if len(vars) == 0 || !strings.Contains(s, "${") {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); {
		start := strings.Index(s[i:], "${")
		if start == -1 {
			sb.WriteString(s[i:])
			break
		}
		sb.WriteString(s[i : i+start])
		rest := s[i+start+2:]
		end := strings.Index(rest, "}")
		if end == -1 {
			sb.WriteString("${")
			sb.WriteString(rest)
			break
		}
		name := rest[:end]
		if val, ok := vars[name]; ok {
			sb.WriteString(val)
		} else {
			sb.WriteString("${")
			sb.WriteString(name)
			sb.WriteString("}")
		}
		i = i + start + 2 + end + 1
	}
	return sb.String()
}
