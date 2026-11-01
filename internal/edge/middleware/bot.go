// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/router"
)

var (
	defaultBotSecretOnce sync.Once
	defaultBotSecret     string
)

func processBotSecret() string {
	defaultBotSecretOnce.Do(func() {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			defaultBotSecret = hex.EncodeToString([]byte("goproxify-bot-fallback"))
			return
		}
		defaultBotSecret = hex.EncodeToString(b)
	})
	return defaultBotSecret
}

// BotProtection retourne un middleware de protection bot.
func BotProtection(cfg *router.BotConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil || !cfg.Enabled {
			return next
		}
		mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
		monitor := mode == "monitor" || mode == "log"
		jsChallenge := cfg.JSChallenge || mode == "challenge"
		secret := cfg.ChallengeSecret
		if secret == "" {
			secret = processBotSecret()
		}
		var challenge *botChallenge
		if jsChallenge {
			challenge = newBotChallenge(cfg, secret)
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ua := r.Header.Get("User-Agent")

			// 1. Blacklist User-Agent (liste config + liste intégrée)
			blacklist := cfg.UABlacklist
			if len(blacklist) == 0 {
				blacklist = defaultBotUABlacklist
			}
			if matchesUABlacklist(ua, blacklist) {
				slog.Warn("bot: user-agent blacklist",
					"ua", ua,
					"ip", clientIP(r),
					"uri", r.URL.RequestURI(),
					"monitor", monitor,
				)
				if !monitor {
					metrics.Pipeline.BlockedTotal.WithLabelValues(metrics.HostOf(r), "bot", "ua_blacklist").Inc()
					http.Error(w, "403 Forbidden", http.StatusForbidden)
					return
				}
			}

			// 2. Challenge navigateur (preuve de travail ou captcha)
			if jsChallenge {
				if r.Method == http.MethodPost && r.URL.Path == botChallengePath {
					challenge.handleVerify(w, r)
					return
				}
				if !challenge.isExempt(r.URL.Path) {
					if !challenge.hasProof(r) {
						metrics.Pipeline.BlockedTotal.WithLabelValues(metrics.HostOf(r), "bot", "js_challenge").Inc()
						challenge.serve(w, r)
						return
					}
					stripCookie(r, botCookie)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}

// defaultBotUABlacklist est la blacklist intégrée de bots malveillants.
var defaultBotUABlacklist = []string{
	"sqlmap", "nikto", "nmap", "masscan", "zgrab", "dirbuster",
	"gobuster", "feroxbuster", "nuclei", "wfuzz", "hydra", "medusa",
	"semrushbot", "ahrefsbot", "mj12bot", "dotbot", "petalbot",
	"majestic", "rogerbot", "exabot",
}

func matchesUABlacklist(ua string, blacklist []string) bool {
	uaLow := strings.ToLower(ua)
	for _, entry := range blacklist {
		if strings.Contains(uaLow, strings.ToLower(entry)) {
			return true
		}
	}
	return false
}

// stripCookie retire un cookie de la requête transmise au backend : la preuve ne le concerne pas.
func stripCookie(r *http.Request, name string) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name != name {
			r.AddCookie(c)
		}
	}
}
