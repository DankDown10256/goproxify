// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
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
					http.Error(w, "403 Forbidden", http.StatusForbidden)
					return
				}
			}

			// 2. JS Challenge
			if jsChallenge {
				if !hasChallengeProof(r, secret) {
					serveChallengeJS(w, r, secret)
					return
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

func hasChallengeProof(r *http.Request, secret string) bool {
	c, err := r.Cookie("_gpx_bot")
	if err != nil || c.Value == "" {
		return false
	}
	parts := strings.SplitN(c.Value, ".", 2)
	if len(parts) != 2 || len(parts[0]) < 16 || parts[1] == "" {
		return false
	}
	return hmac.Equal([]byte(parts[1]), []byte(signChallengeToken(secret, parts[0])))
}

func serveChallengeJS(w http.ResponseWriter, r *http.Request, secret string) {
	token := generateChallengeToken()
	signed := token + "." + signChallengeToken(secret, token)
	redirectJSON, _ := json.Marshal(SafeLocalRedirect(r.URL.RequestURI()))
	tokenJSON, _ := json.Marshal(signed)
	secureAttr := ""
	if CookieSecure(r) {
		secureAttr = "; Secure"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.WriteHeader(http.StatusOK)
	page := `<!DOCTYPE html>
<html>
<head><title>Checking your browser...</title></head>
<body>
<p>Checking your browser, please wait...</p>
<script>
(function(){
  var t = ` + string(tokenJSON) + `;
  document.cookie = "_gpx_bot=" + encodeURIComponent(t) + "; path=/; SameSite=Lax` + secureAttr + `; expires=" +
    new Date(Date.now() + 86400000).toUTCString();
  window.location.href = ` + string(redirectJSON) + `;
})();
</script>
</body>
</html>`
	w.Write([]byte(page)) //nolint:errcheck
}

func signChallengeToken(secret, token string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil))
}

func generateChallengeToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(time.Now().String()))
	}
	return hex.EncodeToString(b)
}
