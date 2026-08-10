// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ws

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	replayWindow  = 5 * time.Minute
	hmacHeader    = "X-Goproxify-Signature"
	joinTokenHeader = "X-Join-Token"
	agentHMACHeader = "X-Agent-HMAC"
)

// ValidateAdminHMAC valide la signature HMAC-SHA256 du handshake Admin→Core.
// Format du header : "hmac-sha256 <timestamp_unix>.<hex_sig>"
// La signature couvre : "<timestamp>:<method>:<path>"
// Fenêtre anti-replay : ±5 minutes.
func ValidateAdminHMAC(r *http.Request, secret string) error {
	if secret == "" {
		return fmt.Errorf("HMAC non configuré")
	}
	raw := r.Header.Get(hmacHeader)
	if raw == "" {
		return fmt.Errorf("header %s manquant", hmacHeader)
	}
	parts := strings.SplitN(raw, " ", 2)
	if len(parts) != 2 || parts[0] != "hmac-sha256" {
		return fmt.Errorf("format de signature invalide")
	}
	fields := strings.SplitN(parts[1], ".", 2)
	if len(fields) != 2 {
		return fmt.Errorf("format timestamp.sig invalide")
	}
	ts, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return fmt.Errorf("timestamp invalide")
	}
	now := time.Now().Unix()
	if abs(now-ts) > int64(replayWindow.Seconds()) {
		return fmt.Errorf("timestamp hors fenêtre replay (±5 min)")
	}
	data := fmt.Sprintf("%d:%s:%s", ts, r.Method, r.URL.Path)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(fields[1])) {
		return fmt.Errorf("signature HMAC invalide")
	}
	return nil
}

// ExtractJoinToken extrait le JOIN_TOKEN du header WS upgrade.
func ExtractJoinToken(r *http.Request) string {
	return r.Header.Get(joinTokenHeader)
}

// ExtractAgentHMAC extrait le secret HMAC rotatif de l'Agent.
func ExtractAgentHMAC(r *http.Request) string {
	return r.Header.Get(agentHMACHeader)
}

// GenerateAgentHMAC génère un nouveau secret HMAC de 32 octets encodé en hex.
func GenerateAgentHMAC() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ValidateAgentHMAC vérifie que le secret HMAC Agent est valide.
// Pour simplifier la vérification côté Core, on compare directement les secrets stockés.
func ValidateAgentHMAC(provided, stored string) bool {
	return hmac.Equal([]byte(provided), []byte(stored))
}

// BuildAdminSignature construit le header HMAC-SHA256 pour un client Admin.
// À utiliser côté Admin lors du handshake WS.
func BuildAdminSignature(secret, method, path string) string {
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	data := fmt.Sprintf("%s:%s:%s", ts, method, path)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	sig := hex.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("hmac-sha256 %s.%s", ts, sig)
}

// RandomJitter retourne une durée aléatoire dans [0, max).
func RandomJitter(max time.Duration) time.Duration {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
