// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ws

import (
	"os"
	"strings"

	"nhooyr.io/websocket"
)

// AcceptOpts retourne les options WS avec vérification Origin (pas InsecureSkipVerify).
// Origin vide (clients non-navigateur) est accepté par nhooyr.
// GPX_WS_ALLOWED_ORIGINS : hôtes supplémentaires (filepath.Match), séparés par virgules.
func AcceptOpts() *websocket.AcceptOptions {
	var patterns []string
	for _, p := range strings.Split(os.Getenv("GPX_WS_ALLOWED_ORIGINS"), ",") {
		p = strings.TrimSpace(p)
		if p != "" && p != "*" {
			patterns = append(patterns, p)
		}
	}
	return &websocket.AcceptOptions{OriginPatterns: patterns}
}
