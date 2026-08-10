// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ws

import (
	"log/slog"
	"testing"
)

func TestReviewP1_UnregisterAgentKeepsSuccessor(t *testing.T) {
	h := NewHub("secret", slog.Default())
	old := &agentConn{id: "a1", name: "node-a"}
	neu := &agentConn{id: "a1", name: "node-a"}

	h.mu.Lock()
	h.agentConns["a1"] = neu
	h.mu.Unlock()

	h.unregisterAgent("a1", old)

	h.mu.RLock()
	cur := h.agentConns["a1"]
	h.mu.RUnlock()
	if cur != neu {
		t.Fatal("unregister de l'ancienne conn ne doit pas effacer le successeur")
	}

	h.unregisterAgent("a1", neu)
	h.mu.RLock()
	_, ok := h.agentConns["a1"]
	h.mu.RUnlock()
	if ok {
		t.Fatal("unregister de la conn courante doit retirer l'entrée")
	}
}
