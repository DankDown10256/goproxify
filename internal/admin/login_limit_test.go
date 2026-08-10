// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"testing"
	"time"
)

func TestLoginLimiter_BlocksAfterMaxFails(t *testing.T) {
	l := newLoginLimiter()
	key := loginKey("127.0.0.1", "a@b.c")
	for i := 0; i < loginMaxFails-1; i++ {
		if blocked, _ := l.blocked(key); blocked {
			t.Fatalf("blocked trop tôt à l’échec %d", i+1)
		}
		l.fail(key)
	}
	l.fail(key) // 5e échec → lock
	blocked, wait := l.blocked(key)
	if !blocked {
		t.Fatal("attendu lockout après loginMaxFails échecs")
	}
	if wait < time.Minute {
		t.Fatalf("Retry-After trop court: %v", wait)
	}
	l.success(key)
	if blocked, _ := l.blocked(key); blocked {
		t.Fatal("success doit lever le lockout")
	}
}

func TestLoginLimiter_WindowResets(t *testing.T) {
	l := newLoginLimiter()
	key := loginKey("10.0.0.1", "x@y.z")
	l.fail(key)
	l.mu.Lock()
	l.byKey[key].windowAt = time.Now().Add(-loginWindowSecs - time.Second)
	l.mu.Unlock()
	if blocked, _ := l.blocked(key); blocked {
		t.Fatal("fenêtre expirée ne doit pas bloquer")
	}
	l.fail(key)
	l.mu.Lock()
	fails := l.byKey[key].fails
	l.mu.Unlock()
	if fails != 1 {
		t.Fatalf("fails après reset fenêtre: got %d want 1", fails)
	}
}
