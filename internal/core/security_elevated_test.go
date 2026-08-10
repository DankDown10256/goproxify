// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func skipUntilElevatedFix(t *testing.T, id, reason string) {
	t.Helper()
	t.Skipf("pending %s: %s", id, reason)
}

func coreServerSource(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(file), "server.go"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestElevatedH3_NoAutoEnrollUnknownBearer — EnsureToken auto sur
// /internal/v1/agent/* doit disparaître.
func TestElevatedH3_NoAutoEnrollUnknownBearer(t *testing.T) {
	src := coreServerSource(t)
	if strings.Contains(src, `"agent-auto"`) || strings.Contains(src, "agent-auto") {
		t.Fatal("H3: auto-enroll EnsureToken agent-auto encore présent")
	}
	// authMiddleware doit refuser un bearer inconnu sans EnsureToken conditionnel agent/
	if strings.Contains(src, "enroll-on-first-use") {
		t.Fatal("H3: commentaire enroll-on-first-use encore présent")
	}
}

// TestElevatedH10_DelegationTLSSkipNotForced — TLSSkipVerify ne doit plus
// être forcé sur routes deleg-*.
func TestElevatedH10_DelegationTLSSkipNotForced(t *testing.T) {
	src := coreServerSource(t)
	// Dans applyDelegationRoutes, ne plus assigner TLSSkipVerify = true.
	fnStart := strings.Index(src, "func (s *Server) applyDelegationRoutes")
	if fnStart < 0 {
		t.Fatal("applyDelegationRoutes introuvable")
	}
	fnEnd := strings.Index(src[fnStart+1:], "\nfunc (")
	if fnEnd < 0 {
		fnEnd = len(src) - fnStart
	}
	body := src[fnStart : fnStart+fnEnd]
	if strings.Contains(body, "TLSSkipVerify = true") {
		t.Fatal("H10: applyDelegationRoutes force encore TLSSkipVerify=true")
	}
}

// TestElevatedH8_LoginRateLimitOwnedByAdmin — le rate-limit login vit côté admin.
func TestElevatedH8_LoginRateLimitOwnedByAdmin(t *testing.T) {
	// Couvert par internal/admin (login_limit_test + TestElevatedH8_LoginRateLimited).
}
