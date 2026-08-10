// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// skipUntilElevatedFix marque un contrat Élevé non encore implémenté.
func skipUntilElevatedFix(t *testing.T, id, reason string) {
	t.Helper()
	t.Skipf("pending %s: %s", id, reason)
}

// TestElevatedH2_ApproveAgentRequiresWriteScope — PAT nodes:read ne doit plus
// suffire pour approve/revoke.
func TestElevatedH2_ApproveAgentRequiresWriteScope(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/agents/agent-1/approve", nil)
	got := rbac.RequiredScopeForRequest(req)
	if got == rbac.ScopeNodesRead {
		t.Fatalf("POST approve ne doit pas exiger seulement nodes:read, got %q", got)
	}
	if got != rbac.ScopeNodesWrite {
		t.Fatalf("POST approve: got %q want %q", got, rbac.ScopeNodesWrite)
	}
	if rbac.ToolRequiredScope("approve_agent") != rbac.ScopeNodesWrite {
		t.Fatalf("MCP approve_agent: got %q want nodes:write", rbac.ToolRequiredScope("approve_agent"))
	}
}

// TestElevatedH2_SecurityMutationsNotAuditRead — mutations security/import
// ne doivent pas se contenter de audit:read.
func TestElevatedH2_SecurityMutationsNotAuditRead(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/security/bans", nil)
	got := rbac.RequiredScopeForRequest(req)
	if got == rbac.ScopeAuditRead {
		t.Fatalf("mutation security ne doit pas mapper à audit:read seul, got %q", got)
	}
	if got != rbac.ScopeSecurityWrite {
		t.Fatalf("POST security: got %q want %q", got, rbac.ScopeSecurityWrite)
	}
	imp := httptest.NewRequest(http.MethodPost, "/api/v1/import/traefik", nil)
	if rbac.RequiredScopeForRequest(imp) != rbac.ScopeImportWrite {
		t.Fatalf("POST import: got %q want import:write", rbac.RequiredScopeForRequest(imp))
	}
}

// TestElevatedH2_PairingSecretNotNodesRead — lecture pairing-secret trop large.
func TestElevatedH2_PairingSecretNotNodesRead(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/pairing-secret", nil)
	got := rbac.RequiredScopeForRequest(req)
	if got == rbac.ScopeNodesRead {
		t.Fatalf("pairing-secret ne doit pas être nodes:read, got %q", got)
	}
	if got != rbac.ScopePairingRead {
		t.Fatalf("pairing-secret: got %q want %q", got, rbac.ScopePairingRead)
	}
}

// TestElevatedH1_SensitiveRoutesRequireAdmin — H1 documenté côté rbac ;
// le câblage adminOnly est vérifié dans admin.TestElevatedH1_*.
func TestElevatedH1_SensitiveRoutesRequireAdmin(t *testing.T) {
	// Contrat couvert par internal/admin/security_elevated_test.go (H1).
}
