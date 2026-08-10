// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin_test

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

func adminServerSource(t *testing.T) string {
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

// TestElevatedH1_PairingSecretAdminOnly — surfaces sensibles sous adminOnly.
func TestElevatedH1_PairingSecretAdminOnly(t *testing.T) {
	src := adminServerSource(t)
	needles := []string{
		`mux.Handle("/api/v1/auth-providers", adminOnly(`,
		`mux.Handle("/api/v1/security", adminOnly(`,
		`mux.Handle("/api/v1/import", adminOnly(`,
		`mux.Handle("/api/v1/backups", adminOnly(`,
		`mux.Handle("/api/v1/agents", adminOnly(`,
		`mux.Handle("GET /api/v1/pairing-secret", adminOnly(`,
		`mux.Handle("/api/v1/settings/mfa/", adminOnly(`,
	}
	for _, n := range needles {
		if !strings.Contains(src, n) {
			t.Fatalf("H1: route manquante sous adminOnly: %s", n)
		}
	}
}

// TestElevatedH7_BackupsEncrypted — snapshots rédigent secrets + chiffrement optionnel.
func TestElevatedH7_BackupsEncrypted(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	dir := filepath.Dir(file)
	sched, err := os.ReadFile(filepath.Join(dir, "backup", "scheduler.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sched), "RedactSecrets") || !strings.Contains(string(sched), "sealSnapshot") {
		t.Fatal("H7: TakeSnapshot doit RedactSecrets + sealSnapshot")
	}
	redact, err := os.ReadFile(filepath.Join(dir, "importer", "redact.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(redact), "func RedactSecrets") {
		t.Fatal("H7: RedactSecrets manquant")
	}
}

// TestElevatedH8_LoginRateLimited — brute-force login Admin (limiter + câblage handleLogin).
func TestElevatedH8_LoginRateLimited(t *testing.T) {
	src := adminServerSource(t)
	if !strings.Contains(src, "loginLimit") || !strings.Contains(src, "loginLimit.blocked") {
		t.Fatal("H8: handleLogin doit utiliser loginLimit.blocked")
	}
	if !strings.Contains(src, "StatusTooManyRequests") {
		t.Fatal("H8: handleLogin doit répondre 429")
	}
}

// TestElevatedH12_NodeTokensHashed — tokens Core/Agent hashés / chiffrés.
func TestElevatedH12_NodeTokensHashed(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	dir := filepath.Dir(file)
	dbSrc, err := os.ReadFile(filepath.Join(dir, "db", "db.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dbSrc), "token_hash") || !strings.Contains(string(dbSrc), "migrateNodeTokenHashes") {
		t.Fatal("H12: migration token_hash requise")
	}
	authSrc, err := os.ReadFile(filepath.Join(dir, "auth", "nodetoken.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(authSrc), "PrepareNodeTokenForStore") || !strings.Contains(string(authSrc), "HashNodeToken") {
		t.Fatal("H12: PrepareNodeTokenForStore / HashNodeToken manquants")
	}
}

// TestElevatedH6_SSRFDenyPrivate — vulnscan deny RFC1918 / metadata par défaut.
func TestElevatedH6_SSRFDenyPrivate(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(file), "vulnscan", "scanner.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "validateProbeURL") {
		t.Fatal("H6: probeServer doit appeler validateProbeURL")
	}
}

// TestElevatedH9_HelmHardeningDocumented — charts durcis (sock RO, hostPID opt-in).
func TestElevatedH9_HelmHardeningDocumented(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	agentTpl, err := os.ReadFile(filepath.Join(root, "helm", "goproxify", "templates", "agent-daemonset.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	vals, err := os.ReadFile(filepath.Join(root, "helm", "goproxify", "values.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(vals), "agentDockerSockReadOnly") || !strings.Contains(string(vals), "agentHostPID") {
		t.Fatal("H9: values security.* manquants")
	}
	if !strings.Contains(string(agentTpl), "agentDockerSockReadOnly") {
		t.Fatal("H9: agent sock doit être configurable readOnly")
	}
	if strings.Contains(string(agentTpl), "hostPID: true") && !strings.Contains(string(agentTpl), "agentHostPID") {
		t.Fatal("H9: hostPID ne doit plus être forcé sans opt-in")
	}
}
