// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"log/slog"
	"path/filepath"
	"testing"
)

func clearMasterKeySources(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"GPX_PORTAL_MASTER_KEY", "GPX_CONTROL_PLANE_AUTH_TOKEN", "GPX_CONTROLPLANE_AUTH_TOKEN",
		"GPX_PAIRING_SECRET", "GPX_PAIRING_SECRET_FILE", "GPX_NODE_KEY", "GPX_NODE_KEY_FILE",
	} {
		t.Setenv(k, "")
	}
	t.Setenv("GPX_NODE_KEY_PATH", filepath.Join(t.TempDir(), "absent.key"))
}

// Une passerelle sans secret d'appairage (ADR 0015) démarre son portail avec sa clé locale.
func TestPortalStartsWithNodeKeyWithoutPairingSecret(t *testing.T) {
	clearMasterKeySources(t)
	t.Setenv("GPX_NODE_KEY", "cle-locale-de-la-passerelle-0123456789")

	svc := NewService(slog.Default())
	cfg := Config{Enabled: true, SSHPort: 2223, HTTPPort: 18445, DBPath: filepath.Join(t.TempDir(), "portal.gpx"), PublicHost: "a.example"}
	if err := svc.ApplyConfig(cfg); err != nil {
		t.Fatalf("le portail doit démarrer avec la clé locale: %v", err)
	}
	svc.Stop()
}

func TestPortalWithoutAnyKeyReportsClearError(t *testing.T) {
	clearMasterKeySources(t)

	svc := NewService(slog.Default())
	err := svc.ApplyConfig(Config{Enabled: true, SSHPort: 2224, HTTPPort: 18446, DBPath: filepath.Join(t.TempDir(), "portal.gpx")})
	if err != errNoMasterKey {
		t.Fatalf("err=%v", err)
	}
}
