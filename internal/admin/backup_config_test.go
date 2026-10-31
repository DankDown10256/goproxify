// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/config"
)

func TestBackupCarriesWhatOnlyTheEnvironmentHolds(t *testing.T) {
	dir := t.TempDir()
	crt, key := filepath.Join(dir, "admin.crt"), filepath.Join(dir, "admin.key")
	if err := os.WriteFile(crt, []byte("CERT"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GPX_PAIRING_SECRET", "root-secret")
	t.Setenv("GPX_PAIRING_SECRET_PREVIOUS", "old-1,old-2")
	t.Setenv("GPX_ADMIN_TLS_CERT", crt)
	t.Setenv("GPX_ADMIN_TLS_KEY", key)
	t.Setenv("GPX_SECURITY_JWT_SECRET", "jwt-secret")

	files := (&Server{cfg: &config.AdminConfig{}}).backupConfigFiles()

	var secrets map[string]string
	if err := json.Unmarshal(files["admin-secrets.json"], &secrets); err != nil {
		t.Fatalf("admin-secrets.json : %v", err)
	}
	if secrets["GPX_PAIRING_SECRET"] != "root-secret" || secrets["GPX_PAIRING_SECRET_PREVIOUS"] != "old-1,old-2" {
		t.Errorf("secret racine et précédents attendus : %v", secrets)
	}
	if string(files["admin-tls.crt"]) != "CERT" || string(files["admin-tls.key"]) != "KEY" {
		t.Errorf("le certificat et sa clé suivent : %q %q", files["admin-tls.crt"], files["admin-tls.key"])
	}
	for name, data := range files {
		if strings.Contains(string(data), "jwt-secret") {
			t.Errorf("le secret JWT ne doit pas être sauvegardé (%s)", name)
		}
	}
}

func TestBackupWithoutRootSecretOrCertificateStaysQuiet(t *testing.T) {
	t.Setenv("GPX_PAIRING_SECRET", "")
	t.Setenv("GPX_ADMIN_TLS_CERT", "")
	t.Setenv("GPX_ADMIN_TLS_KEY", "")
	files := (&Server{cfg: &config.AdminConfig{}}).backupConfigFiles()
	for _, name := range []string{"admin-secrets.json", "admin-tls.crt", "admin-tls.key"} {
		if _, ok := files[name]; ok {
			t.Errorf("%s ne doit pas être produit sans source", name)
		}
	}
	t.Setenv("GPX_ADMIN_TLS_CERT", filepath.Join(t.TempDir(), "absent.crt"))
	if _, ok := (&Server{cfg: &config.AdminConfig{}}).backupConfigFiles()["admin-tls.crt"]; ok {
		t.Error("un certificat illisible n'est pas sauvegardé")
	}
}
