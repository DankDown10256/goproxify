// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/importer"
)

func TestSealOpenRoundTrip(t *testing.T) {
	t.Setenv("GPX_BACKUP_KEY", "test-backup-key")
	plain := []byte(`{"version":"1"}`)
	sealed, err := sealSnapshot(plain)
	if err != nil {
		t.Fatal(err)
	}
	if string(sealed) == string(plain) {
		t.Fatal("attendu chiffrement")
	}
	out, err := openSnapshot(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(plain) {
		t.Fatalf("got %s", out)
	}
}

func TestSealWithoutKeyPassthrough(t *testing.T) {
	os.Unsetenv("GPX_BACKUP_KEY")
	plain := []byte(`{"x":1}`)
	sealed, err := sealSnapshot(plain)
	if err != nil {
		t.Fatal(err)
	}
	if string(sealed) != string(plain) {
		t.Fatal("sans clé, passthrough attendu")
	}
}

func TestRedactInExportShape(t *testing.T) {
	b := &importer.Backup{
		Version: "1",
		Tokens:  []importer.BackupToken{{Token: "plain-secret-tok"}},
	}
	importer.RedactSecrets(b)
	raw, _ := json.Marshal(b)
	if strings.Contains(string(raw), "plain-secret-tok") {
		t.Fatalf("token encore présent: %s", raw)
	}
}
