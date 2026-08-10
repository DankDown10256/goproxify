// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package importer_test

import (
	"testing"

	"github.com/vincamok/goproxify/internal/admin/importer"
)

func TestRedactSecrets(t *testing.T) {
	b := &importer.Backup{
		Tokens: []importer.BackupToken{{ID: "t1", Token: "secret-tok", Role: "core"}},
		AlertChannels: []map[string]any{
			{"id": "c1", "config": map[string]any{"url": "https://hooks.ex/x", "token": "abc", "secret": "xyz"}},
		},
	}
	importer.RedactSecrets(b)
	if b.Tokens[0].Token != "" {
		t.Fatal("token doit être rédigé")
	}
	cfg := b.AlertChannels[0]["config"].(map[string]any)
	if cfg["token"] != "" || cfg["secret"] != "" {
		t.Fatalf("secrets canal: %+v", cfg)
	}
	if cfg["url"] != "https://hooks.ex/x" {
		t.Fatal("url non-secrète ne doit pas être effacée")
	}
}
