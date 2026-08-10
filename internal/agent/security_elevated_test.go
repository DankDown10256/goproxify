// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import "testing"

// TestElevatedH11_ShellCmdAllowlist — déjà corrigé avec C5 ; garde-fou CI Élevés.
func TestElevatedH11_ShellCmdAllowlist(t *testing.T) {
	if !shellCmdAllowed([]string{"/bin/sh"}) {
		t.Fatal("/bin/sh doit être autorisé")
	}
	if shellCmdAllowed([]string{"curl", "http://x"}) {
		t.Fatal("curl ne doit pas être autorisé")
	}
	if shellCmdAllowed([]string{"/bin/sh", "-c", "id"}) {
		t.Fatal("shell avec args ne doit pas être autorisé")
	}
}

// TestElevatedH11_ContainerAuthz — refuse conteneur hors catalogue découvert.
func TestElevatedH11_ContainerAuthz(t *testing.T) {
	allow := map[string]bool{"abcdef0123456789fullid": true}
	hub := newShellHub(nil, nil, func(id string) bool {
		return allow[id]
	})
	if hub.allowCont("deadbeef0000") {
		t.Fatal("shellHub doit refuser conteneur hors discovered")
	}
	if !hub.allowCont("abcdef0123456789fullid") {
		t.Fatal("shellHub doit autoriser conteneur discovered")
	}
}
