// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import "testing"

func TestIsKnown(t *testing.T) {
	d := NewDiscovery(nil, "", "", "goproxify.", "a", nil, nil)
	d.mu.Lock()
	d.known["abcdef0123456789fullid"] = "web"
	d.mu.Unlock()
	if !d.IsKnown("abcdef0123456789fullid") {
		t.Fatal("ID complet")
	}
	if !d.IsKnown("abcdef012345") {
		t.Fatal("préfixe 12")
	}
	if d.IsKnown("deadbeef0000") {
		t.Fatal("inconnu")
	}
}
