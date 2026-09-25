// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package corews

import (
	"encoding/json"
	"testing"

	coreWS "github.com/vincamok/goproxify/internal/core/ws"
)

// TestStampLogBatchNodeAlwaysOverwritesNodeID vérifie que node_id est
// toujours écrasé par l'ID stable de la connexion WS (coreID), même si
// l'entrée en portait déjà un différent — l'identité du nœud doit être
// autoritaire côté Admin, jamais déclarée par le Core.
func TestStampLogBatchNodeAlwaysOverwritesNodeID(t *testing.T) {
	entries := []coreWS.LogEntryPayload{
		{Message: "a", NodeID: "spoofed"},
		{Message: "b", NodeName: "already-set"},
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}

	out := stampLogBatchNode(raw, "real-core-id", "goproxify-core")

	var got []coreWS.LogEntryPayload
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if got[0].NodeID != "real-core-id" {
		t.Fatalf("NodeID[0] = %q, attendu real-core-id (jamais celui envoyé par Core)", got[0].NodeID)
	}
	if got[0].NodeName != "goproxify-core" {
		t.Fatalf("NodeName[0] = %q, attendu goproxify-core (absent à l'origine)", got[0].NodeName)
	}
	if got[1].NodeID != "real-core-id" {
		t.Fatalf("NodeID[1] = %q, attendu real-core-id", got[1].NodeID)
	}
	if got[1].NodeName != "already-set" {
		t.Fatalf("NodeName[1] = %q, un nom déjà présent ne doit pas être écrasé", got[1].NodeName)
	}
}

// TestStampLogBatchNodeNoopWhenNothingToStamp vérifie l'absence de
// modification (et donc de ré-allocation) quand il n'y a rien à faire.
func TestStampLogBatchNodeNoopWhenNothingToStamp(t *testing.T) {
	if out := stampLogBatchNode(nil, "id", "name"); out != nil {
		t.Fatalf("raw vide devrait rester nil, got %v", out)
	}
	if out := stampLogBatchNode([]byte("[]"), "", ""); string(out) != "[]" {
		t.Fatalf("sans id ni nom, le payload ne devrait pas changer, got %s", out)
	}
}
