// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logs

import (
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// TestNodeIDSurvivesRenameIntegration reproduit le scénario réel : un nœud
// écrit des logs sous un node_name, est renommé/re-pairé (nouveau
// node_name, même node_id), écrit de nouveaux logs — puis on vérifie que
// filtrer par node_id retrouve bien tout l'historique malgré le
// changement de nom, alors que filtrer par l'ancien node_name ne retrouve
// plus que les anciennes entrées.
func TestNodeIDSurvivesRenameIntegration(t *testing.T) {
	dir := t.TempDir()
	db, err := admindb.Open(filepath.Join(dir, "admin.db"))
	if err != nil {
		t.Fatalf("ouverture DB : %v", err)
	}
	defer db.Close()

	s := New(db)

	s.Write(Entry{NodeName: "Frontal", NodeID: "token-abc", Status: 200, Message: "avant renommage"})
	s.Write(Entry{NodeName: "goproxify-edge", NodeID: "token-abc", Status: 200, Message: "après renommage"})
	s.Write(Entry{NodeName: "autre-noeud", NodeID: "token-xyz", Status: 200, Message: "un autre nœud"})

	byID, _, err := s.Search(SearchParams{NodeID: "token-abc"})
	if err != nil {
		t.Fatal(err)
	}
	if len(byID) != 2 {
		t.Fatalf("filtrage par node_id : %d entrées, attendu 2 (avant et après renommage)", len(byID))
	}

	byOldName, _, err := s.Search(SearchParams{NodeName: "Frontal"})
	if err != nil {
		t.Fatal(err)
	}
	if len(byOldName) != 1 {
		t.Fatalf("filtrage par l'ancien node_name : %d entrées, attendu 1 (comportement historique inchangé)", len(byOldName))
	}

	bySearch, _, err := s.Search(SearchParams{Search: "frontal"})
	if err != nil {
		t.Fatal(err)
	}
	if len(bySearch) != 1 {
		t.Fatalf("recherche libre 'frontal' : %d entrées, attendu 1 (retrouve l'historique par nom sans filtre de nœud)", len(bySearch))
	}
}
