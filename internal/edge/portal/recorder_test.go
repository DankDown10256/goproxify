// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecordingRoundTripEncryptedAtRest(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rec")
	st, err := NewRecordingStore(dir, "secret")
	if err != nil {
		t.Fatal(err)
	}
	rec := st.Start("alice", "srv-db", "ssh", "1.2.3.4:5")
	rec.Output([]byte("hello \x1b[31mworld\x1b[0m\r\n"))
	rec.Output([]byte("é et \"guillemets\"\n"))
	id := rec.meta.ID
	rec.Close()

	list, err := st.List()
	if err != nil || len(list) != 1 || list[0].ID != id || list[0].Actor != "alice" || list[0].Bytes == 0 {
		t.Fatalf("list: %+v %v", list, err)
	}
	cast, err := st.Read(id)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(cast)), "\n")
	if len(lines) != 3 || !strings.Contains(lines[0], `"version":2`) || !strings.Contains(lines[1], `"o"`) || !strings.Contains(lines[2], "guillemets") {
		t.Fatalf("cast inattendu: %q", cast)
	}
	onDisk, _ := os.ReadFile(filepath.Join(dir, id+".cast.gpx"))
	if bytes.Contains(onDisk, []byte("hello")) {
		t.Fatal("le fichier doit être chiffré au repos")
	}
	other, _ := NewRecordingStore(dir, "autre-secret")
	if _, err := other.Read(id); err == nil {
		t.Fatal("un autre secret ne doit pas déchiffrer")
	}

	if err := st.Delete(id); err != nil {
		t.Fatal(err)
	}
	if l, _ := st.List(); len(l) != 0 {
		t.Fatalf("suppression: %+v", l)
	}
}

func TestRecordingRejectsBadIDs(t *testing.T) {
	st, _ := NewRecordingStore(t.TempDir(), "s")
	for _, id := range []string{"", "../etc/passwd", "abc", "00000000-0000-0000-0000-00000000000/../x"} {
		if _, err := st.Read(id); err == nil {
			t.Errorf("Read(%q) doit échouer", id)
		}
		if err := st.Delete(id); err == nil {
			t.Errorf("Delete(%q) doit échouer", id)
		}
	}
}

func TestRecordingTruncatesAndPurges(t *testing.T) {
	st, _ := NewRecordingStore(t.TempDir(), "s")
	rec := st.Start("bob", "t", "web", "")
	chunk := bytes.Repeat([]byte("x"), 1<<20)
	for i := 0; i < 12; i++ {
		rec.Output(chunk)
	}
	rec.Close()
	list, _ := st.List()
	if len(list) != 1 || !list[0].Truncated || list[0].Bytes > maxRecordingBytes+(2<<20) {
		t.Fatalf("troncature attendue: %+v", list)
	}

	old := st.Start("carol", "t", "ssh", "")
	old.meta.Started = time.Now().UTC().AddDate(0, 0, -40).Format(time.RFC3339)
	old.Close()
	if n := st.Purge(30, time.Now()); n != 1 {
		t.Fatalf("purge: %d", n)
	}
	if l, _ := st.List(); len(l) != 1 || l[0].Actor != "bob" {
		t.Fatalf("après purge: %+v", l)
	}
	var nilRec *Recording
	nilRec.Output([]byte("x"))
	nilRec.Close()
	if (*RecordingStore)(nil).Start("a", "b", "c", "d") != nil {
		t.Fatal("store nul: pas d'enregistrement")
	}
}
