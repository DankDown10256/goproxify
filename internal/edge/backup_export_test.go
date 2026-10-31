package edge

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackupExportRestoreRoundTrip(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GPX_EDGE_DATA_DIR", root)
	os.MkdirAll(filepath.Join(root, "proxies"), 0o700)
	os.MkdirAll(filepath.Join(root, "geoip"), 0o700)
	os.WriteFile(filepath.Join(root, "proxies", "app.yaml"), []byte("host: app.fr"), 0o600)
	os.WriteFile(filepath.Join(root, "portal-config.gpx"), []byte("chiffré"), 0o600)
	os.WriteFile(filepath.Join(root, "geoip", "GeoLite2-City.mmdb"), []byte("gros"), 0o600)
	os.WriteFile(filepath.Join(root, "x.cast.gpx"), []byte("enregistrement"), 0o600)
	db, err := sql.Open("sqlite", filepath.Join(root, "bans.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`CREATE TABLE b (ip TEXT)`)
	db.Exec(`INSERT INTO b VALUES ('203.0.113.9')`)
	db.Close()

	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleBackupExport(rec, httptest.NewRequest(http.MethodGet, "/internal/v1/backup/export", nil))
	var b backupBundle
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"proxies/app.yaml", "portal-config.gpx", "bans.db"} {
		if len(b.Files[want]) == 0 {
			t.Fatalf("%s absent de l'export : %v", want, keys(b.Files))
		}
	}
	for _, not := range []string{"geoip/GeoLite2-City.mmdb", "x.cast.gpx"} {
		if _, ok := b.Files[not]; ok {
			t.Fatalf("%s ne devrait pas être exporté", not)
		}
	}

	// Restauration sur un dossier vierge, avec une tentative d'évasion de chemin.
	root2 := t.TempDir()
	t.Setenv("GPX_EDGE_DATA_DIR", root2)
	b.Files["../evil.txt"] = []byte("x")
	b.Files["geoip/y.mmdb"] = []byte("x")
	body, _ := json.Marshal(b)
	rec = httptest.NewRecorder()
	s.handleBackupRestore(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/backup/restore", bytes.NewReader(body)))
	var res struct {
		Written  int      `json:"written"`
		Rejected []string `json:"rejected"`
	}
	json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Written != 3 || len(res.Rejected) != 2 {
		t.Fatalf("résultat : %+v", res)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(root2), "evil.txt")); err == nil {
		t.Fatal("écriture hors du dossier de données")
	}
	if data, _ := os.ReadFile(filepath.Join(root2, "proxies", "app.yaml")); string(data) != "host: app.fr" {
		t.Fatalf("proxy non restauré : %q", data)
	}
	db2, err := sql.Open("sqlite", filepath.Join(root2, "bans.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	var ip string
	if err := db2.QueryRow(`SELECT ip FROM b`).Scan(&ip); err != nil || ip != "203.0.113.9" {
		t.Fatalf("base restaurée illisible : %q %v", ip, err)
	}
}

func keys(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestBackupExportReportsSkippedWithReasonAndStreamsValidJSON(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GPX_EDGE_DATA_DIR", root)
	t.Setenv("GPX_BACKUP_MAX_FILE_MB", "1")
	os.WriteFile(filepath.Join(root, "petit.gpx"), []byte("ok"), 0o600)
	os.WriteFile(filepath.Join(root, "gros.gpx"), bytes.Repeat([]byte("x"), 2<<20), 0o600)
	// Base WAL ouverte, comme en production : sa copie passe par un dossier de travail du volume.
	live, _ := sql.Open("sqlite", filepath.Join(root, "bans.db")+"?_pragma=journal_mode(WAL)")
	defer live.Close()
	live.SetMaxOpenConns(1)
	live.Exec(`CREATE TABLE b (ip TEXT)`)
	live.Exec(`INSERT INTO b VALUES ('203.0.113.9')`)

	rec := httptest.NewRecorder()
	(&Server{}).handleBackupExport(rec, httptest.NewRequest(http.MethodGet, "/internal/v1/backup/export", nil))
	var b backupBundle
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatalf("JSON invalide : %v", err)
	}
	if string(b.Files["petit.gpx"]) != "ok" || len(b.Files["bans.db"]) == 0 {
		t.Fatalf("fichiers : %v", keys(b.Files))
	}
	if _, ok := b.Files["gros.gpx"]; ok {
		t.Fatal("fichier au-delà de la limite exporté")
	}
	if len(b.Skipped) != 1 || !strings.Contains(b.Skipped[0], "gros.gpx") || !strings.Contains(b.Skipped[0], "Mo par fichier") {
		t.Fatalf("raison absente : %v", b.Skipped)
	}
	if b.Sizes["petit.gpx"] != 2 || b.Sizes["bans.db"] == 0 {
		t.Fatalf("tailles : %v", b.Sizes)
	}
	if entries, _ := os.ReadDir(root); func() bool {
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), backupTmpPrefix) {
				return true
			}
		}
		return false
	}() {
		t.Fatal("dossier de travail non nettoyé")
	}
}

// Le dossier des logs n'est pas sauvegardé, sauf les gels légaux : le registre et les archives des lignes qu'ils gardent.
// Une restauration les remet ; elle refuse tout autre fichier du dossier des logs.
func TestBackupKeepsOnlyTheLegalHoldsOfTheLogsFolder(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GPX_EDGE_DATA_DIR", root)
	for rel, content := range map[string]string{
		"logs/access-2026-10-19.db": "gros",
		"logs/system-2026-10.db":    "gros",
		"logs/legal-holds.json":     `[{"id":"abc"}]`,
		"log-ip-key.gpx":            "clé",
		"log-sign-key.gpx":          "clé de signature",
		"log-export-audit.jsonl":    "{}",
		"siem-config.gpx":           "config",
		"siem-state.gpx":            "curseurs",
	} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0o700)
		os.WriteFile(p, []byte(content), 0o600)
	}
	os.MkdirAll(filepath.Join(root, "logs", "held", "abc"), 0o700)
	// Une archive est une base SQLite : elle est copiée par VACUUM INTO, il faut une vraie base.
	arch := filepath.Join(root, "logs", "held", "abc", "access-2026-10-05.db")
	db, err := sql.Open("sqlite", arch)
	if err != nil {
		t.Fatal(err)
	}
	db.Exec(`CREATE TABLE entries (id INTEGER PRIMARY KEY, ip TEXT)`)
	db.Exec(`INSERT INTO entries VALUES (1, '203.0.113.9')`)
	db.Close()

	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleBackupExport(rec, httptest.NewRequest(http.MethodGet, "/internal/v1/backup/export", nil))
	var b backupBundle
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"logs/legal-holds.json", "logs/held/abc/access-2026-10-05.db", "log-ip-key.gpx", "log-sign-key.gpx", "log-export-audit.jsonl", "siem-config.gpx", "siem-state.gpx"} {
		if len(b.Files[want]) == 0 {
			t.Errorf("%s absent de la sauvegarde : %v", want, keys(b.Files))
		}
	}
	for _, not := range []string{"logs/access-2026-10-19.db", "logs/system-2026-10.db"} {
		if _, ok := b.Files[not]; ok {
			t.Errorf("%s ne devrait pas être sauvegardé", not)
		}
	}

	root2 := t.TempDir()
	t.Setenv("GPX_EDGE_DATA_DIR", root2)
	b.Files["logs/access-2026-10-26.db"] = []byte("x")
	b.Files["logs/held/../access.db"] = []byte("x")
	body, _ := json.Marshal(b)
	rec = httptest.NewRecorder()
	s.handleBackupRestore(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/backup/restore", bytes.NewReader(body)))
	var res struct {
		Rejected []string `json:"rejected"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Rejected) != 2 {
		t.Errorf("rejetés = %v, attendu les deux fichiers de logs hors gel", res.Rejected)
	}
	for _, want := range []string{"logs/legal-holds.json", "logs/held/abc/access-2026-10-05.db", "siem-state.gpx"} {
		if _, err := os.Stat(filepath.Join(root2, filepath.FromSlash(want))); err != nil {
			t.Errorf("%s non restauré : %v", want, err)
		}
	}
	for _, not := range []string{"logs/access-2026-10-26.db", "access.db"} {
		if _, err := os.Stat(filepath.Join(root2, filepath.FromSlash(not))); err == nil {
			t.Errorf("%s restauré alors qu'il devait être refusé", not)
		}
	}
}

// Les copies chiffrées ajoutées avec Ephor, le groupe HA et la conservation des logs sont reprises ; la base ASN, que
// l'Admin repousse et retélécharge, ne prend pas la place du reste dans le budget de la sauvegarde.
func TestBackupKeepsTheStateOfEphorAndTheHAGroupButNotTheASNBase(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GPX_EDGE_DATA_DIR", root)
	files := []string{"threat-state.gpx", "behavior-state.gpx", "group-card.gpx", "pushed-journal.gpx", "log-retention.gpx", "asn-db.gpx"}
	for _, name := range files {
		os.WriteFile(filepath.Join(root, name), []byte("contenu "+name), 0o600)
	}
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleBackupExport(rec, httptest.NewRequest(http.MethodGet, "/internal/v1/backup/export", nil))
	var b backupBundle
	if err := json.Unmarshal(rec.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	for _, name := range files[:5] {
		if len(b.Files[name]) == 0 {
			t.Errorf("%s absent de la sauvegarde : %v", name, keys(b.Files))
		}
	}
	if _, ok := b.Files["asn-db.gpx"]; ok {
		t.Error("la base ASN est rejouable par l'Admin : elle n'a pas à être sauvegardée")
	}
}
