package importer

import (
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestTablesRoundTripAndRedaction(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.Exec(`INSERT INTO settings (key, value) VALUES ('mcp.allowed_ips', '["10.0.0.0/8"]'), ('smtp.password', 'hunter2')`)
	db.Exec(`INSERT INTO rules_engine_rules (id, name, condition_json, action_json) VALUES ('r1','Règle','{"type":"cve_critical"}','{"type":"notify"}')`)
	db.Exec(`INSERT INTO auth_providers (id, name, provider, config) VALUES ('p1','oidc','oidc','{"client_id":"abc","client_secret":"s3cr3t"}')`)

	bk := &Backup{Tables: exportTables(db)}
	RedactSecrets(bk)
	if got := bk.Tables["auth_providers"][0]["config"].(string); got != `{"client_id":"abc","client_secret":""}` {
		t.Fatalf("secret non rédigé: %s", got)
	}
	for _, r := range bk.Tables["settings"] {
		if r["key"] == "smtp.password" && r["value"] != "" {
			t.Fatal("setting secret non rédigé")
		}
	}

	db.Exec(`DELETE FROM rules_engine_rules`)
	db.Exec(`DELETE FROM settings WHERE key='mcp.allowed_ips'`)
	w, _ := applyTables(db, bk.Tables, false)
	if w != 2 {
		t.Fatalf("écrites=%d", w)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM rules_engine_rules WHERE id='r1'`).Scan(&n)
	if n != 1 {
		t.Fatal("règle non restaurée")
	}
	var v string
	db.QueryRow(`SELECT value FROM settings WHERE key='smtp.password'`).Scan(&v)
	if v != "hunter2" {
		t.Fatalf("secret écrasé: %q", v)
	}
}

func TestSummarizeBackupRejectsUnknownVersion(t *testing.T) {
	if _, _, err := SummarizeBackup([]byte(`{"version":"99"}`)); err == nil {
		t.Fatal("version inconnue acceptée")
	}
	_, sum, err := SummarizeBackup([]byte(`{"version":"1","tables":{"settings":[{"key":"a","value":"b"}]}}`))
	if err != nil || sum.ConfigRowCount != 1 || sum.ConfigTables["settings"] != 1 {
		t.Fatalf("résumé incorrect: %+v %v", sum, err)
	}
}
