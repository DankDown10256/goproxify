package importer

import (
	"path/filepath"
	"sort"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// entityTables : tables sauvegardées par les sections dédiées de ExportBackup (hors `tables`, `secrets`, `history`).
var entityTables = map[string]bool{
	"proxies": true, "users": true, "tokens": true, "token_scopes": true, "snippets": true,
	"alert_rules": true, "declared_nodes": true,
}

// notBackedUp : tables volontairement absentes d'une sauvegarde, avec la raison. Une table nouvelle doit être
// rangée ici ou dans backupTables / secretTables / historyTables, sinon ce test échoue.
var notBackedUp = map[string]string{
	"backup_snapshots":      "les autres snapshots : récursivité",
	"backup_deliveries":     "journal des copies vers les destinations, propre à l'instance",
	"nodes":                 "état dynamique, les nœuds se ré-enregistrent",
	"pending_nodes":         "état dynamique, les nœuds se ré-enregistrent",
	"logs_minute":           "cumuls reconstitués : chaque passerelle renvoie les siens",
	"edge_ip_errors":        "compteurs reconstitués : chaque passerelle renvoie les siens",
	"geoip_cache":           "cache de résolutions",
	"user_mfa_challenges":   "défis éphémères",
	"certs":                 "certificats repris par le dossier certs/ de la section secrets, l'Admin relit ce dossier si la table est vide",
	"bootstrap_tickets":     "tickets à courte durée de vie",
	"sqlite_sequence":       "interne à SQLite",
	"schema_migrations":     "interne à l'Admin",
	"password_reset_tokens": "jetons éphémères",
}

func TestEveryAdminTableIsBackedUpOrExcluded(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	known := map[string]bool{}
	for _, list := range [][]string{backupTables, secretTables, historyTables} {
		for _, tbl := range list {
			known[tbl] = true
		}
	}
	for tbl := range entityTables {
		known[tbl] = true
	}
	for tbl := range notBackedUp {
		known[tbl] = true
	}

	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var missing []string
	for rows.Next() {
		var name string
		rows.Scan(&name) //nolint:errcheck
		if !known[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("tables ni sauvegardées ni exclues explicitement : %v — les ajouter à backupTables / secretTables / historyTables, ou à notBackedUp avec la raison", missing)
	}
}

func TestBackedUpTablesExist(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, list := range [][]string{backupTables, secretTables, historyTables} {
		for _, tbl := range list {
			var n int
			if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, tbl).Scan(&n); err != nil || n == 0 {
				t.Errorf("la table %q est sauvegardée mais n'existe plus : la restauration l'ignorerait en silence", tbl)
			}
		}
	}
}
