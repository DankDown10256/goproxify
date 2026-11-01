package fleet

import (
	"database/sql"
	"testing"
	"time"
)

func insertCounter(t *testing.T, d *sql.DB, node, ip string, at time.Time, n int) {
	t.Helper()
	if _, err := d.Exec(`INSERT INTO edge_ip_errors (node_id, minute, ip, errors) VALUES (?, ?, ?, ?)
		ON CONFLICT (node_id, minute, ip) DO UPDATE SET errors = excluded.errors`,
		node, at.UTC().Format("2006-01-02T15:04"), ip, n); err != nil {
		t.Fatal(err)
	}
}

// Une IP bannie d'après les seuls compteurs envoyés par les passerelles, sans aucune ligne brute.
func TestScanBansFromGatewayCounters(t *testing.T) {
	e, d := newTestEngine(t)
	now := time.Now()
	insertCounter(t, d, "edge-a", "203.0.113.9", now.Add(-2*time.Minute), 3)
	insertCounter(t, d, "edge-a", "203.0.113.9", now.Add(-1*time.Minute), 4) // 7 en tout, seuil 5
	insertCounter(t, d, "edge-a", "203.0.113.10", now.Add(-1*time.Minute), 4)
	e.scan()
	if activeBans(t, d, "203.0.113.9") != 1 {
		t.Fatal("l'IP au-dessus du seuil devait être bannie")
	}
	if activeBans(t, d, "203.0.113.10") != 0 {
		t.Fatal("l'IP sous le seuil ne doit pas être bannie")
	}
}

// Les compteurs de plusieurs passerelles s'additionnent pour une même IP (c'est l'intérêt d'un Seuils multi-passerelles global).
func TestCountersFromSeveralGatewaysAreAdded(t *testing.T) {
	e, d := newTestEngine(t)
	at := time.Now().Add(-90 * time.Second)
	insertCounter(t, d, "edge-a", "203.0.113.9", at, 3)
	insertCounter(t, d, "edge-b", "203.0.113.9", at, 3)
	e.scan()
	if activeBans(t, d, "203.0.113.9") != 1 {
		t.Fatal("3 erreurs sur chacune de deux passerelles (6 > 5) devaient bannir l'IP")
	}
}

// La minute partielle au début de la fenêtre n'est pas comptée : jamais plus de bans qu'avec les lignes brutes.
func TestTheCounterMinuteContainingTheWindowStartIsIgnored(t *testing.T) {
	e, d := newTestEngine(t)
	since := time.Now().Add(-5 * time.Minute) // WindowSec = 300
	insertCounter(t, d, "edge-a", "203.0.113.9", since, 9)
	e.scan()
	if activeBans(t, d, "203.0.113.9") != 0 {
		t.Fatal("la minute qui contient le début de la fenêtre ne doit pas compter")
	}
}

// Les erreurs servies pendant un ban levé depuis ne comptent pas : pas de ban à nouveau dès la levée.
func TestCountersDoNotRebanRightAfterAnUnban(t *testing.T) {
	e, d := newTestEngine(t)
	now := time.Now()
	if _, err := d.Exec(`INSERT INTO security_ban_history (ip, domain, action, reason, source, created_at) VALUES (?, '', 'unbanned', 'test', 'manual', ?)`,
		"203.0.113.9", now.Add(-30*time.Second).UTC().Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}
	// Des erreurs de la minute précédente et de la minute courante : toutes avant ou pendant la minute du déban.
	insertCounter(t, d, "edge-a", "203.0.113.9", now.Add(-2*time.Minute), 9)
	e.scan()
	if activeBans(t, d, "203.0.113.9") != 0 {
		t.Fatal("l'IP est rebannie sur des erreurs antérieures à son déban")
	}
}

func TestPrivateAndWhitelistedIPsInCountersAreNeverBanned(t *testing.T) {
	e, d := newTestEngine(t)
	if err := e.SaveConfig(Config{Enabled: true, WindowSec: 300, MaxErrors: 5, Whitelist: []string{"203.0.113.50"}}); err != nil {
		t.Fatal(err)
	}
	at := time.Now().Add(-90 * time.Second)
	insertCounter(t, d, "edge-a", "10.0.0.5", at, 50)
	insertCounter(t, d, "edge-a", "203.0.113.50", at, 50)
	e.scan()
	if activeBans(t, d, "10.0.0.5") != 0 || activeBans(t, d, "203.0.113.50") != 0 {
		t.Fatal("une IP privée ou en liste blanche a été bannie")
	}
}
