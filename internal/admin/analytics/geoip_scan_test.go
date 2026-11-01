package analytics

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/db"
)

func TestEnsureCachesPrivateIPsAndRetriesUnresolvedIPs(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Close() })
	g := &GeoResolver{DB: d}
	for range 2 {
		g.Ensure(context.Background(), []string{"10.1.2.3", "10.9.9.9", "203.0.113.77"})
		var n int
		if err := d.QueryRowContext(t.Context(), `SELECT count(*) FROM geoip_cache WHERE country_code='LO'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 2 {
			t.Fatalf("private cache entries = %d, want 2", n)
		}
		if err := d.QueryRowContext(t.Context(), `SELECT count(*) FROM geoip_cache WHERE ip='203.0.113.77'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatal("an unresolved public IP must remain eligible for retry")
		}
	}
}
