// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/db"
)

// Nécessite une base GeoLite2-City : GPX_TEST_CITY_MMDB=/chemin/GeoLite2-City.mmdb
func TestGeoResolverLocalDB(t *testing.T) {
	path := os.Getenv("GPX_TEST_CITY_MMDB")
	if path == "" {
		t.Skip("GPX_TEST_CITY_MMDB non défini")
	}
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	ts := time.Now().UTC().Format(time.RFC3339)
	for _, ip := range []string{"81.2.69.142", "8.8.8.8", "10.1.2.3", "203.0.113.5"} {
		d.Exec(`INSERT INTO logs (ts, domain, ip, status) VALUES (?,?,?,?)`, ts, "a.fr", ip, 200)
	}

	g := &GeoResolver{DB: d, MMDBPath: path}
	g.resolve(context.Background()) // aucun accès réseau : la base locale est utilisée

	type row struct {
		cc, city string
		lat      float64
	}
	get := func(ip string) (r row, ok bool) {
		var lat *float64
		err := d.QueryRow(`SELECT country_code, city, lat FROM geoip_cache WHERE ip=?`, ip).Scan(&r.cc, &r.city, &lat)
		if lat != nil {
			r.lat = *lat
		}
		return r, err == nil
	}
	if r, ok := get("81.2.69.142"); !ok || r.cc != "GB" || r.lat == 0 {
		t.Errorf("81.2.69.142 : %+v (ok=%v)", r, ok)
	}
	if r, ok := get("8.8.8.8"); !ok || r.cc != "US" {
		t.Errorf("8.8.8.8 : %+v (ok=%v)", r, ok)
	}
	if r, ok := get("10.1.2.3"); !ok || r.cc != "LO" {
		t.Errorf("IP privée : %+v (ok=%v)", r, ok)
	}
	if r, ok := get("203.0.113.5"); !ok || r.cc != "XX" {
		t.Errorf("IP de documentation : %+v (ok=%v)", r, ok)
	}
}
