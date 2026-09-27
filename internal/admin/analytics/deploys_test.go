// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/db"
)

func TestGetDeployMarkers(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	d.Exec(`INSERT INTO proxies (id, name, config, enabled) VALUES ('p1','api','{"host":"api.acme.fr"}',1)`)
	now := time.Now().UTC()
	ins := func(id, note string, age time.Duration, config string) {
		d.Exec(`INSERT INTO proxy_history (id, proxy_id, config, note, created_at) VALUES (?,?,?,?,?)`,
			id, "p1", config, note, now.Add(-age).Format("2006-01-02 15:04:05"))
	}
	ins("h1", "création", 3*time.Hour, `{"host":"api.acme.fr"}`)
	ins("h2", "modification", 2*time.Hour, `{"host":"api.acme.fr"}`)
	ins("h3", "modification", 40*24*time.Hour, `{"host":"api.acme.fr"}`) // hors fenêtre
	d.Exec(`INSERT INTO proxy_history (id, proxy_id, config, note, created_at) VALUES ('h4','ghost','{"host":"old.fr"}','création',?)`, now.Add(-time.Hour).Format("2006-01-02 15:04:05"))

	p := Params{From: now.Add(-24 * time.Hour), To: now}
	out, err := GetDeployMarkers(context.Background(), d, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Fatalf("3 marqueurs attendus dans la fenêtre, got %d: %+v", len(out), out)
	}
	if out[0].Note != "création" || out[0].Domain != "api.acme.fr" || out[0].Proxy != "api" {
		t.Errorf("premier marqueur inattendu : %+v", out[0])
	}
	if out[2].Proxy != "ghost" {
		t.Errorf("proxy supprimé : repli sur proxy_id attendu, got %+v", out[2])
	}

	for _, m := range out {
		if m.Kind != "proxy" {
			t.Errorf("Kind=proxy attendu pour un marqueur de proxy_history : %+v", m)
		}
	}

	scoped, _ := GetDeployMarkers(context.Background(), d, Params{From: p.From, To: p.To, Proxy: "old.fr"})
	if len(scoped) != 1 {
		t.Errorf("filtre par proxy : %+v", scoped)
	}
}

func TestGetDeployMarkersDomainAndCert(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	now := time.Now().UTC()
	inWin := now.Add(-2 * time.Hour).Format("2006-01-02 15:04:05")
	outWin := now.Add(-40 * 24 * time.Hour).Format("2006-01-02 15:04:05")

	d.Exec(`INSERT INTO domains (id, domain, updated_at) VALUES ('d1','shop.acme.fr',?)`, inWin)
	d.Exec(`INSERT INTO domains (id, domain, updated_at) VALUES ('d2','old.acme.fr',?)`, outWin)

	d.Exec(`INSERT INTO certs (id, domain, issuer, expires_at, updated_at) VALUES ('c1','api.acme.fr','letsencrypt',?,?)`, now.Format(time.RFC3339), now.Format(time.RFC3339))
	d.Exec(`INSERT INTO cert_deploy_targets (id, cert_id, name, type, config) VALUES ('t1','c1','prod','webhook','{}')`)
	d.Exec(`INSERT INTO cert_deploy_history (id, target_id, cert_id, status, message, deployed_at) VALUES ('e1','t1','c1','ok','200 OK',?)`, inWin)

	p := Params{From: now.Add(-24 * time.Hour), To: now}
	out, err := GetDeployMarkers(context.Background(), d, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("2 marqueurs attendus (domaine dans la fenêtre + certificat) : %+v", out)
	}
	kinds := map[string]DeployMarker{}
	for _, m := range out {
		kinds[m.Kind] = m
	}
	if m, ok := kinds["domain"]; !ok || m.Domain != "shop.acme.fr" {
		t.Errorf("marqueur domaine attendu pour shop.acme.fr : %+v", kinds)
	}
	if m, ok := kinds["cert"]; !ok || m.Domain != "api.acme.fr" || m.Note != "ok" {
		t.Errorf("marqueur certificat attendu pour api.acme.fr, statut ok : %+v", kinds)
	}

	scoped, _ := GetDeployMarkers(context.Background(), d, Params{From: p.From, To: p.To, Proxy: "api.acme.fr"})
	if len(scoped) != 1 || scoped[0].Kind != "cert" {
		t.Errorf("filtre par domaine restreint au certificat d'api.acme.fr : %+v", scoped)
	}
}
