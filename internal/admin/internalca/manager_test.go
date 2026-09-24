// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package internalca

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"io"
	"log/slog"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	for _, s := range []string{
		`CREATE TABLE internal_ca (
			id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, subject TEXT NOT NULL,
			cert_pem TEXT NOT NULL, not_after DATETIME NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE internal_ca_certs (
			id TEXT PRIMARY KEY, ca_id TEXT NOT NULL, common_name TEXT NOT NULL, usage TEXT NOT NULL,
			sans_json TEXT NOT NULL DEFAULT '[]', serial TEXT NOT NULL, cert_pem TEXT NOT NULL,
			not_after DATETIME NOT NULL, revoked INTEGER NOT NULL DEFAULT 0, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("schema: %v", err)
		}
	}
	return db
}

func TestCreateCAAndIssueCert(t *testing.T) {
	db := testDB(t)
	m := New(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.SetCertDir(t.TempDir())
	ctx := context.Background()

	ca, err := m.CreateCA(ctx, "root", "GoProxify Internal Root", 5*365*24*time.Hour)
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	block, _ := pem.Decode([]byte(ca.CertPEM))
	if block == nil {
		t.Fatal("cert PEM vide")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse ca cert: %v", err)
	}
	if !caCert.IsCA {
		t.Fatal("le certificat racine devrait être marqué IsCA")
	}

	cert, err := m.IssueCert(ctx, ca.ID, "svc.internal.local", []string{"svc.internal.local", "10.0.0.5"}, "server", 90*24*time.Hour)
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	leafBlock, _ := pem.Decode([]byte(cert.CertPEM))
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "svc.internal.local", Roots: roots}); err != nil {
		t.Fatalf("verify chain: %v", err)
	}

	certs, err := m.ListCerts(ctx, ca.ID)
	if err != nil || len(certs) != 1 {
		t.Fatalf("ListCerts: %v %v", certs, err)
	}
	if err := m.RevokeCert(ctx, cert.ID); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	certs, _ = m.ListCerts(ctx, ca.ID)
	if !certs[0].Revoked {
		t.Fatal("le certificat devrait être révoqué")
	}
}

func TestIssueCertUnknownCA(t *testing.T) {
	db := testDB(t)
	m := New(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.SetCertDir(t.TempDir())
	if _, err := m.IssueCert(context.Background(), "inconnue", "x", nil, "server", 0); err == nil {
		t.Fatal("attendu une erreur pour une CA inconnue")
	}
}
