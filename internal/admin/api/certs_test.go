// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"

	"github.com/vincamok/goproxify/internal/admin/api"
)

func generateTestCertPair(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "import.example.com"},
		DNSNames:     []string{"import.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return string(certPEMBytes), string(keyPEMBytes)
}

func TestImportCert(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "certs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	certPEM, keyPEM := generateTestCertPair(t)

	h := &api.CertsHandler{DB: db}
	body, _ := json.Marshal(map[string]any{
		"cert_pem": certPEM,
		"key_pem":  keyPEM,
		"issuer":   "test-ca",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/import", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated && rec.Code != http.StatusOK {
		t.Fatalf("import status %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["domain"] != "import.example.com" {
		t.Errorf("unexpected domain: %v", resp["domain"])
	}

	// Second import of the same domain should upsert (no error).
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/certs/import", bytes.NewReader(body))
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusCreated && rec2.Code != http.StatusOK {
		t.Fatalf("upsert status %d: %s", rec2.Code, rec2.Body.String())
	}
}

func TestImportCertInvalidPEM(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "certs2.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	h := &api.CertsHandler{DB: db}
	body, _ := json.Marshal(map[string]any{
		"cert_pem": "notapem",
		"key_pem":  "notapem",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/import", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestACMEMonitor(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "certs3.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Insert a cert that expires soon (warning) and one that is ok.
	_, _ = db.Exec(`INSERT INTO certs (id, domain, issuer, cert_pem, key_pem, expires_at)
		VALUES ('id1', 'warn.example.com', 'letsencrypt', 'x', 'x', datetime('now', '+20 days'))`)
	_, _ = db.Exec(`INSERT INTO certs (id, domain, issuer, cert_pem, key_pem, expires_at)
		VALUES ('id2', 'ok.example.com', 'letsencrypt', 'x', 'x', datetime('now', '+60 days'))`)

	h := &api.CertsHandler{DB: db}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/acme-monitor", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("monitor status %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp["total"].(float64) != 2 {
		t.Errorf("expected 2 certs, got %v", resp["total"])
	}
	if resp["warning"].(float64) != 1 {
		t.Errorf("expected 1 warning, got %v", resp["warning"])
	}
	if resp["ok"].(float64) != 1 {
		t.Errorf("expected 1 ok, got %v", resp["ok"])
	}
}
