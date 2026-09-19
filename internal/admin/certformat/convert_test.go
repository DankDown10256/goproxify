// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package certformat

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func generateTestCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		DNSNames:     []string{"test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

func TestIsValid(t *testing.T) {
	valid := []string{"pem", "key", "fullchain", "der", "der_key", "pkcs12", "json"}
	for _, f := range valid {
		if !IsValid(f) {
			t.Errorf("IsValid(%q) should be true", f)
		}
	}
	if IsValid("bad") || IsValid("") {
		t.Error("IsValid should return false for unknown format")
	}
}

func TestConvertPEM(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)
	b, err := Convert("test.example.com", certPEM, keyPEM, FormatPEM, "")
	if err != nil {
		t.Fatal(err)
	}
	if b.ContentType != "application/x-pem-file" {
		t.Errorf("unexpected content-type: %s", b.ContentType)
	}
	if len(b.Data) == 0 {
		t.Error("empty data")
	}
}

func TestConvertKey(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)
	b, err := Convert("test.example.com", certPEM, keyPEM, FormatKey, "")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b.Data)
	if block == nil {
		t.Fatal("expected PEM block in key output")
	}
}

func TestConvertFullchain(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)
	b, err := Convert("test.example.com", certPEM, keyPEM, FormatFullChain, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Data) < len(certPEM) {
		t.Error("fullchain should be at least as large as cert alone")
	}
}

func TestConvertDER(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)
	b, err := Convert("test.example.com", certPEM, keyPEM, FormatDERCert, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseCertificate(b.Data); err != nil {
		t.Errorf("DER output is not a valid certificate: %v", err)
	}
}

func TestConvertDERKey(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)
	b, err := Convert("test.example.com", certPEM, keyPEM, FormatDERKey, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Data) == 0 {
		t.Error("empty DER key output")
	}
}

func TestConvertPKCS12(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)
	b, err := Convert("test.example.com", certPEM, keyPEM, FormatPKCS12, "secret")
	if err != nil {
		t.Fatal(err)
	}
	if b.ContentType != "application/x-pkcs12" {
		t.Errorf("unexpected content-type: %s", b.ContentType)
	}
}

func TestConvertJSON(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)
	b, err := Convert("test.example.com", certPEM, keyPEM, FormatJSON, "")
	if err != nil {
		t.Fatal(err)
	}
	if b.ContentType != "application/json" {
		t.Errorf("unexpected content-type: %s", b.ContentType)
	}
}

func TestConvertUnknownFormat(t *testing.T) {
	certPEM, keyPEM := generateTestCert(t)
	_, err := Convert("test.example.com", certPEM, keyPEM, "badformat", "")
	if err == nil {
		t.Error("expected error for unknown format")
	}
}
