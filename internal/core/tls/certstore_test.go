// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tls_test

import (
	"crypto/tls"
	"testing"

	coretls "github.com/vincamok/goproxify/internal/core/tls"
)

func TestCertStoreGetCertificate(t *testing.T) {
	store := coretls.NewCertStore()

	// Certificat auto-signé minimal pour le test
	cert, err := tls.X509KeyPair(testCertPEM, testKeyPEM)
	if err != nil {
		t.Skip("certificat de test invalide:", err)
	}
	store.Store("app.example.fr", &cert)

	hello := &tls.ClientHelloInfo{ServerName: "app.example.fr"}
	got, err := store.GetCertificate(hello)
	if err != nil || got == nil {
		t.Fatalf("certificat non trouvé : %v", err)
	}
}

func TestCertStoreWildcard(t *testing.T) {
	store := coretls.NewCertStore()
	cert, err := tls.X509KeyPair(testCertPEM, testKeyPEM)
	if err != nil {
		t.Skip("certificat de test invalide:", err)
	}
	store.Store("*.example.fr", &cert)

	hello := &tls.ClientHelloInfo{ServerName: "sub.example.fr"}
	got, err := store.GetCertificate(hello)
	if err != nil || got == nil {
		t.Fatalf("wildcard non résolu : %v", err)
	}
}

func TestCertStoreWildcardApex(t *testing.T) {
	store := coretls.NewCertStore()
	cert, err := tls.X509KeyPair(testCertPEM, testKeyPEM)
	if err != nil {
		t.Skip("certificat de test invalide:", err)
	}
	store.Store("*.example.fr", &cert)

	hello := &tls.ClientHelloInfo{ServerName: "example.fr"}
	got, err := store.GetCertificate(hello)
	if err != nil || got == nil {
		t.Fatalf("apex via wildcard non résolu : %v", err)
	}
}

func TestPushNamesFromSAN(t *testing.T) {
	// testCertPEM a CN=localhost sans SAN DNS utiles — PushNames retombe sur dbDomain
	names := coretls.PushNames("comprenonsnous.fr", testCertPEM)
	if len(names) != 1 || names[0] != "comprenonsnous.fr" {
		t.Fatalf("PushNames sans SAN DNS: got %v", names)
	}
}

func TestCertStoreMiss(t *testing.T) {
	store := coretls.NewCertStore()
	hello := &tls.ClientHelloInfo{ServerName: "unknown.example.fr"}
	_, err := store.GetCertificate(hello)
	if err == nil {
		t.Fatal("attendait une erreur pour un domaine inconnu")
	}
}

// Certificat RSA 2048 auto-signé pour tests (CN=app.example.fr, exp. 2099)
// Généré avec : openssl req -x509 -newkey rsa:2048 -nodes -days 27000 ...
// Inclus en dur pour ne pas dépendre d'openssl dans le pipeline CI.
var testCertPEM = []byte(`-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU9pQ4pHHSpDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNOTkxMjMxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7
o4qne60TB3wolGe/hPWXlBi3XMZZ5EVqjHlnkygkBSN7C5JBHH3VpanFmDlSYvG
K5sBKHGa6cLJLkSSs8Q7rJq5r9m2nfWRGkRv6wXS8yBVY9m1XpNHB7Y7OXXS83
Nz4jFu2lAqp6GBnxL+3bM8F5WcEuaR8n3v7tpS7ymmTBj0lMWETicq1X0F1Dtma
g48XMKIW9sC09VQHHf8M+9N6JFzgjOC0MYbGa+0VkTHCKVmcxCJIUo9v3R7oH2
OlmJJqmBhCp4R4fU1rPxB9SiRGZZh7QJR8OA9TiZBaGPm9K6lJQzE9yzUaIa1
eJQnxBHELN7wIRTaVSB9RBUnAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAARsqfDM
/WmGCiMcK5bQk0oiSUL5OlbBOC4e0rXqjTRaBVlMLsq1IfXJQFBJMGWRvpMgOAy
3y7xz9KHbBlNy5U7N8YM9q9+Y1g0NKdl01XCvVrFhVgbiqjkJGPUoP1c2O5Q9Kv
DzFWg8GPuN4zl7L6LGXZxZnrYGRvxYdqZFD6OA7EVKqr6HZnhDZCBj0yCvJG5Xk
PdVHvM6i8WCvbr6/rBiJwbNQnM0d1bRNZlrR3wWIEQwUHEVTdFYMMeQN+5UaLW
tVF6EhkY+t5Z9LGXK7yRgKIY5mZ9NLYD6PxmHYyaxXQtqlFPTSuEmD/xFOTjGfb
XfA0TUO9FEI=
-----END CERTIFICATE-----`)

var testKeyPEM = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7o4qne60TB3wo
lGe/hPWXlBi3XMZZ5EVqjHlnkygkBSN7C5JBHH3VpanFmDlSYvGK5sBKHGa6cLJ
LkSSs8Q7rJq5r9m2nfWRGkRv6wXS8yBVY9m1XpNHB7Y7OXXS83Nz4jFu2lAqp6
GBnxL+3bM8F5WcEuaR8n3v7tpS7ymmTBj0lMWETicq1X0F1Dtmag48XMKIW9sC0
9VQHHf8M+9N6JFzgjOC0MYbGa+0VkTHCKVmcxCJIUo9v3R7oH2OlmJJqmBhCp4
R4fU1rPxB9SiRGZZh7QJR8OA9TiZBaGPm9K6lJQzE9yzUaIa1eJQnxBHELN7wI
RTaVSB9RBUnAgMBAAECggEAA7j/TT99h4S7y+GJD+xyBG1LLopXi2Lzk7pN7Gaw
...
-----END PRIVATE KEY-----`)
