// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tls_test

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"

	coretls "github.com/vincamok/goproxify/internal/core/tls"
)

// clientHelloWithSNI est un ClientHello TLS 1.2 minimal avec SNI "app.example.fr".
// Longueurs record/handshake alignées sur le payload réel (sinon PeekSNI attend
// plus d’octets et renvoie EOF sur un buffer fermé).
var clientHelloWithSNI = []byte{
	// TLS Record: Handshake (0x16), TLS 1.0 (0x03 0x01), length = 70 (0x0046)
	0x16, 0x03, 0x01, 0x00, 0x46,
	// Handshake: ClientHello (0x01), length = 66 (0x000042)
	0x01, 0x00, 0x00, 0x42,
	// version TLS 1.2
	0x03, 0x03,
	// random (32 bytes)
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	// session_id length = 0
	0x00,
	// cipher_suites length = 2, one suite
	0x00, 0x02, 0x00, 0x2f,
	// compression methods length = 1, null
	0x01, 0x00,
	// extensions length = 23 (0x0017)
	0x00, 0x17,
	// Extension: server_name (0x0000)
	0x00, 0x00,
	// extension data length = 19 (0x0013)
	0x00, 0x13,
	// server name list length = 17 (0x0011)
	0x00, 0x11,
	// name type = host_name (0x00)
	0x00,
	// name length = 14 (0x000e) = len("app.example.fr")
	0x00, 0x0e,
	// "app.example.fr"
	0x61, 0x70, 0x70, 0x2e, 0x65, 0x78, 0x61, 0x6d,
	0x70, 0x6c, 0x65, 0x2e, 0x66, 0x72,
}

func TestPeekSNI(t *testing.T) {
	conn := &mockConn{buf: bytes.NewBuffer(clientHelloWithSNI)}
	sni, peeked, err := coretls.PeekSNI(conn)
	if err != nil {
		t.Fatalf("PeekSNI: %v", err)
	}
	if sni != "app.example.fr" {
		t.Fatalf("SNI = %q, want app.example.fr", sni)
	}
	// Les octets peekés doivent être rejouables intégralement.
	got, err := io.ReadAll(peeked)
	if err != nil {
		t.Fatalf("lecture peeked: %v", err)
	}
	if !bytes.Equal(got, clientHelloWithSNI) {
		t.Fatalf("replay tronqué: got %d octets, want %d", len(got), len(clientHelloWithSNI))
	}
}

func TestPeekSNILargeFragmentedClientHello(t *testing.T) {
	// Simule un vrai ClientHello TLS (souvent > 1 KiB avec navigateurs modernes).
	raw := captureClientHello(t, "api.dankdown.fr")
	if len(raw) < 1024 {
		t.Fatalf("ClientHello trop petit pour le test (%d) — attendu > 1 KiB", len(raw))
	}

	// Livraison fragmentée (comme plusieurs segments TCP).
	conn := &chunkConn{data: raw, chunk: 200}
	sni, peeked, err := coretls.PeekSNI(conn)
	if err != nil {
		t.Fatalf("PeekSNI: %v", err)
	}
	if sni != "api.dankdown.fr" {
		t.Fatalf("SNI = %q, want api.dankdown.fr (record=%d octets)", sni, len(raw))
	}
	got, err := io.ReadAll(peeked)
	if err != nil {
		t.Fatalf("lecture peeked: %v", err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("replay incorrect: got %d want %d", len(got), len(raw))
	}
}

func captureClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	helloCh := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 16<<10)
		n, err := c.Read(buf)
		if err != nil {
			errCh <- err
			return
		}
		helloCh <- append([]byte(nil), buf[:n]...)
	}()

	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			errCh <- err
			return
		}
		defer c.Close()
		tc := tls.Client(c, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		})
		// Handshake échouera (pas de serveur TLS) mais le ClientHello est déjà parti.
		_ = tc.Handshake()
	}()

	select {
	case raw := <-helloCh:
		return raw
	case err := <-errCh:
		t.Fatalf("capture ClientHello: %v", err)
		return nil
	case <-time.After(5 * time.Second):
		t.Fatal("timeout capture ClientHello")
		return nil
	}
}

type mockConn struct {
	buf *bytes.Buffer
}

func (m *mockConn) Read(b []byte) (int, error)         { return m.buf.Read(b) }
func (m *mockConn) Write(b []byte) (int, error)        { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (m *mockConn) SetDeadline(_ time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(_ time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(_ time.Time) error { return nil }

// chunkConn livre les données par petits paquets (TCP fragmenté).
type chunkConn struct {
	data  []byte
	off   int
	chunk int
}

func (c *chunkConn) Read(b []byte) (int, error) {
	if c.off >= len(c.data) {
		return 0, io.EOF
	}
	n := c.chunk
	if n > len(b) {
		n = len(b)
	}
	if c.off+n > len(c.data) {
		n = len(c.data) - c.off
	}
	copy(b, c.data[c.off:c.off+n])
	c.off += n
	return n, nil
}
func (c *chunkConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *chunkConn) Close() error                       { return nil }
func (c *chunkConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *chunkConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *chunkConn) SetDeadline(_ time.Time) error      { return nil }
func (c *chunkConn) SetReadDeadline(_ time.Time) error  { return nil }
func (c *chunkConn) SetWriteDeadline(_ time.Time) error { return nil }
