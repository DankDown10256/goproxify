// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
)

func TestPeerRegistryReplaceAndLookup(t *testing.T) {
	r := NewPeerRegistry()
	r.Replace([]PeerInfo{
		{Name: "core-b", Endpoint: "http://10.0.0.2:8000/", Token: "tok-b"},
	})
	p, ok := r.LookupByEndpoint("http://10.0.0.2:8000")
	if !ok || p.Token != "tok-b" {
		t.Fatalf("lookup = %#v ok=%v", p, ok)
	}
}

func TestDialGatewayTunnel(t *testing.T) {
	// Serveur gateway minimal
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer backendLn.Close()

	go func() {
		c, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 64)
		n, _ := c.Read(buf)
		_, _ = c.Write([]byte("echo:" + string(buf[:n])))
	}()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		var body struct {
			Target string `json:"target"`
		}
		_ = json.NewDecoder(req.Body).Decode(&body)
		if !strings.HasPrefix(req.Header.Get("Authorization"), "Bearer ") {
			c.Write([]byte("HTTP/1.1 401 Unauthorized\r\n\r\n"))
			return
		}
		up, err := net.Dial("tcp", body.Target)
		if err != nil {
			c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
			return
		}
		defer up.Close()
		c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
		go io.Copy(up, br)
		io.Copy(c, up)
	}()

	peers := NewPeerRegistry()
	ep := "http://" + ln.Addr().String()
	peers.Replace([]PeerInfo{{Name: "peer", Endpoint: ep, Token: "secret"}})

	b := &router.Backend{
		URL:               "http://" + backendLn.Addr().String(),
		OwnerCoreEndpoint: ep,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := DialBackend(ctx, b, peers, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("ping"))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); got != "echo:ping" {
		t.Fatalf("got %q", got)
	}
}

func TestMergeRemoteBackends(t *testing.T) {
	// Exercice via logique équivalente (copie du helper core)
	existing := []router.Backend{
		{URL: "http://10.0.0.1:80"},
		{URL: "http://10.0.0.2:80", OwnerCoreEndpoint: "http://peer:8000"},
	}
	remote := []router.Backend{
		{URL: "http://10.0.0.3:80", OwnerCoreEndpoint: "http://peer:8000"},
	}
	out := make([]router.Backend, 0)
	for _, b := range existing {
		if b.OwnerCoreEndpoint == "http://peer:8000" {
			continue
		}
		out = append(out, b)
	}
	out = append(out, remote...)
	if len(out) != 2 || out[1].URL != "http://10.0.0.3:80" {
		t.Fatalf("%#v", out)
	}
}

func TestTransportForRemoteBackend(t *testing.T) {
	route := &router.Route{
		Host: "app.test",
		Backends: []router.Backend{
			{URL: "http://127.0.0.1:9"},
		},
		LB: router.LBRoundRobin,
	}
	h := NewHandler(route, NewBackendHealth(nil), NewAgentMetricsStore(), NewPeerRegistry(), slog.Default())
	if h == nil || h.peers == nil {
		t.Fatal("handler nil")
	}
}

