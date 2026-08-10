// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	corews "github.com/vincamok/goproxify/internal/core/ws"
)

type mockShellHub struct {
	mu     sync.Mutex
	online map[string]bool
	sent   []corews.Message
	onSend func(name string, msg corews.Message)
}

func (m *mockShellHub) IsAgentConnected(name string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.online[name]
}

func (m *mockShellHub) SendToAgentByName(name string, msg corews.Message) error {
	m.mu.Lock()
	m.sent = append(m.sent, msg)
	fn := m.onSend
	m.mu.Unlock()
	if fn != nil {
		fn(name, msg)
	}
	return nil
}

func TestShellBrokerOpenReady(t *testing.T) {
	hub := &mockShellHub{online: map[string]bool{"agent1": true}}
	b := NewShellBroker(hub)
	hub.onSend = func(_ string, msg corews.Message) {
		if msg.Type != corews.TypeShellOpen {
			return
		}
		var p corews.ShellOpenPayload
		_ = json.Unmarshal(msg.Payload, &p)
		ready, _ := corews.NewMessage(0, corews.TypeShellReady, corews.ShellReadyPayload{SessionID: p.SessionID})
		go b.HandleAgentMessage(ready.Type, ready.Payload)
	}

	rw, err := b.Open("agent1", "ctr1")
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()

	hub.mu.Lock()
	n := len(hub.sent)
	hub.mu.Unlock()
	if n < 1 {
		t.Fatal("expected shell_open sent")
	}
}

func TestShellBrokerOpenError(t *testing.T) {
	hub := &mockShellHub{online: map[string]bool{"agent1": true}}
	b := NewShellBroker(hub)
	hub.onSend = func(_ string, msg corews.Message) {
		if msg.Type != corews.TypeShellOpen {
			return
		}
		var p corews.ShellOpenPayload
		_ = json.Unmarshal(msg.Payload, &p)
		errMsg, _ := corews.NewMessage(0, corews.TypeShellError, corews.ShellErrorPayload{
			SessionID: p.SessionID, Error: "no such container",
		})
		go b.HandleAgentMessage(errMsg.Type, errMsg.Payload)
	}

	_, err := b.Open("agent1", "missing")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestShellBrokerAgentOffline(t *testing.T) {
	hub := &mockShellHub{online: map[string]bool{}}
	b := NewShellBroker(hub)
	_, err := b.Open("agent1", "ctr")
	if err == nil {
		t.Fatal("expected offline error")
	}
}

func TestShellBrokerRoundTripData(t *testing.T) {
	hub := &mockShellHub{online: map[string]bool{"agent1": true}}
	b := NewShellBroker(hub)
	var sessionID string
	hub.onSend = func(_ string, msg corews.Message) {
		switch msg.Type {
		case corews.TypeShellOpen:
			var p corews.ShellOpenPayload
			_ = json.Unmarshal(msg.Payload, &p)
			sessionID = p.SessionID
			ready, _ := corews.NewMessage(0, corews.TypeShellReady, corews.ShellReadyPayload{SessionID: p.SessionID})
			go b.HandleAgentMessage(ready.Type, ready.Payload)
		case corews.TypeShellData:
			var p corews.ShellDataPayload
			_ = json.Unmarshal(msg.Payload, &p)
			// echo back
			echo, _ := corews.NewMessage(0, corews.TypeShellData, p)
			go b.HandleAgentMessage(echo.Type, echo.Payload)
		}
	}

	rw, err := b.Open("agent1", "ctr1")
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()
	if sessionID == "" {
		t.Fatal("no session id")
	}
	if _, err := rw.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8)
	done := make(chan error, 1)
	go func() {
		_, e := rw.Read(buf)
		done <- e
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
		if string(buf[:2]) != "hi" {
			t.Fatalf("got %q", buf[:2])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("read timeout")
	}
}
