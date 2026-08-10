// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"sync"
	"testing"
	"time"
)

func TestDynamicLoggerForwarder(t *testing.T) {
	dl := New("info", "json", "")
	var (
		mu  sync.Mutex
		got []ShipEntry
	)
	done := make(chan struct{})
	dl.SetNodeName("core-test")
	dl.SetForwarder(func(batch []ShipEntry) {
		mu.Lock()
		got = append(got, batch...)
		mu.Unlock()
		select {
		case <-done:
		default:
			close(done)
		}
	})

	dl.Info("hello system", "domain", "example.com", "err", "none")

	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatal("timeout waiting for system log ship")
	}

	mu.Lock()
	defer mu.Unlock()
	if len(got) == 0 {
		t.Fatal("expected shipped entries")
	}
	e := got[0]
	if e.Component != "core" {
		t.Errorf("component=%q want core", e.Component)
	}
	if e.Status != 0 {
		t.Errorf("status=%d want 0 (system)", e.Status)
	}
	if e.NodeName != "core-test" {
		t.Errorf("node_name=%q want core-test", e.NodeName)
	}
	if e.Domain != "example.com" {
		t.Errorf("domain=%q want example.com", e.Domain)
	}
	if e.Method != "" || e.Path != "" {
		t.Errorf("system log must not have method/path: %q %q", e.Method, e.Path)
	}
	if e.Message == "" || e.Message[:5] != "hello" {
		t.Errorf("message=%q", e.Message)
	}
}
