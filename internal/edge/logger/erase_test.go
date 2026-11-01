// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logstore"
)

func TestEraseIPRemovesClearAndPseudonymizedEntries(t *testing.T) {
	s, _ := testStore(t)
	a := NewAccessLogger()
	a.SetStore(s)
	for _, e := range []logstore.Entry{
		{IP: "203.0.113.42"},
		{IP: "203.0.113.0", RealIP: "203.0.113.42", IPTruncated: true},
		{IP: "2001:DB8:0:0:0:0:0:1"},
		{IP: "198.51.100.9"},
	} {
		e.Ts = time.Now().UTC()
		if !s.Add(logstore.KindAccess, e) {
			t.Fatal("entry rejected")
		}
	}
	if n, err := a.EraseIP("::ffff:203.0.113.42"); err != nil || n != 2 {
		t.Fatalf("IPv4: n=%d err=%v, want 2", n, err)
	}
	if n, err := a.EraseIP("2001:db8::1"); err != nil || n != 1 {
		t.Fatalf("IPv6: n=%d err=%v, want 1", n, err)
	}
	rows, err := s.ReadAfter(logstore.KindAccess, 0, 10)
	if err != nil || len(rows) != 1 || rows[0].IP != "198.51.100.9" {
		t.Fatalf("remaining entries: %+v err=%v", rows, err)
	}
	if !s.Add(logstore.KindAccess, logstore.Entry{Ts: time.Now().UTC(), IP: "192.0.2.1"}) {
		t.Fatal("entry rejected after erasure")
	}
	s.Flush()
	rows, err = s.ReadAfter(logstore.KindAccess, 0, 10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("logging after erasure: %d entries, err=%v", len(rows), err)
	}
}

func TestEraseIPWithoutStoreIsANoop(t *testing.T) {
	a := NewAccessLogger()
	if n, err := a.EraseIP("203.0.113.42"); err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}
