// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSessionAcquireOneShot(t *testing.T) {
	m := NewSessionManager()
	s := m.Create("u", "alice", "t1", dialTarget{Kind: TargetSSH, Host: "h", Port: 22}, FacadeSSH, DefaultSessionTTL, SessionModeOneShot)
	if _, ok := m.Acquire(s.ID); !ok {
		t.Fatal("first acquire")
	}
	if _, ok := m.Acquire(s.ID); ok {
		t.Fatal("second acquire must fail (one_shot)")
	}
}

func TestSessionAcquireMulti(t *testing.T) {
	m := NewSessionManager()
	s := m.Create("u", "alice", "t1", dialTarget{Kind: TargetSSH, Host: "h", Port: 22}, FacadeWeb, time.Minute, SessionModeMulti)
	if _, ok := m.Acquire(s.ID); !ok {
		t.Fatal("first")
	}
	if _, ok := m.Acquire(s.ID); !ok {
		t.Fatal("second must succeed (multi)")
	}
	list := m.ListForUser("u")
	if len(list) != 1 {
		t.Fatalf("list=%d", len(list))
	}
}

func TestSessionTTLExpired(t *testing.T) {
	m := NewSessionManager()
	s := m.Create("u", "alice", "t1", dialTarget{Kind: TargetSSH, Host: "h", Port: 22}, FacadeSSH, 20*time.Millisecond, SessionModeMulti)
	time.Sleep(40 * time.Millisecond)
	if _, ok := m.Acquire(s.ID); ok {
		t.Fatal("expired must fail")
	}
	if len(m.ListForUser("u")) != 0 {
		t.Fatal("expired purged from list")
	}
}

func TestSessionRevoke(t *testing.T) {
	m := NewSessionManager()
	s := m.Create("u1", "alice", "t1", dialTarget{Kind: TargetSSH, Host: "h", Port: 22}, FacadeSSH, time.Minute, SessionModeOneShot)
	if m.RevokeForUser(s.ID, "other") {
		t.Fatal("wrong user")
	}
	if !m.RevokeForUser(s.ID, "u1") {
		t.Fatal("revoke")
	}
	if _, ok := m.Acquire(s.ID); ok {
		t.Fatal("revoked")
	}
	if len(m.ListForUser("u1")) != 0 {
		t.Fatal("list empty")
	}
}

func TestAuditMetadataOnly(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(filepath.Join(dir, "portal.gpx"), "audit-key")
	e := AuditEvent{
		Ts: time.Now().UTC(), Actor: "alice", TargetID: "dest-1",
		Facade: FacadeSSH, Success: true, Detail: "session_created",
	}
	if err := s.AppendAudit(e); err != nil {
		t.Fatal(err)
	}
	got := s.ListAuditForUser("alice", 10)
	if len(got) != 1 {
		t.Fatalf("got %d", len(got))
	}
	if strings.Contains(got[0].Detail, "password") || strings.Contains(got[0].Detail, "BEGIN") {
		t.Fatal("audit must not carry secrets")
	}
	if got[0].TargetID != "dest-1" || got[0].Facade != FacadeSSH {
		t.Fatalf("%+v", got[0])
	}
	if len(s.ListAuditForUser("bob", 10)) != 0 {
		t.Fatal("other user")
	}
}
