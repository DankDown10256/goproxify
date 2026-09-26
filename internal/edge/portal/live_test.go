// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"testing"
	"time"
)

func TestLiveRegistryAddKillDone(t *testing.T) {
	r := NewLiveRegistry()
	changes := 0
	r.SetOnChange(func() { changes++ })

	killed := false
	done := r.Add("alice", "srv-1", "ssh", "1.2.3.4:5", func() { killed = true })
	if got := r.List(); len(got) != 1 || got[0].Actor != "alice" || got[0].TargetID != "srv-1" {
		t.Fatalf("list: %+v", got)
	}
	id := r.List()[0].ID
	if !r.Kill(id) || !killed {
		t.Fatal("kill n'a pas appelé la fonction de fermeture")
	}
	done()
	if len(r.List()) != 0 || r.Kill(id) {
		t.Fatal("la connexion doit disparaître après done")
	}
	if changes != 2 {
		t.Fatalf("onChange attendu 2 fois, reçu %d", changes)
	}
	done()
	if changes != 2 {
		t.Fatal("un second done ne doit pas notifier")
	}
}

func TestLiveRegistryNilSafe(t *testing.T) {
	var r *LiveRegistry
	r.Add("a", "b", "web", "", func() {})()
}

func TestLiveRegistryReapIdle(t *testing.T) {
	r := NewLiveRegistry()
	killedIdle, killedBusy := 0, 0
	idle := r.Track("a", "t1", "ssh", "", func() { killedIdle++ })
	busy := r.Track("b", "t2", "web", "", func() { killedBusy++ })
	_ = idle

	later := time.Now().Add(20 * time.Minute)
	busy.e.last.Store(later.Add(-time.Minute).UnixNano())

	got := r.ReapIdle(15*time.Minute, later)
	if len(got) != 1 || got[0].Actor != "a" || killedIdle != 1 || killedBusy != 0 {
		t.Fatalf("reap: %+v idle=%d busy=%d", got, killedIdle, killedBusy)
	}
	if again := r.ReapIdle(15*time.Minute, later); len(again) != 0 || killedIdle != 1 {
		t.Fatal("une connexion déjà fermée ne doit pas l'être deux fois")
	}
	busy.Touch()
	if len(r.ReapIdle(0, later)) != 0 {
		t.Fatal("timeout nul: aucune fermeture")
	}
}

func TestLiveWatchBacklogStreamAndEnd(t *testing.T) {
	r := NewLiveRegistry()
	h := r.Track("alice", "srv", "ssh", "", func() {})
	h.Publish([]byte("avant "))

	id := r.List()[0].ID
	meta, backlog, ch, cancel, ok := r.Subscribe(id)
	if !ok || meta.Actor != "alice" || string(backlog) != "avant " {
		t.Fatalf("subscribe: %+v %q %v", meta, backlog, ok)
	}
	defer cancel()

	h.Publish([]byte("après"))
	select {
	case p := <-ch:
		if string(p) != "après" {
			t.Fatalf("flux: %q", p)
		}
	case <-time.After(time.Second):
		t.Fatal("aucun morceau reçu")
	}

	// Un observateur lent ne bloque pas la session.
	for i := 0; i < 1000; i++ {
		h.Publish([]byte("x"))
	}

	h.Done()
	deadline := time.After(time.Second)
	for {
		select {
		case _, open := <-ch:
			if !open {
				if _, _, _, _, ok := r.Subscribe(id); ok {
					t.Fatal("s'abonner à une session terminée doit échouer")
				}
				return
			}
		case <-deadline:
			t.Fatal("le canal doit se fermer à la fin de la session")
		}
	}
}
