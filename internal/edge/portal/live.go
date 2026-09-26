// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

// LiveSession décrit une connexion pontée en cours (métadonnées uniquement).
type LiveSession struct {
	ID       string `json:"id"`
	Actor    string `json:"actor"`
	TargetID string `json:"target_id"`
	Facade   string `json:"facade"`
	Remote   string `json:"remote,omitempty"`
	Since    string `json:"since"`
}

type liveEntry struct {
	meta   LiveSession
	since  time.Time
	kill   func()
	last   atomic.Int64 // dernière activité, UnixNano

	subMu  sync.Mutex
	subs   map[chan []byte]struct{}
	tail   []byte
	closed bool
	reaped bool
}

// LiveHandle permet à un pont de signaler son activité et de se désinscrire.
type LiveHandle struct {
	r *LiveRegistry
	e *liveEntry
}

// Touch enregistre une activité (octets échangés).
func (h *LiveHandle) Touch() {
	if h != nil && h.e != nil {
		h.e.last.Store(time.Now().UnixNano())
	}
}

// Done retire la connexion du registre.
func (h *LiveHandle) Done() {
	if h == nil || h.r == nil {
		return
	}
	h.r.remove(h.e.meta.ID)
}

// LiveRegistry recense les connexions pontées en cours et permet de les terminer.
type LiveRegistry struct {
	mu       sync.Mutex
	m        map[string]*liveEntry
	onChange func()
}

// NewLiveRegistry crée un registre vide.
func NewLiveRegistry() *LiveRegistry {
	return &LiveRegistry{m: map[string]*liveEntry{}}
}

// SetOnChange enregistre le rappel appelé après chaque ajout ou retrait.
func (r *LiveRegistry) SetOnChange(fn func()) {
	r.mu.Lock()
	r.onChange = fn
	r.mu.Unlock()
}

// Track enregistre une connexion ; kill ferme le pont. Un registre nul retourne une poignée inerte.
func (r *LiveRegistry) Track(actor, targetID, facade, remote string, kill func()) *LiveHandle {
	if r == nil {
		return nil
	}
	now := time.Now().UTC()
	id := uuid.NewString()
	e := &liveEntry{
		meta:  LiveSession{ID: id, Actor: actor, TargetID: targetID, Facade: facade, Remote: remote, Since: now.Format(time.RFC3339)},
		since: now,
		kill:  kill,
	}
	e.last.Store(now.UnixNano())
	r.mu.Lock()
	r.m[id] = e
	fn := r.onChange
	r.mu.Unlock()
	if fn != nil {
		fn()
	}
	return &LiveHandle{r: r, e: e}
}

// Add enregistre une connexion et retourne la fonction à appeler à sa fin.
func (r *LiveRegistry) Add(actor, targetID, facade, remote string, kill func()) (done func()) {
	return r.Track(actor, targetID, facade, remote, kill).Done
}

func (r *LiveRegistry) remove(id string) {
	r.mu.Lock()
	e, ok := r.m[id]
	delete(r.m, id)
	fn := r.onChange
	r.mu.Unlock()
	if ok {
		e.closeSubs()
	}
	if ok && fn != nil {
		fn()
	}
}

// List retourne les connexions en cours, les plus anciennes d'abord.
func (r *LiveRegistry) List() []LiveSession {
	r.mu.Lock()
	entries := make([]*liveEntry, 0, len(r.m))
	for _, e := range r.m {
		entries = append(entries, e)
	}
	r.mu.Unlock()
	sort.Slice(entries, func(i, j int) bool { return entries[i].since.Before(entries[j].since) })
	out := make([]LiveSession, len(entries))
	for i, e := range entries {
		out[i] = e.meta
	}
	return out
}

// Kill ferme la connexion ; false si elle n'existe plus.
func (r *LiveRegistry) Kill(id string) bool {
	r.mu.Lock()
	e, ok := r.m[id]
	r.mu.Unlock()
	if !ok {
		return false
	}
	e.kill()
	return true
}

// ReapIdle ferme les connexions sans activité depuis plus de timeout et retourne celles qu'il vient de fermer.
func (r *LiveRegistry) ReapIdle(timeout time.Duration, now time.Time) []LiveSession {
	if r == nil || timeout <= 0 {
		return nil
	}
	var victims []*liveEntry
	r.mu.Lock()
	for _, e := range r.m {
		if !e.reaped && now.Sub(time.Unix(0, e.last.Load())) > timeout {
			e.reaped = true
			victims = append(victims, e)
		}
	}
	r.mu.Unlock()
	out := make([]LiveSession, 0, len(victims))
	for _, e := range victims {
		e.kill()
		out = append(out, e.meta)
	}
	return out
}

// touchChannel signale l'activité de l'utilisateur (données reçues du client SSH) et enregistre
// la sortie envoyée à son terminal.
type touchChannel struct {
	ssh.Channel
	h   *LiveHandle
	rec *Recording
}

func (c touchChannel) Read(p []byte) (int, error) {
	n, err := c.Channel.Read(p)
	if n > 0 {
		c.h.Touch()
	}
	return n, err
}

func (c touchChannel) Write(p []byte) (int, error) {
	n, err := c.Channel.Write(p)
	c.h.Publish(p[:n])
	c.rec.Output(p[:n])
	return n, err
}

// touchRW signale l'activité de l'utilisateur (données reçues du navigateur) et enregistre
// la sortie envoyée à son terminal.
type touchRW struct {
	io.ReadWriteCloser
	h   *LiveHandle
	rec *Recording
}

func (c touchRW) Read(p []byte) (int, error) {
	n, err := c.ReadWriteCloser.Read(p)
	if n > 0 {
		c.h.Touch()
	}
	return n, err
}

func (c touchRW) Write(p []byte) (int, error) {
	n, err := c.ReadWriteCloser.Write(p)
	c.h.Publish(p[:n])
	c.rec.Output(p[:n])
	return n, err
}
