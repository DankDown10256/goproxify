// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

// watchTailBytes est la fin de sortie renvoyée à un observateur qui rejoint une session déjà commencée.
const watchTailBytes = 32 << 10

// Publish diffuse la sortie du terminal aux observateurs. Un observateur trop lent perd des morceaux
// plutôt que de ralentir la session.
func (h *LiveHandle) Publish(p []byte) {
	if h == nil || h.e == nil || len(p) == 0 {
		return
	}
	e := h.e
	e.subMu.Lock()
	defer e.subMu.Unlock()
	e.tail = append(e.tail, p...)
	if extra := len(e.tail) - watchTailBytes; extra > 0 {
		e.tail = append([]byte(nil), e.tail[extra:]...)
	}
	if len(e.subs) == 0 {
		return
	}
	chunk := append([]byte(nil), p...)
	for ch := range e.subs {
		select {
		case ch <- chunk:
		default:
		}
	}
}

func (e *liveEntry) closeSubs() {
	e.subMu.Lock()
	defer e.subMu.Unlock()
	e.closed = true
	for ch := range e.subs {
		close(ch)
		delete(e.subs, ch)
	}
}

// Subscribe s'abonne à la sortie d'une connexion en cours : retourne la fin déjà émise, un canal
// (fermé quand la session se termine) et la fonction de désabonnement.
func (r *LiveRegistry) Subscribe(id string) (meta LiveSession, backlog []byte, ch <-chan []byte, cancel func(), ok bool) {
	r.mu.Lock()
	e, found := r.m[id]
	r.mu.Unlock()
	if !found {
		return LiveSession{}, nil, nil, nil, false
	}
	e.subMu.Lock()
	defer e.subMu.Unlock()
	if e.closed {
		return LiveSession{}, nil, nil, nil, false
	}
	if e.subs == nil {
		e.subs = map[chan []byte]struct{}{}
	}
	c := make(chan []byte, 256)
	e.subs[c] = struct{}{}
	backlog = append([]byte(nil), e.tail...)
	return e.meta, backlog, c, func() {
		e.subMu.Lock()
		defer e.subMu.Unlock()
		if _, live := e.subs[c]; live {
			delete(e.subs, c)
			close(c)
		}
	}, true
}
