// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

// Session est un jeton UUID en mémoire (non sync HA).
type Session struct {
	ID        string
	UserID    string
	Username  string
	TargetID  string
	Target    dialTarget
	Facade    SessionFacade
	Mode      string
	CreatedAt time.Time
	ExpiresAt time.Time
	Used      bool
}

// SessionMeta métadonnées exposées (sans secrets).
type SessionMeta struct {
	ID        string        `json:"id"`
	TargetID  string        `json:"target_id"`
	Facade    SessionFacade `json:"facade"`
	CreatedAt string        `json:"created_at"`
	ExpiresAt string        `json:"expires_at"`
	Used      bool          `json:"used"`
}

type dialTarget struct {
	Kind       TargetKind
	Host       string
	Port       int
	Username   string
	Password   string
	PrivateKey string
	AgentName  string
	Container  string
}

// SessionManager gère les UUID one-shot / multi + TTL.
type SessionManager struct {
	mu   sync.Mutex
	byID map[string]*Session
}

// NewSessionManager crée un manager vide.
func NewSessionManager() *SessionManager {
	return &SessionManager{byID: map[string]*Session{}}
}

// Create enregistre une nouvelle session avec TTL et mode explicites.
func (m *SessionManager) Create(userID, username, targetID string, target dialTarget, facade SessionFacade, ttl time.Duration, mode string) *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeLocked(time.Now())
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	if mode != SessionModeMulti {
		mode = SessionModeOneShot
	}
	now := time.Now().UTC()
	s := &Session{
		ID:        uuid.NewString(),
		UserID:    userID,
		Username:  username,
		TargetID:  targetID,
		Target:    target,
		Facade:    facade,
		Mode:      mode,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	m.byID[s.ID] = s
	return s
}

// Peek retourne la session sans la consommer.
func (m *SessionManager) Peek(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeLocked(time.Now())
	s, ok := m.byID[id]
	if !ok || s.Used || time.Now().After(s.ExpiresAt) {
		return nil, false
	}
	return s, true
}

// Consume marque la session utilisée (one-shot) et la retourne.
func (m *SessionManager) Consume(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeLocked(time.Now())
	s, ok := m.byID[id]
	if !ok || s.Used || time.Now().After(s.ExpiresAt) {
		return nil, false
	}
	s.Used = true
	delete(m.byID, id)
	return s, true
}

// Acquire respecte le mode de la session (one_shot|multi).
func (m *SessionManager) Acquire(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeLocked(time.Now())
	s, ok := m.byID[id]
	if !ok || s.Used || time.Now().After(s.ExpiresAt) {
		return nil, false
	}
	if s.Mode == SessionModeMulti {
		return s, true
	}
	s.Used = true
	delete(m.byID, id)
	return s, true
}

// Invalidate supprime une session.
func (m *SessionManager) Invalidate(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byID, id)
}

// RevokeForUser invalide si la session appartient à userID.
func (m *SessionManager) RevokeForUser(id, userID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.byID[id]
	if !ok || s.UserID != userID {
		return false
	}
	delete(m.byID, id)
	return true
}

// ListForUser retourne les sessions actives de l'utilisateur (sans secrets).
func (m *SessionManager) ListForUser(userID string) []SessionMeta {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.purgeLocked(time.Now())
	out := []SessionMeta{}
	for _, s := range m.byID {
		if s.UserID != userID || s.Used {
			continue
		}
		out = append(out, SessionMeta{
			ID: s.ID, TargetID: s.TargetID, Facade: s.Facade,
			CreatedAt: s.CreatedAt.Format(time.RFC3339),
			ExpiresAt: s.ExpiresAt.Format(time.RFC3339),
			Used:      s.Used,
		})
	}
	return out
}

func (m *SessionManager) purgeLocked(now time.Time) {
	for id, s := range m.byID {
		if s.Used || now.After(s.ExpiresAt) {
			delete(m.byID, id)
		}
	}
}
