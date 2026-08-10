// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// AuthSession est un jeton bearer portail (persisté pour survivre aux redémarrages).
type AuthSession struct {
	UserID   string    `json:"user_id"`
	Username string    `json:"username"`
	VaultKey string    `json:"vault_key"` // hex 32 octets
	Expires  time.Time `json:"expires"`
}

// Snapshot est le contenu chiffré de la base portail.
type Snapshot struct {
	SavedAt      time.Time                   `json:"saved_at"`
	Users        []UserRecord                `json:"users"`
	Vaults       map[string][]byte           `json:"vaults"`   // userID → blob vault chiffré (clé user)
	Personal     map[string][]PersonalTarget `json:"personal"` // userID → cibles
	Catalog      []CatalogTarget             `json:"catalog"`
	AuthSessions map[string]AuthSession      `json:"auth_sessions,omitempty"`
	Audit        []AuditEvent                `json:"audit,omitempty"`
	Favorites    map[string][]string         `json:"favorites,omitempty"` // userID → target IDs (non secret)
}

// Store persiste la base portail (AES-256-GCM, master key).
type Store struct {
	mu   sync.RWMutex
	path string
	key  [32]byte
	snap Snapshot
}

// NewStore crée un store ; secret = master key (GPX_PORTAL_MASTER_KEY ou dérivée).
func NewStore(path, secret string) *Store {
	key := sha256.Sum256([]byte(secret))
	return &Store{
		path: path,
		key:  key,
		snap: Snapshot{
			Vaults:       map[string][]byte{},
			Personal:     map[string][]PersonalTarget{},
			AuthSessions: map[string]AuthSession{},
			Favorites:    map[string][]string{},
		},
	}
}

// Load charge depuis le disque (noop si absent).
func (s *Store) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	plain, err := decryptWithKey(data, s.key)
	if err != nil {
		return fmt.Errorf("portal store decrypt: %w", err)
	}
	var snap Snapshot
	if err := json.Unmarshal(plain, &snap); err != nil {
		return fmt.Errorf("portal store parse: %w", err)
	}
	if snap.Vaults == nil {
		snap.Vaults = map[string][]byte{}
	}
	if snap.Personal == nil {
		snap.Personal = map[string][]PersonalTarget{}
	}
	if snap.AuthSessions == nil {
		snap.AuthSessions = map[string]AuthSession{}
	}
	if snap.Favorites == nil {
		snap.Favorites = map[string][]string{}
	}
	// Purge jetons expirés au chargement.
	now := time.Now()
	for id, sess := range snap.AuthSessions {
		if now.After(sess.Expires) {
			delete(snap.AuthSessions, id)
		}
	}
	s.snap = snap
	return nil
}

func (s *Store) persistLocked() error {
	s.snap.SavedAt = time.Now().UTC()
	plain, err := json.Marshal(&s.snap)
	if err != nil {
		return err
	}
	enc, err := encryptWithKey(plain, s.key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(s.path, enc, 0o600)
}

// Save force une écriture disque.
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.persistLocked()
}

// SetCatalog remplace le catalogue Admin.
func (s *Store) SetCatalog(items []CatalogTarget) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snap.Catalog = items
	return s.persistLocked()
}

// Catalog retourne une copie du catalogue.
func (s *Store) Catalog() []CatalogTarget {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]CatalogTarget, len(s.snap.Catalog))
	copy(out, s.snap.Catalog)
	return out
}

// FindUserByUsername cherche un user local (comparaison insensible à la casse).
func (s *Store) FindUserByUsername(username string) (UserRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	lu := strings.ToLower(username)
	for _, u := range s.snap.Users {
		if strings.ToLower(u.Username) == lu {
			return u, true
		}
	}
	return UserRecord{}, false
}

// FindUserByID cherche un user par ID.
func (s *Store) FindUserByID(id string) (UserRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, u := range s.snap.Users {
		if u.ID == id {
			return u, true
		}
	}
	return UserRecord{}, false
}

// EnsureSSOUser crée un compte portail sans mot de passe local s'il n'existe pas.
// PasswordHash vide = compte SSO-only.
func (s *Store) EnsureSSOUser(username string) (UserRecord, error) {
	if u, ok := s.FindUserByUsername(username); ok {
		return u, nil
	}
	u := UserRecord{
		ID:        uuid.NewString(),
		Username:  username,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := s.CreateUser(u); err != nil {
		// course : un autre login a créé le compte
		if got, ok := s.FindUserByUsername(username); ok {
			return got, nil
		}
		return UserRecord{}, err
	}
	return u, nil
}

// CreateUser ajoute un compte local.
func (s *Store) CreateUser(u UserRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.snap.Users {
		if strings.EqualFold(existing.Username, u.Username) {
			return fmt.Errorf("username déjà pris")
		}
	}
	if u.Status == "" {
		u.Status = UserStatusActive
	}
	s.snap.Users = append(s.snap.Users, u)
	if s.snap.Personal[u.ID] == nil {
		s.snap.Personal[u.ID] = []PersonalTarget{}
	}
	if err := s.persistLocked(); err != nil {
		s.snap.Users = s.snap.Users[:len(s.snap.Users)-1]
		delete(s.snap.Personal, u.ID)
		return err
	}
	return nil
}

// SyncUsers remplace les comptes Admin-managed ; préserve password_hash local et comptes SSO.
func (s *Store) SyncUsers(synced []SyncedUser) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	keep := make([]UserRecord, 0, len(s.snap.Users))
	byID := map[string]UserRecord{}
	for _, u := range s.snap.Users {
		if !u.AdminManaged {
			keep = append(keep, u)
			continue
		}
		byID[u.ID] = u
	}

	now := time.Now().UTC().Format(time.RFC3339)
	for _, su := range synced {
		email := strings.ToLower(strings.TrimSpace(su.Email))
		if su.ID == "" || email == "" {
			continue
		}
		status := su.Status
		if status == "" {
			status = UserStatusInvited
		}
		tags := su.Tags
		if tags == nil {
			tags = []string{}
		}
		u := UserRecord{
			ID:              su.ID,
			Username:        email,
			Status:          status,
			Tags:            tags,
			InviteTokenHash: su.InviteTokenHash,
			InviteExpires:   su.InviteExpires,
			AdminManaged:    true,
			CreatedAt:       now,
		}
		if prev, ok := byID[su.ID]; ok {
			u.PasswordHash = prev.PasswordHash
			u.CreatedAt = prev.CreatedAt
			if u.CreatedAt == "" {
				u.CreatedAt = now
			}
			u.TOTPSecret = prev.TOTPSecret
			u.TOTPEnabled = prev.TOTPEnabled
			u.TOTPPendingSecret = prev.TOTPPendingSecret
			u.EmailOTPEnabled = prev.EmailOTPEnabled
		}
		if status == UserStatusActive {
			u.InviteTokenHash = ""
			u.InviteExpires = ""
		}
		keep = append(keep, u)
		if s.snap.Personal[u.ID] == nil {
			s.snap.Personal[u.ID] = []PersonalTarget{}
		}
		delete(byID, su.ID)
	}
	// Comptes admin absents du push : retirés (byID restants).
	s.snap.Users = keep
	return s.persistLocked()
}

// FindUserByInviteHash trouve un compte invité par hash de jeton.
func (s *Store) FindUserByInviteHash(tokenHash string) (UserRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if tokenHash == "" {
		return UserRecord{}, false
	}
	for _, u := range s.snap.Users {
		if u.InviteTokenHash == tokenHash {
			return u, true
		}
	}
	return UserRecord{}, false
}

// CompleteInvite pose le mot de passe et active le compte.
func (s *Store) CompleteInvite(userID, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.snap.Users {
		if s.snap.Users[i].ID != userID {
			continue
		}
		s.snap.Users[i].PasswordHash = passwordHash
		s.snap.Users[i].Status = UserStatusActive
		s.snap.Users[i].InviteTokenHash = ""
		s.snap.Users[i].InviteExpires = ""
		return s.persistLocked()
	}
	return fmt.Errorf("utilisateur introuvable")
}

// UpdateUserStatus force un statut (disabled depuis Admin sync déjà couvert).
func (s *Store) UpdateUserStatus(userID, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.snap.Users {
		if s.snap.Users[i].ID != userID {
			continue
		}
		s.snap.Users[i].Status = status
		return s.persistLocked()
	}
	return fmt.Errorf("utilisateur introuvable")
}

// UpdateUser2FA met à jour les champs 2FA d'un user.
func (s *Store) UpdateUser2FA(userID string, fn func(*UserRecord)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.snap.Users {
		if s.snap.Users[i].ID != userID {
			continue
		}
		fn(&s.snap.Users[i])
		return s.persistLocked()
	}
	return fmt.Errorf("utilisateur introuvable")
}

// UserCount retourne le nombre de comptes locaux.
func (s *Store) UserCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.snap.Users)
}

// Path retourne le chemin du fichier store.
func (s *Store) Path() string {
	return s.path
}

// PutAuthSession persiste un jeton bearer.
func (s *Store) PutAuthSession(token string, sess AuthSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snap.AuthSessions == nil {
		s.snap.AuthSessions = map[string]AuthSession{}
	}
	s.snap.AuthSessions[token] = sess
	return s.persistLocked()
}

// GetAuthSession lit un jeton (false si absent/expiré).
func (s *Store) GetAuthSession(token string) (AuthSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.snap.AuthSessions[token]
	if !ok {
		return AuthSession{}, false
	}
	if time.Now().After(sess.Expires) {
		delete(s.snap.AuthSessions, token)
		_ = s.persistLocked()
		return AuthSession{}, false
	}
	return sess, true
}

// DeleteAuthSession invalide un jeton.
func (s *Store) DeleteAuthSession(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.snap.AuthSessions, token)
	return s.persistLocked()
}

// PersonalTargets liste les cibles perso d'un user.
func (s *Store) PersonalTargets(userID string) []PersonalTarget {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src := s.snap.Personal[userID]
	out := make([]PersonalTarget, len(src))
	copy(out, src)
	return out
}

// UpsertPersonalTarget crée ou met à jour une cible perso.
func (s *Store) UpsertPersonalTarget(userID string, t PersonalTarget) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.snap.Personal[userID]
	found := false
	for i, existing := range list {
		if existing.ID == t.ID {
			list[i] = t
			found = true
			break
		}
	}
	if !found {
		list = append(list, t)
	}
	s.snap.Personal[userID] = list
	return s.persistLocked()
}

// DeletePersonalTarget supprime une cible perso.
func (s *Store) DeletePersonalTarget(userID, targetID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.snap.Personal[userID]
	out := list[:0]
	for _, t := range list {
		if t.ID != targetID {
			out = append(out, t)
		}
	}
	s.snap.Personal[userID] = out
	return s.persistLocked()
}

// FindPersonalTarget retourne une cible perso.
func (s *Store) FindPersonalTarget(userID, targetID string) (PersonalTarget, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.snap.Personal[userID] {
		if t.ID == targetID {
			return t, true
		}
	}
	return PersonalTarget{}, false
}

// FindCatalogTarget retourne une cible catalogue.
func (s *Store) FindCatalogTarget(targetID string) (CatalogTarget, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, t := range s.snap.Catalog {
		if t.ID == targetID {
			return t, true
		}
	}
	return CatalogTarget{}, false
}

// SetVaultBlob stocke le vault chiffré d'un user.
func (s *Store) SetVaultBlob(userID string, blob []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snap.Vaults[userID] = blob
	return s.persistLocked()
}

// VaultBlob retourne le vault chiffré (copie).
func (s *Store) VaultBlob(userID string) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b := s.snap.Vaults[userID]
	if len(b) == 0 {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// AppendAudit ajoute un événement (ring buffer).
func (s *Store) AppendAudit(e AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.Ts.IsZero() {
		e.Ts = time.Now().UTC()
	}
	s.snap.Audit = append(s.snap.Audit, e)
	if len(s.snap.Audit) > maxAuditEvents {
		s.snap.Audit = s.snap.Audit[len(s.snap.Audit)-maxAuditEvents:]
	}
	return s.persistLocked()
}

// ListAuditForUser retourne les N derniers événements de l'acteur.
func (s *Store) ListAuditForUser(actor string, limit int) []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	out := make([]AuditEvent, 0, limit)
	for i := len(s.snap.Audit) - 1; i >= 0 && len(out) < limit; i-- {
		if s.snap.Audit[i].Actor == actor {
			out = append(out, s.snap.Audit[i])
		}
	}
	return out
}

// ListAuditRecent retourne les N derniers événements (tous acteurs).
func (s *Store) ListAuditRecent(limit int) []AuditEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	n := len(s.snap.Audit)
	if n == 0 {
		return []AuditEvent{}
	}
	start := n - limit
	if start < 0 {
		start = 0
	}
	out := make([]AuditEvent, n-start)
	copy(out, s.snap.Audit[start:])
	return out
}

// Favorites retourne les IDs de cibles favorites (copie).
func (s *Store) Favorites(userID string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	src := s.snap.Favorites[userID]
	if len(src) == 0 {
		return []string{}
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

// SetFavorites remplace la liste de favoris (dédupliquée, ordre conservé).
func (s *Store) SetFavorites(userID string, ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snap.Favorites == nil {
		s.snap.Favorites = map[string][]string{}
	}
	seen := map[string]bool{}
	clean := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		clean = append(clean, id)
	}
	s.snap.Favorites[userID] = clean
	return s.persistLocked()
}

// ToggleFavorite ajoute ou retire un favori ; retourne true si désormais favori.
func (s *Store) ToggleFavorite(userID, targetID string) (bool, error) {
	targetID = strings.TrimSpace(targetID)
	if targetID == "" {
		return false, fmt.Errorf("target_id requis")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.snap.Favorites == nil {
		s.snap.Favorites = map[string][]string{}
	}
	cur := s.snap.Favorites[userID]
	for i, id := range cur {
		if id == targetID {
			s.snap.Favorites[userID] = append(cur[:i], cur[i+1:]...)
			return false, s.persistLocked()
		}
	}
	s.snap.Favorites[userID] = append(append([]string{}, cur...), targetID)
	return true, s.persistLocked()
}

func encryptWithKey(plain []byte, key [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func decryptWithKey(data []byte, key [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, fmt.Errorf("données corrompues")
	}
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
