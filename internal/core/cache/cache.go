// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package cache

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
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
	coretls "github.com/vincamok/goproxify/internal/core/tls"
)

// Snapshot est le contenu chiffré sauvegardé sur disque (AES-256-GCM).
// Les clés privées TLS sont incluses ici car le fichier est chiffré.
type Snapshot struct {
	SavedAt       time.Time              `json:"saved_at"`
	Routes        []*router.Route        `json:"routes"`
	Certs         []coretls.CachedCert   `json:"certs,omitempty"`
	Snippets      []*router.Snippet      `json:"snippets,omitempty"`
	AuthProviders []*router.AuthProvider `json:"auth_providers,omitempty"`
}

// Info est retourné par Show() pour la CLI.
type Info struct {
	Path              string
	SavedAt           time.Time
	RouteCount        int
	CertCount         int
	SnippetCount      int
	AuthProviderCount int
}

// Store gère le fichier cache chiffré du Core.
type Store struct {
	path string
	key  [32]byte // AES-256-GCM
}

// ResolveSecret choisit la clé de chiffrement du cache.
// Priorité : auth_token explicite → GPX_CONTROL_PLANE_AUTH_TOKEN → GPX_PAIRING_SECRET.
// En stack compose, auth_token est vide : on utilise GPX_PAIRING_SECRET (stable entre redémarrages).
func ResolveSecret(authToken string) string {
	if authToken != "" {
		return authToken
	}
	if s := os.Getenv("GPX_CONTROL_PLANE_AUTH_TOKEN"); s != "" {
		return s
	}
	// Alias historique CLI
	if s := os.Getenv("GPX_CONTROLPLANE_AUTH_TOKEN"); s != "" {
		return s
	}
	if s := os.Getenv("GPX_PAIRING_SECRET"); s != "" {
		return s
	}
	return ""
}

// New crée un Store.
// secret : passer ResolveSecret(...) pour la clé de production.
func New(path, secret string) *Store {
	key := sha256.Sum256([]byte(secret))
	return &Store{path: path, key: key}
}

// Save chiffre et écrit un snapshot sur disque.
func (s *Store) Save(snap *Snapshot) error {
	data, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshal snapshot : %w", err)
	}

	encrypted, err := s.encrypt(data)
	if err != nil {
		return fmt.Errorf("chiffrement snapshot : %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return fmt.Errorf("création répertoire cache : %w", err)
	}
	return os.WriteFile(s.path, encrypted, 0o600)
}

// Load déchiffre et retourne le snapshot du disque.
// nil, nil = fichier absent. err = lecture/déchiffrement/parsing.
func (s *Store) Load() (*Snapshot, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	return s.decode(data, s.key)
}

// LoadWithFallbacks tente la clé courante puis d'anciennes clés (migration).
// Si un fallback réussit, resauvegarde avec la clé courante.
func (s *Store) LoadWithFallbacks(legacySecrets ...string) (*Snapshot, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	snap, err := s.decode(data, s.key)
	if err == nil {
		return snap, nil
	}
	primaryErr := err

	seen := map[[32]byte]bool{s.key: true}
	for _, secret := range legacySecrets {
		key := sha256.Sum256([]byte(secret))
		if seen[key] {
			continue
		}
		seen[key] = true
		snap, err := s.decode(data, key)
		if err != nil {
			continue
		}
		// Réécrit avec la clé courante pour les prochains démarrages.
		_ = s.Save(snap)
		return snap, nil
	}
	return nil, primaryErr
}

func (s *Store) decode(data []byte, key [32]byte) (*Snapshot, error) {
	plain, err := decryptWithKey(data, key)
	if err != nil {
		return nil, fmt.Errorf("déchiffrement cache : %w", err)
	}
	var snap Snapshot
	if err := json.Unmarshal(plain, &snap); err != nil {
		return nil, fmt.Errorf("parsing cache : %w", err)
	}
	return &snap, nil
}

// Info retourne les métadonnées du cache.
func (s *Store) Info() (*Info, error) {
	snap, err := s.Load()
	if err != nil {
		return nil, err
	}
	if snap == nil {
		return nil, nil
	}
	return &Info{
		Path:              s.path,
		SavedAt:           snap.SavedAt,
		RouteCount:        len(snap.Routes),
		CertCount:         len(snap.Certs),
		SnippetCount:      len(snap.Snippets),
		AuthProviderCount: len(snap.AuthProviders),
	}, nil
}

// Clear supprime le fichier cache.
func (s *Store) Clear() error {
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// ExportJSON écrit le snapshot en JSON lisible dans destPath.
func (s *Store) ExportJSON(destPath string) error {
	snap, err := s.Load()
	if err != nil {
		return err
	}
	if snap == nil {
		return fmt.Errorf("aucun cache disponible à %s", s.path)
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(destPath, data, 0o644)
}

// --- chiffrement AES-256-GCM ---------------------------------------------

func (s *Store) encrypt(plain []byte) ([]byte, error) {
	return encryptWithKey(plain, s.key)
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
