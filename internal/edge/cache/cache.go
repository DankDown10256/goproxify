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
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/pairing"
	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
)

// Snapshot est le contenu chiffré sauvegardé sur disque (AES-256-GCM).
// Les clés privées TLS sont incluses ici car le fichier est chiffré.
type Snapshot struct {
	SavedAt       time.Time              `json:"saved_at"`
	Routes        []*router.Route        `json:"routes"`
	Certs         []edgetls.CachedCert   `json:"certs,omitempty"`
	Snippets      []*router.Snippet      `json:"snippets,omitempty"`
	AuthProviders []*router.AuthProvider `json:"auth_providers,omitempty"`
	ECHKeys       []edgetls.ECHKey       `json:"ech_keys,omitempty"`
	ECHVersion    int64                  `json:"ech_version,omitempty"`
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

// Store gère le fichier cache chiffré de la passerelle.
type Store struct {
	path string
	key  [32]byte // AES-256-GCM
	// previous : clés des secrets précédents (GPX_PAIRING_SECRET_PREVIOUS), essayées en lecture seulement.
	previous [][32]byte
}

// PreviousSecretsEnv liste les anciens secrets d'appairage, séparés par des virgules. Changer GPX_PAIRING_SECRET change la
// clé de chiffrement des copies locales de la passerelle (routes, certificats, plugins, configurations) : sans l'ancien
// secret, elles ne se déchiffrent plus et la passerelle repart sans rien tant que l'Admin ne lui renvoie pas tout —
// exactement ce que l'autonomie (ADR 0006) doit éviter. Les fichiers lus avec un ancien secret sont réécrits avec le
// courant ; retirez la variable une fois la rotation terminée. Elle ne sert qu'à lire des données locales : elle
// n'authentifie jamais rien (WebSocket Admin, appairage), pour qu'un secret révoqué ne reste pas valable.
const PreviousSecretsEnv = "GPX_PAIRING_SECRET_PREVIOUS"

// La clé locale d'une passerelle chiffre ses propres copies (cache, clé de pseudonymisation des IP des logs…). Elle lui
// est propre et ne dépend plus du secret d'appairage, que tous les composants partagent : changer ce secret ne rend plus
// les copies illisibles (ADR 0015).
const (
	// NodeKeyEnv : la clé locale, fournie par l'environnement.
	NodeKeyEnv = "GPX_NODE_KEY"
	// NodeKeyFileEnv : chemin d'un fichier de secret (secret Docker) qui contient la clé locale.
	NodeKeyFileEnv = "GPX_NODE_KEY_FILE"
	// NodeKeyPathEnv : emplacement de la clé générée par la passerelle quand rien n'est fourni.
	NodeKeyPathEnv     = "GPX_NODE_KEY_PATH"
	defaultNodeKeyPath = "/etc/goproxify/node.key"
	nodeKeyMinLen      = 32
)

// NodeKeyPath est l'emplacement de la clé locale générée (à la racine du volume d'état).
func NodeKeyPath() string {
	if p := os.Getenv(NodeKeyPathEnv); p != "" {
		return p
	}
	return defaultNodeKeyPath
}

func providedNodeKey() string {
	if k := strings.TrimSpace(os.Getenv(NodeKeyEnv)); k != "" {
		return k
	}
	if f := os.Getenv(NodeKeyFileEnv); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

func generatedNodeKey() string {
	b, err := os.ReadFile(NodeKeyPath())
	if err != nil {
		return ""
	}
	if k := strings.TrimSpace(string(b)); len(k) >= nodeKeyMinLen {
		return k
	}
	return ""
}

// EnsureNodeKey crée la clé locale si ni l'environnement ni le volume n'en fournissent. Rend vrai quand elle vient
// d'être générée. Un fichier présent mais illisible ou trop court n'est jamais écrasé : une clé neuve rendrait
// définitivement illisible ce que l'ancienne aurait encore pu ouvrir.
func EnsureNodeKey() (created bool, err error) {
	if providedNodeKey() != "" {
		return false, nil
	}
	path := NodeKeyPath()
	if b, rerr := os.ReadFile(path); rerr == nil {
		if len(strings.TrimSpace(string(b))) >= nodeKeyMinLen {
			return false, nil
		}
		return false, fmt.Errorf("%s existe mais n'est pas une clé valide : il n'est pas écrasé", path)
	} else if !errors.Is(rerr, os.ErrNotExist) {
		return false, rerr
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return false, fmt.Errorf("clé aléatoire : %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return false, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil // créée entre-temps par un autre processus
		}
		return false, err
	}
	defer f.Close()
	if _, err := f.WriteString(fmt.Sprintf("%x\n", raw)); err != nil {
		return false, err
	}
	return true, nil
}

// NodeKey rend la clé locale de la passerelle (fournie, sinon générée) ; vide tant qu'aucune n'existe.
func NodeKey() string {
	if k := providedNodeKey(); k != "" {
		return k
	}
	return generatedNodeKey()
}

// LegacySecret est la clé d'avant la clé locale, dérivée du jeton ou du secret d'appairage. Le portail s'en sert encore
// par défaut : sa clé maître doit être la même sur tous les membres d'un groupe HA, ce que le secret d'appairage, commun
// à tous les composants, assure sans réglage (GPX_PORTAL_MASTER_KEY la remplace).
// Priorité : auth_token explicite → GPX_CONTROL_PLANE_AUTH_TOKEN → GPX_PAIRING_SECRET.
func LegacySecret(authToken string) string {
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
	if s := pairing.Secret("GPX_PAIRING_SECRET"); s != "" {
		return s
	}
	return ""
}

var (
	olderMu      sync.Mutex
	olderSecrets []string
)

// ResolveSecret choisit la clé de chiffrement des copies locales de la passerelle.
// Priorité : GPX_NODE_KEY → fichier GPX_NODE_KEY_FILE → clé générée (node.key) → ancienne clé (LegacySecret).
// Les clés écartées (jeton, secret d'appairage, clé générée) restent lisibles : New les ajoute aux anciennes clés, si bien
// que les copies écrites avant le changement sont relues puis réécrites avec la clé courante.
func ResolveSecret(authToken string) string {
	chosen := providedNodeKey()
	if chosen == "" {
		chosen = generatedNodeKey()
	}
	if chosen == "" {
		chosen = LegacySecret(authToken)
	}
	var older []string
	seen := map[string]bool{chosen: true}
	for _, c := range []string{
		authToken, os.Getenv("GPX_CONTROL_PLANE_AUTH_TOKEN"), os.Getenv("GPX_CONTROLPLANE_AUTH_TOKEN"),
		pairing.Secret("GPX_PAIRING_SECRET"), generatedNodeKey(),
	} {
		if c != "" && !seen[c] {
			seen[c] = true
			older = append(older, c)
		}
	}
	olderMu.Lock()
	olderSecrets = older
	olderMu.Unlock()
	return chosen
}

// New crée un Store.
// secret : passer ResolveSecret(...) pour la clé de production.
func New(path, secret string) *Store {
	key := sha256.Sum256([]byte(secret))
	st := &Store{path: path, key: key}
	seen := map[string]bool{secret: true}
	add := func(old string) {
		if old = strings.TrimSpace(old); old != "" && !seen[old] {
			seen[old] = true
			st.previous = append(st.previous, sha256.Sum256([]byte(old)))
		}
	}
	for _, old := range strings.Split(os.Getenv(PreviousSecretsEnv), ",") {
		add(old)
	}
	olderMu.Lock()
	for _, old := range olderSecrets {
		add(old)
	}
	olderMu.Unlock()
	return st
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
	return s.LoadWithFallbacks()
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

	for _, key := range s.previous {
		if old, err := s.decode(data, key); err == nil {
			_ = s.Save(old)
			return old, nil
		}
	}

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

// SaveFile chiffre v (JSON) avec la clé du cache et l'écrit de façon atomique dans path.
// Sert aux copies locales hors snapshot de ce que pousse l'Admin (ex. configuration Ephor).
func (s *Store) SaveFile(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	encrypted, err := s.encrypt(data)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(encrypted); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// LoadFile déchiffre dans v un fichier écrit par SaveFile. false, nil = fichier absent.
func (s *Store) LoadFile(path string, v any) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	plain, err := decryptWithKey(data, s.key)
	usedPrevious := false
	if err != nil {
		for _, key := range s.previous {
			if p, perr := decryptWithKey(data, key); perr == nil {
				plain, err, usedPrevious = p, nil, true
				break
			}
		}
	}
	if err != nil {
		return false, fmt.Errorf("déchiffrement %s : %w", filepath.Base(path), err)
	}
	if err := json.Unmarshal(plain, v); err != nil {
		return false, fmt.Errorf("parsing %s : %w", filepath.Base(path), err)
	}
	if usedPrevious {
		_ = s.SaveFile(path, v) // réécrit avec le secret courant
	}
	return true, nil
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
