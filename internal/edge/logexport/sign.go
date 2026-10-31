// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logexport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// Sealer est le stockage chiffré local de la passerelle (cache.Store).
type Sealer interface {
	SaveFile(path string, v any) error
	LoadFile(path string, v any) (bool, error)
}

type keyFile struct {
	Seed []byte `json:"seed"`
}

// LoadOrCreateKey rend la clé de signature des exports, créée à la première utilisation. Elle est dédiée : la clé
// qui pseudonymise les IP n'a pas à signer. Un fichier illisible n'est jamais écrasé : une clé neuve ne
// vérifierait plus les exports déjà remis.
func LoadOrCreateKey(s Sealer, path string) (ed25519.PrivateKey, error) {
	var kf keyFile
	ok, err := s.LoadFile(path, &kf)
	if err != nil {
		return nil, fmt.Errorf("clé de signature illisible (%s) : %w", path, err)
	}
	if ok && len(kf.Seed) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(kf.Seed), nil
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := s.SaveFile(path, keyFile{Seed: seed}); err != nil {
		return nil, fmt.Errorf("enregistrement de la clé de signature : %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// KeyID est l'empreinte courte d'une clé publique, à comparer à celle relevée à la remise de l'export.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// Manifest décrit un export. Il ne porte aucune donnée personnelle : l'IP filtrée n'y figure que par son empreinte.
type Manifest struct {
	Version int    `json:"version"`
	Node    string `json:"node"`
	// Nodes : les passerelles que couvre un export de l'Admin (absent pour l'export d'une seule base).
	Nodes []string `json:"nodes,omitempty"`
	// Origin : pair dont l'export reprend les lignes répliquées (absent pour les lignes propres de la base).
	Origin    string `json:"origin,omitempty"`
	CreatedAt string `json:"created_at"` // heure de la passerelle : sa valeur de preuve dépend de son horloge (NTP)
	Operator  string `json:"operator"`
	Reason    string `json:"reason"`
	Kind      string `json:"kind"`
	From      string `json:"from"`
	To        string `json:"to"`
	Filters   struct {
		Domain   string `json:"domain,omitempty"`
		IPSHA256 string `json:"ip_sha256,omitempty"`
	} `json:"filters"`
	Format      string `json:"format"`
	Rows        int64  `json:"rows"`
	FirstTS     string `json:"first_ts,omitempty"`
	LastTS      string `json:"last_ts,omitempty"`
	PlainSHA256 string `json:"plain_sha256"`
	PlainBytes  int64  `json:"plain_bytes"`
	Encrypted   bool   `json:"encrypted"`
	File        string `json:"file"`
	FileSHA256  string `json:"file_sha256"`
	FileBytes   int64  `json:"file_bytes"`
	PublicKey   string `json:"public_key"`
	KeyID       string `json:"key_id"`
}

// Signed est le fichier de manifeste : le manifeste et sa signature Ed25519 (sur le manifeste compacté).
type Signed struct {
	Manifest  json.RawMessage `json:"manifest"`
	Algorithm string          `json:"algorithm"`
	Signature string          `json:"signature"`
}

func compact(raw []byte) ([]byte, error) {
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// SignManifest produit le contenu du fichier de manifeste.
func SignManifest(priv ed25519.PrivateKey, m Manifest) ([]byte, error) {
	m.PublicKey = base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))
	m.KeyID = KeyID(priv.Public().(ed25519.PublicKey))
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, raw)
	return json.MarshalIndent(Signed{Manifest: raw, Algorithm: "ed25519", Signature: base64.StdEncoding.EncodeToString(sig)}, "", "  ")
}

// ParseManifest lit un fichier de manifeste et vérifie sa signature avec la clé qu'il annonce. pinned (facultatif)
// est la clé publique attendue : sans elle, la signature prouve seulement que le manifeste est intact, pas qui l'a
// signé.
func ParseManifest(file []byte, pinned ed25519.PublicKey) (Manifest, error) {
	var s Signed
	var m Manifest
	if err := json.Unmarshal(file, &s); err != nil || len(s.Manifest) == 0 {
		return m, errors.New("manifeste illisible")
	}
	if s.Algorithm != "ed25519" {
		return m, fmt.Errorf("algorithme de signature inconnu %q", s.Algorithm)
	}
	body, err := compact(s.Manifest)
	if err != nil {
		return m, errors.New("manifeste illisible")
	}
	if err := json.Unmarshal(body, &m); err != nil {
		return m, errors.New("manifeste illisible")
	}
	pub, err := base64.StdEncoding.DecodeString(m.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return m, errors.New("clé publique du manifeste invalide")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(pub), body, sig) {
		return m, errors.New("signature invalide : le manifeste a été modifié")
	}
	if len(pinned) > 0 && !bytes.Equal(pinned, pub) {
		return m, errors.New("le manifeste n'est pas signé par la clé attendue")
	}
	return m, nil
}
