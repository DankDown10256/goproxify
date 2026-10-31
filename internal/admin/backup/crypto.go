// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/vincamok/goproxify/internal/admin/importer"
)

const backupEncPrefix = "GPXBK1:"

// backupKey dérive une clé 32 octets depuis GPX_BACKUP_KEY (optionnel).
func backupKey() ([]byte, bool) { return importer.BackupKey() }

func sealSnapshot(plain []byte) ([]byte, error) {
	key, ok := backupKey()
	if !ok {
		return plain, nil
	}
	block, err := aes.NewCipher(key)
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
	out := gcm.Seal(nonce, nonce, plain, nil)
	return []byte(backupEncPrefix + base64.StdEncoding.EncodeToString(out)), nil
}

// openSnapshotConsume est openSnapshot pour un tampon jetable : le base64 est décodé et le contenu
// déchiffré sur place, si bien que la vérification d'un snapshot de 100 Mo n'a besoin que d'un tampon
// de cette taille au lieu de trois. data est inutilisable ensuite.
func openSnapshotConsume(data []byte) ([]byte, error) {
	if !bytes.HasPrefix(data, []byte(backupEncPrefix)) {
		return data, nil
	}
	body := data[len(backupEncPrefix):]
	n, err := base64.StdEncoding.Decode(body, body) // sortie <= entrée : le décodage progresse sans rattraper la lecture
	if err != nil {
		return nil, err
	}
	plain, err := importer.DecryptAnyConsume(body[:n])
	if errors.Is(err, importer.ErrNoBackupKey) {
		return nil, fmt.Errorf("snapshot chiffré — définir la clé de chiffrement des sauvegardes")
	}
	return plain, err
}

// OpenSnapshot déchiffre le fichier d'un snapshot (enveloppe `GPXBK1:`) avec les clés connues d'importer ; un snapshot
// sans enveloppe est rendu tel quel. C'est ce qu'il faut pour lire un fichier de sauvegarde hors de l'Admin.
func OpenSnapshot(data []byte) ([]byte, error) { return openSnapshot(data) }

func openSnapshot(data []byte) ([]byte, error) {
	if !bytes.HasPrefix(data, []byte(backupEncPrefix)) {
		return data, nil
	}
	// Sur des octets, sans copie en chaîne : un snapshot peut peser une centaine de Mo.
	body := data[len(backupEncPrefix):]
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(body)))
	n, err := base64.StdEncoding.Decode(raw, body)
	if err != nil {
		return nil, err
	}
	plain, err := importer.DecryptAny(raw[:n])
	if errors.Is(err, importer.ErrNoBackupKey) {
		return nil, fmt.Errorf("snapshot chiffré — définir la clé de chiffrement des sauvegardes")
	}
	return plain, err
}
