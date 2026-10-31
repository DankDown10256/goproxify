// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logexport

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// Row est une ligne d'un export NDJSON.
type Row = exportRow

// ReadRows relit un export NDJSON : il contrôle d'abord la signature du manifeste, l'empreinte du fichier remis et, quand il
// est chiffré, celle du contenu déchiffré (avec le mot de passe), puis appelle fn pour chaque ligne. Un export modifié ou
// tronqué n'est jamais relu. L'export CSV ne se relit pas.
func ReadRows(manifestPath, dataPath, password string, pinned ed25519.PublicKey, fn func(Row) error) (Manifest, error) {
	rep, err := Verify(manifestPath, dataPath, password, pinned, nil)
	if err != nil {
		return Manifest{}, err
	}
	m := rep.Manifest
	if m.Format != FormatNDJSON {
		return m, fmt.Errorf("format %q : seul l'export ndjson se relit", m.Format)
	}
	if !rep.FileChecked || (m.Encrypted && !rep.PlainChecked) {
		return m, errors.New("contenu non vérifié : le mot de passe est requis pour un export chiffré")
	}
	f, err := os.Open(dataPath)
	if err != nil {
		return m, err
	}
	defer f.Close()
	var r io.Reader = f
	if m.Encrypted {
		if r, err = NewDecryptReader(f, password); err != nil {
			return m, err
		}
	}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var row Row
		if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
			return m, fmt.Errorf("ligne illisible : %w", err)
		}
		if err := fn(row); err != nil {
			return m, err
		}
	}
	return m, sc.Err()
}
