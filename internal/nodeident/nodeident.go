// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package nodeident génère et résout l'identité stable d'un nœud (Core ou Agent).
package nodeident

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

const persistDir = "/etc/goproxify"

// Resolve retourne le node_id à utiliser :
// 1. GPX_IDENTITY_<ROLE>_NODE_NAME si définie (override explicite).
// 2. L'ID persisté dans /etc/goproxify/<role>-node-id (généré au premier démarrage).
// 3. Génère un UUID court, le persiste et le retourne.
//
// L'ID est auto-généré et ne dépend pas du hostname, évitant les collisions
// entre plusieurs nœuds déployés avec la même image sans configuration manuelle.
func Resolve(role string) string {
	roleEnv := "GPX_IDENTITY_" + strings.ToUpper(role) + "_NODE_NAME"
	if name := os.Getenv(roleEnv); name != "" {
		return name
	}
	// Fallback générique : GPX_IDENTITY_NODE_NAME (utilisé dans docker-compose et wizard).
	if name := os.Getenv("GPX_IDENTITY_NODE_NAME"); name != "" {
		return name
	}

	persistPath := fmt.Sprintf("%s/%s-node-id", persistDir, role)
	if data, err := os.ReadFile(persistPath); err == nil {
		if id := strings.TrimSpace(string(data)); id != "" {
			return id
		}
	}

	// Premier démarrage : génère un ID unique et le persiste.
	// On utilise 8 octets (64 bits) pour un risque de collision négligeable.
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		// fallback déterministe si rand échoue (très improbable)
		copy(buf, []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x00, 0x01})
	}
	id := fmt.Sprintf("%s-%s", role, hex.EncodeToString(buf))
	_ = os.MkdirAll(persistDir, 0755)
	_ = os.WriteFile(persistPath, []byte(id), 0644)
	return id
}
