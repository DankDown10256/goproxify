// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/vincamok/goproxify/internal/config"
	"github.com/vincamok/goproxify/internal/pairing"
)

// backupConfigFiles : fichiers de configuration ajoutés à la section secrets d'un snapshot.
// La config HA effective est sauvegardée telle que lue (fichier + variables GPX_*), car elle
// peut ne venir que de l'environnement.
//
// Ce qui ne vit que dans l'environnement du conteneur de l'Admin y figure aussi, car sans cela une sauvegarde ne permet pas
// de reconstruire l'Admin : le secret racine (dont dérivent les clés de toutes les passerelles et de tous les Agents) et
// le certificat TLS de l'Admin. Le secret JWT n'y est pas : il ne sert qu'aux sessions, qu'une restauration coupe sans
// conséquence. Ces fichiers ne sont jamais réécrits dans la config vivante à la restauration (dossier restored-config).
func (s *Server) backupConfigFiles() map[string][]byte {
	out := map[string][]byte{}
	if ha, err := json.MarshalIndent(s.cfg.HA, "", "  "); err == nil {
		out["admin-ha.json"] = ha
	}
	if p := config.AdminConfigPath(); p != "" {
		if data, err := os.ReadFile(p); err == nil {
			out["admin.json"] = data
		}
	}
	if root := pairing.Secret("GPX_PAIRING_SECRET"); root != "" {
		secrets := map[string]any{"GPX_PAIRING_SECRET": root}
		if prev := pairing.Previous("GPX_PAIRING_SECRET"); len(prev) > 0 {
			secrets["GPX_PAIRING_SECRET_PREVIOUS"] = strings.Join(prev, ",")
		}
		if data, err := json.MarshalIndent(secrets, "", "  "); err == nil {
			out["admin-secrets.json"] = data
		}
	}
	for name, env := range map[string]string{"admin-tls.crt": "GPX_ADMIN_TLS_CERT", "admin-tls.key": "GPX_ADMIN_TLS_KEY"} {
		if p := strings.TrimSpace(os.Getenv(env)); p != "" {
			if data, err := os.ReadFile(p); err == nil {
				out[name] = data
			}
		}
	}
	return out
}
