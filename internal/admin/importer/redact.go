// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"strings"
)

var alertSecretKeys = map[string]bool{
	"password": true, "token": true, "secret": true, "api_key": true,
	"app_token": true, "user_token": true, "webhook_url": true,
	"authorization": true, "private_key": true,
}

// RedactSecrets retire les secrets du backup (tokens nœuds, canaux d'alerte).
// Les tokens doivent être réémis après restore ; ImportTokens sur un backup rédigé
// n'importe que les métadonnées (token vide).
func RedactSecrets(b *Backup) {
	if b == nil {
		return
	}
	for i := range b.Tokens {
		if b.Tokens[i].Token != "" {
			b.Tokens[i].Token = ""
		}
	}
	for i, ch := range b.AlertChannels {
		cfg, _ := ch["config"].(map[string]any)
		if cfg == nil {
			continue
		}
		redacted := map[string]any{}
		for k, v := range cfg {
			if alertSecretKeys[strings.ToLower(k)] {
				redacted[k] = ""
				continue
			}
			redacted[k] = v
		}
		b.AlertChannels[i]["config"] = redacted
	}
}
