// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"fmt"
	"strconv"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// Conservation des logs dans le volume de logs de l'Admin (ADR 0018) : la durée de l'historique que l'Admin garde pour toutes
// les passerelles, à ne pas confondre avec la conservation de sa propre table (`retention_access_days`, événements de
// sécurité) ni avec le tampon des passerelles.
const (
	DefaultVaultAccessDays = 365
	DefaultVaultSystemDays = 90
	maxVaultRetentionDays  = 3650

	vaultAccessKey = "logs.vault_retention_access_days"
	vaultSystemKey = "logs.vault_retention_system_days"
)

// VaultRetention est la conservation des accès et des logs système dans le volume de logs, en jours.
type VaultRetention struct {
	AccessDays int `json:"access_days"`
	SystemDays int `json:"system_days"`
}

func (v VaultRetention) validate() error {
	for name, d := range map[string]int{"access_days": v.AccessDays, "system_days": v.SystemDays} {
		if d < 1 || d > maxVaultRetentionDays {
			return fmt.Errorf("vault_retention.%s : de 1 à %d jours", name, maxVaultRetentionDays)
		}
	}
	return nil
}

// LoadVaultRetention lit la conservation réglée, ou celle par défaut (365 jours pour les accès, 90 pour le système).
func LoadVaultRetention(db *sql.DB) VaultRetention {
	read := func(key string, def int) int {
		if n, err := strconv.Atoi(admindb.GetSetting(db, key, "")); err == nil && n >= 1 && n <= maxVaultRetentionDays {
			return n
		}
		return def
	}
	return VaultRetention{AccessDays: read(vaultAccessKey, DefaultVaultAccessDays), SystemDays: read(vaultSystemKey, DefaultVaultSystemDays)}
}

func (h *LogsHandler) vaultRetentionView() map[string]any {
	v := LoadVaultRetention(h.DB)
	return map[string]any{
		"access_days": v.AccessDays, "system_days": v.SystemDays,
		"defaults": map[string]int{"access_days": DefaultVaultAccessDays, "system_days": DefaultVaultSystemDays},
	}
}

// saveVaultRetention enregistre la conservation du volume de logs et la fait appliquer à la prochaine purge.
func (h *LogsHandler) saveVaultRetention(v VaultRetention) error {
	if err := admindb.SetSetting(h.DB, vaultAccessKey, strconv.Itoa(v.AccessDays)); err != nil {
		return err
	}
	if err := admindb.SetSetting(h.DB, vaultSystemKey, strconv.Itoa(v.SystemDays)); err != nil {
		return err
	}
	if h.OnVaultRetention != nil {
		h.OnVaultRetention(v.AccessDays, v.SystemDays)
	}
	return nil
}
