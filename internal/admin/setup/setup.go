// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package setup gère la détection du premier lancement et l'initialisation du compte admin.
package setup

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/config"
)

// IsFirstRun retourne true si la table users est vide (aucun administrateur créé).
func IsFirstRun(db *sql.DB) bool {
	var count int
	_ = db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count == 0
}

// CreateFirstAdmin crée le premier compte administrateur.
func CreateFirstAdmin(db *sql.DB, email, password string) error {
	hash, err := auth.HashPassword(password)
	if err != nil {
		return fmt.Errorf("hash mot de passe : %w", err)
	}
	id := uuid.New().String()
	_, err = db.Exec(
		`INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, 'superadmin')`,
		id, email, hash,
	)
	if err != nil {
		return fmt.Errorf("création admin : %w", err)
	}
	slog.Info("Compte administrateur créé", "email", email, "id", id)
	return nil
}

// Init vérifie si c'est le premier lancement et crée le premier admin.
// Priorité : variables d'environnement > champs first_boot du fichier de config.
func Init(db *sql.DB, cfg *config.AdminConfig) {
	if !IsFirstRun(db) {
		return
	}
	email := os.Getenv("GPX_FIRST_ADMIN_EMAIL")
	if email == "" && cfg != nil {
		email = cfg.Security.FirstBoot.DefaultAdminEmail
	}
	password := os.Getenv("GPX_FIRST_ADMIN_PASSWORD")
	if password == "" && cfg != nil {
		password = cfg.Security.FirstBoot.DefaultAdminPassword
	}
	if email == "" || password == "" {
		slog.Warn("Premier lancement : définir GPX_FIRST_ADMIN_EMAIL et GPX_FIRST_ADMIN_PASSWORD pour initialiser automatiquement le compte admin")
		return
	}
	if err := CreateFirstAdmin(db, email, password); err != nil {
		slog.Error("Impossible de créer le premier admin", "err", err)
	}
}
