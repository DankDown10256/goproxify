// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package mailer envoie des emails via la config SMTP Admin (settings "smtp").
package mailer

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/smtp"
	"strings"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

const SettingKey = "smtp"

// Config shape partagée MFA / portail / alertes legacy.
type Config struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
	From     string `json:"from"`
}

// Load lit la config depuis settings. Host vide = non configuré.
func Load(db *sql.DB) Config {
	raw := admindb.GetSetting(db, SettingKey, "{}")
	var cfg Config
	_ = json.Unmarshal([]byte(raw), &cfg)
	if cfg.Port <= 0 {
		cfg.Port = 587
	}
	return cfg
}

// Configured indique si un envoi est possible.
func (c Config) Configured() bool {
	return strings.TrimSpace(c.Host) != "" && strings.TrimSpace(c.From) != ""
}

// Validate vérifie les champs requis pour une sauvegarde.
func (c Config) Validate() error {
	if strings.TrimSpace(c.Host) == "" {
		return fmt.Errorf("host SMTP requis")
	}
	if strings.TrimSpace(c.From) == "" {
		return fmt.Errorf("adresse From requise")
	}
	if c.Port < 0 || c.Port > 65535 {
		return fmt.Errorf("port SMTP invalide")
	}
	return nil
}

// Save persiste la config.
func Save(db *sql.DB, cfg Config) error {
	if cfg.Port <= 0 {
		cfg.Port = 587
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return admindb.SetSetting(db, SettingKey, string(raw))
}

// ErrNotConfigured lorsque SMTP est absent.
var ErrNotConfigured = fmt.Errorf("SMTP non configuré — renseigner Paramètres → SMTP")

// Send envoie un email texte brut.
func Send(db *sql.DB, to, subject, body string) error {
	cfg := Load(db)
	if !cfg.Configured() {
		return ErrNotConfigured
	}
	return SendWith(cfg, to, subject, body)
}

// SendWith envoie avec une config explicite (tests).
func SendWith(cfg Config, to, subject, body string) error {
	if !cfg.Configured() {
		return ErrNotConfigured
	}
	if cfg.Port <= 0 {
		cfg.Port = 587
	}
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	msg := "From: " + cfg.From + "\r\nTo: " + to +
		"\r\nSubject: " + subject + "\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" +
		body
	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}
	return smtp.SendMail(addr, auth, cfg.From, []string{to}, []byte(msg))
}

// PublicView masque le mot de passe pour l'API.
func (c Config) PublicView() Config {
	out := c
	if out.Password != "" {
		out.Password = "••••••••"
	}
	return out
}
