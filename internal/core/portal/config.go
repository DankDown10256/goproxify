// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import "time"

// Config runtime du portail (local + push Admin).
type Config struct {
	Enabled              bool   `json:"enabled"`
	SSHPort              int    `json:"ssh_port"`               // défaut 2222
	HTTPPort             int    `json:"http_port"`              // défaut 8444 — UI publique
	DBPath               string `json:"db_path"`                // défaut /etc/goproxify/portal.gpx
	AuthProviderID       string `json:"auth_provider_id"`       // optionnel — fournisseur Core
	PublicHost           string `json:"public_host"`            // host affiché dans les chaînes générées
	AllowPersonalTargets bool   `json:"allow_personal_targets"` // off par défaut (R14)
	Require2FA           bool   `json:"require_2fa"`            // off par défaut (KTD3)
	SessionTTLSec        int    `json:"session_ttl_sec"`        // défaut 60 (KTD1)
	SessionMode          string `json:"session_mode"`           // one_shot | multi
}

// Defaults applique les valeurs par défaut.
func (c *Config) Defaults() {
	if c.SSHPort <= 0 {
		c.SSHPort = 2222
	}
	if c.HTTPPort <= 0 {
		c.HTTPPort = 8444
	}
	if c.DBPath == "" {
		c.DBPath = "/etc/goproxify/portal.gpx"
	}
	if c.SessionTTLSec <= 0 {
		c.SessionTTLSec = 60
	}
	if c.SessionMode != SessionModeMulti {
		c.SessionMode = SessionModeOneShot
	}
}

// TargetKind distingue VM/sshd et conteneur Docker.
type TargetKind string

const (
	TargetSSH    TargetKind = "ssh"
	TargetDocker TargetKind = "docker"
)

// CatalogTarget est une cible publiée par l'Admin (sans secrets).
type CatalogTarget struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Kind      TargetKind `json:"kind"`
	Host      string     `json:"host,omitempty"`
	Port      int        `json:"port,omitempty"`
	AgentName string     `json:"agent_name,omitempty"`
	Container string     `json:"container,omitempty"`
	Tags      []string   `json:"tags,omitempty"`
}

// PersonalTarget est une cible perso (métadonnées) ; secrets dans le vault user.
type PersonalTarget struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Kind      TargetKind `json:"kind"`
	Host      string     `json:"host,omitempty"`
	Port      int        `json:"port,omitempty"`
	AgentName string     `json:"agent_name,omitempty"`
	Container string     `json:"container,omitempty"`
	Username  string     `json:"username,omitempty"` // login SSH cible (pas secret)
}

// TargetCreds sont les secrets d'une cible (stockés chiffrés dans le vault).
type TargetCreds struct {
	Username   string `json:"username,omitempty"` // login SSH cible (pas l'email Access)
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
}

// UserStatus états d'un compte portail.
const (
	UserStatusInvited  = "invited"
	UserStatusActive   = "active"
	UserStatusDisabled = "disabled"
)

// SyncedUser est un compte poussé par l'Admin (métadonnées ; mot de passe reste sur Core).
type SyncedUser struct {
	ID              string   `json:"id"`
	Email           string   `json:"email"`
	Status          string   `json:"status"`
	Tags            []string `json:"tags,omitempty"`
	InviteTokenHash string   `json:"invite_token_hash,omitempty"`
	InviteExpires   string   `json:"invite_expires,omitempty"`
}

// UserRecord est un compte portail local.
type UserRecord struct {
	ID               string   `json:"id"`
	Username         string   `json:"username"`
	PasswordHash     string   `json:"password_hash"` // bcrypt
	CreatedAt        string   `json:"created_at"`
	Status           string   `json:"status,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	InviteTokenHash  string   `json:"invite_token_hash,omitempty"`
	InviteExpires    string   `json:"invite_expires,omitempty"`
	AdminManaged     bool     `json:"admin_managed,omitempty"`
	TOTPSecret       string   `json:"totp_secret,omitempty"`
	TOTPEnabled      bool     `json:"totp_enabled,omitempty"`
	TOTPPendingSecret string  `json:"totp_pending_secret,omitempty"`
	EmailOTPEnabled  bool     `json:"email_otp_enabled,omitempty"`
}

// DefaultSessionTTL durée de vie d'un UUID non consommé (KTD1).
const DefaultSessionTTL = 60 * time.Second

// SessionMode comportement UUID.
const (
	SessionModeOneShot = "one_shot"
	SessionModeMulti   = "multi"
)

// SessionFacade indique la surface d'accès.
type SessionFacade string

const (
	FacadeWeb SessionFacade = "web"
	FacadeSSH SessionFacade = "ssh"
)
