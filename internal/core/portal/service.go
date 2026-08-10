// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"fmt"
	"log/slog"
	"os"
	"sync"

	corecache "github.com/vincamok/goproxify/internal/core/cache"
)

// Service orchestre store + HTTP + SSH du portail.
type Service struct {
	mu                sync.Mutex
	cfg               Config
	log               *slog.Logger
	store             *Store
	sessions          *SessionManager
	httpSrv           *HTTPServer
	sshSrv            *SSHServer
	shell             *ShellBroker
	running           bool
	audit             func(AuditEvent)
	providers         AuthProviderLookup
	masterSecret      string // pour DeriveSSOVaultKey
	onInviteCompleted func(userID string)
	sendEmailOTP      func(email, code string) error
	onAudit           func(AuditEvent)
	pageTemplates     *TemplateStore
}

// NewService prépare le service (pas encore démarré).
func NewService(log *slog.Logger) *Service {
	return &Service{
		log:           log,
		sessions:      NewSessionManager(),
		audit:         AuditLogger(log),
		pageTemplates: NewTemplateStore(),
	}
}

// SetShellBroker injecte le broker docker exec (avant ApplyConfig).
func (s *Service) SetShellBroker(b *ShellBroker) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shell = b
}

// SetAuthProviders injecte le store AuthProvider du Core.
func (s *Service) SetAuthProviders(p AuthProviderLookup) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.providers = p
	if s.httpSrv != nil {
		s.httpSrv.providers = p
	}
}

// ShellBroker retourne le broker (peut être nil).
func (s *Service) ShellBroker() *ShellBroker {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.shell
}

// ApplyConfig met à jour la config et démarre/arrête selon Enabled.
// Si le portail tourne déjà avec les mêmes ports/DB, mise à jour à chaud (pas de wipe sessions).
func (s *Service) ApplyConfig(cfg Config) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg.Defaults()

	if !cfg.Enabled {
		s.cfg = cfg
		s.stopLocked()
		s.log.Info("portal: désactivé")
		return nil
	}

	needRestart := !s.running ||
		s.cfg.SSHPort != cfg.SSHPort ||
		s.cfg.HTTPPort != cfg.HTTPPort ||
		s.cfg.DBPath != cfg.DBPath

	if s.running && !needRestart {
		s.cfg.PublicHost = cfg.PublicHost
		s.cfg.AuthProviderID = cfg.AuthProviderID
		s.cfg.AllowPersonalTargets = cfg.AllowPersonalTargets
		s.cfg.Require2FA = cfg.Require2FA
		s.cfg.SessionTTLSec = cfg.SessionTTLSec
		s.cfg.SessionMode = cfg.SessionMode
		s.cfg.Enabled = true
		s.log.Info("portal: config à chaud", "public_host", s.cfg.PublicHost, "users", s.store.UserCount(),
			"allow_personal", s.cfg.AllowPersonalTargets, "require_2fa", s.cfg.Require2FA,
			"session_ttl", s.cfg.SessionTTLSec, "session_mode", s.cfg.SessionMode)
		return nil
	}

	s.cfg = cfg
	return s.startLocked()
}

// Config retourne la config courante.
func (s *Service) Config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// Stop arrête HTTP + SSH.
func (s *Service) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopLocked()
}

func (s *Service) stopLocked() {
	if s.httpSrv != nil {
		s.httpSrv.Stop()
		s.httpSrv = nil
	}
	if s.sshSrv != nil {
		s.sshSrv.Stop()
		s.sshSrv = nil
	}
	s.running = false
}

func (s *Service) startLocked() error {
	s.stopLocked()

	secret := resolveMasterKey()
	if secret == "" {
		return fmt.Errorf("portal: master key manquante (GPX_PORTAL_MASTER_KEY ou token Core)")
	}
	store := NewStore(s.cfg.DBPath, secret)
	if err := store.Load(); err != nil {
		return fmt.Errorf("portal store load: %w", err)
	}
	s.store = store
	s.sessions = NewSessionManager()
	s.masterSecret = secret

	baseLog := AuditLogger(s.log)
	s.audit = func(e AuditEvent) {
		baseLog(e)
		_ = store.AppendAudit(e)
		if s.onAudit != nil {
			s.onAudit(e)
		}
	}

	httpSrv := NewHTTPServer(&s.cfg, store, s.sessions, s.log, s.audit)
	httpSrv.shell = s.shell
	httpSrv.providers = s.providers
	httpSrv.masterSecret = secret
	httpSrv.onInviteCompleted = s.onInviteCompleted
	httpSrv.sendEmailOTP = s.sendEmailOTP
	if s.pageTemplates == nil {
		s.pageTemplates = NewTemplateStore()
	}
	httpSrv.pageTemplates = s.pageTemplates
	if err := httpSrv.Start(fmt.Sprintf(":%d", s.cfg.HTTPPort)); err != nil {
		return fmt.Errorf("portal http: %w", err)
	}
	s.httpSrv = httpSrv

	sshSrv, err := NewSSHServer(s.sessions, nil, s.log, s.audit)
	if err != nil {
		httpSrv.Stop()
		return err
	}
	sshSrv.shell = s.shell
	if err := sshSrv.Start(fmt.Sprintf(":%d", s.cfg.SSHPort)); err != nil {
		httpSrv.Stop()
		return fmt.Errorf("portal ssh: %w", err)
	}
	s.sshSrv = sshSrv
	s.running = true
	authHint := s.cfg.AuthProviderID
	if authHint == "" {
		authHint = "(local)"
	}
	s.log.Info("portal: démarré",
		"http", s.cfg.HTTPPort,
		"ssh", s.cfg.SSHPort,
		"db", store.Path(),
		"users", store.UserCount(),
		"auth_provider", authHint,
	)
	return nil
}

// SetCatalog met à jour le catalogue (push Admin).
func (s *Service) SetCatalog(items []CatalogTarget) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == nil {
		return fmt.Errorf("portal non démarré")
	}
	return s.store.SetCatalog(items)
}

// SyncUsers applique la liste Admin (push).
func (s *Service) SyncUsers(users []SyncedUser) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == nil {
		return fmt.Errorf("portal non démarré")
	}
	return s.store.SyncUsers(users)
}

// SetInviteCompletedHook enregistre un callback après complete-invite (notif Admin).
func (s *Service) SetInviteCompletedHook(fn func(userID string)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onInviteCompleted = fn
	if s.httpSrv != nil {
		s.httpSrv.onInviteCompleted = fn
	}
}

// SetEmailOTPSender injecte l'envoi OTP email (typiquement via WS → Admin mailer).
func (s *Service) SetEmailOTPSender(fn func(email, code string) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sendEmailOTP = fn
	if s.httpSrv != nil {
		s.httpSrv.sendEmailOTP = fn
	}
}

// SetAuditHook notifie l'extérieur (Admin WS) pour chaque événement audit.
func (s *Service) SetAuditHook(fn func(AuditEvent)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onAudit = fn
}

// ReplacePageTemplates applique le push Admin (ReplaceAll).
func (s *Service) ReplacePageTemplates(tpls []PageTemplate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pageTemplates == nil {
		s.pageTemplates = NewTemplateStore()
	}
	s.pageTemplates.ReplaceAll(tpls)
	if s.httpSrv != nil {
		s.httpSrv.pageTemplates = s.pageTemplates
	}
	s.log.Info("portal: templates pages mis à jour", "count", len(s.pageTemplates.Snapshot()))
}

func resolveMasterKey() string {
	if k := os.Getenv("GPX_PORTAL_MASTER_KEY"); k != "" {
		return k
	}
	return corecache.ResolveSecret("")
}
