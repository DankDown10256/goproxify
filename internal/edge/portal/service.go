// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
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
	live              *LiveRegistry
	grants            *GrantSet
	policy            atomic.Pointer[Policy]
	reapStop          chan struct{}
	rec               *RecordingStore
	onAccessRequest   func(AccessRequest) error
	pageTemplates     *TemplateStore
	onStoreChange     func()
}

// NewService prépare le service (pas encore démarré).
func NewService(log *slog.Logger) *Service {
	return &Service{
		log:           log,
		sessions:      NewSessionManager(),
		live:          NewLiveRegistry(),
		grants:        NewGrantSet(),
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

// SetAuthProviders injecte le store AuthProvider de la passerelle.
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
	pol := cfg.Policy
	s.policy.Store(&pol)

	if cfg.HAGroup != "" && cfg.HAKey != "" {
		if os.Getenv("GPX_PORTAL_MASTER_KEY") == "" {
			s.log.Warn("portal: groupe HA sans GPX_PORTAL_MASTER_KEY — les coffres des comptes SSO ne sont déchiffrables sur un autre membre que si la clé maître est identique sur tous les membres",
				"groupe", cfg.HAGroup)
		}
		s.log.Info("portal: réplication HA active", "groupe", cfg.HAGroup, "membres", cfg.HAMembers,
			"sessions_partagees", cfg.HASharedSess, "en_attente", cfg.HAStandby)
	}

	if !cfg.Enabled {
		s.cfg = cfg
		s.stopLocked()
		if cfg.HAStandby && cfg.HAKey != "" {
			if err := s.ensureStandbyStoreLocked(); err != nil {
				s.log.Warn("portal: magasin de réplication indisponible", "err", err)
			} else {
				s.log.Info("portal: en attente (réplique du groupe HA, sans écouter)", "groupe", cfg.HAGroup)
				return nil
			}
		}
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
		s.cfg.HAGroup, s.cfg.HAMembers, s.cfg.HAKey = cfg.HAGroup, cfg.HAMembers, cfg.HAKey
		s.cfg.HASharedSess, s.cfg.HAStandby = cfg.HASharedSess, cfg.HAStandby
		s.cfg.Policy = cfg.Policy
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
	if s.reapStop != nil {
		close(s.reapStop)
		s.reapStop = nil
	}
	s.running = false
}

func (s *Service) startLocked() error {
	s.stopLocked()

	secret := resolveMasterKey()
	if secret == "" {
		return fmt.Errorf("portal: master key manquante (GPX_PORTAL_MASTER_KEY ou token passerelle)")
	}
	store := NewStore(s.cfg.DBPath, secret)
	if err := store.Load(); err != nil {
		return fmt.Errorf("portal store load: %w", err)
	}
	s.store = store
	s.sessions = NewSessionManager()
	s.masterSecret = secret
	if rec, err := NewRecordingStore(filepath.Join(filepath.Dir(s.cfg.DBPath), "recordings"), secret); err != nil {
		s.log.Warn("portal: dossier des enregistrements indisponible", "err", err)
		s.rec = nil
	} else {
		s.rec = rec
	}
	store.SetOnChange(s.onStoreChange)

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
	httpSrv.live = s.live
	httpSrv.grants = s.grants
	httpSrv.policy = s.Policy
	httpSrv.record = s.startRecording
	httpSrv.onAccessRequest = s.onAccessRequest
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
	sshSrv.live = s.live
	sshSrv.policy = s.Policy
	sshSrv.record = s.startRecording
	if err := sshSrv.Start(fmt.Sprintf(":%d", s.cfg.SSHPort)); err != nil {
		httpSrv.Stop()
		return fmt.Errorf("portal ssh: %w", err)
	}
	s.sshSrv = sshSrv
	s.running = true
	s.reapStop = make(chan struct{})
	go s.reapLoop(s.reapStop)
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
	return edgecache.ResolveSecret("")
}

// SetStoreChangeHook enregistre le rappel déclenché par une modification locale réplicable du magasin
// (envoi immédiat aux passerelles du groupe HA).
func (s *Service) SetStoreChangeHook(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onStoreChange = fn
	if s.store != nil {
		s.store.SetOnChange(fn)
	}
}

// ensureStandbyStoreLocked charge le magasin sans démarrer les écoutes : une passerelle sans portail
// garde ainsi une copie à jour et peut le reprendre.
func (s *Service) ensureStandbyStoreLocked() error {
	if s.store != nil {
		return nil
	}
	secret := resolveMasterKey()
	if secret == "" {
		return fmt.Errorf("portal: master key manquante (GPX_PORTAL_MASTER_KEY ou token passerelle)")
	}
	store := NewStore(s.cfg.DBPath, secret)
	if err := store.Load(); err != nil {
		return fmt.Errorf("portal store load: %w", err)
	}
	store.SetOnChange(s.onStoreChange)
	s.store = store
	s.masterSecret = secret
	return nil
}

// ReplicaInfo retourne le magasin et les paramètres de réplication HA, ou ok=false hors groupe
// ou tant que la clé du groupe n'est pas connue.
func (s *Service) ReplicaInfo() (store *Store, key string, members []string, sharedSessions, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == nil || s.cfg.HAGroup == "" || s.cfg.HAKey == "" {
		return nil, "", nil, false, false
	}
	return s.store, s.cfg.HAKey, append([]string(nil), s.cfg.HAMembers...), s.cfg.HASharedSess, true
}

// SetLiveHook notifie l'extérieur à chaque changement de la liste des connexions en cours.
func (s *Service) SetLiveHook(fn func()) { s.live.SetOnChange(fn) }

// LiveSessions retourne les connexions pontées en cours.
func (s *Service) LiveSessions() []LiveSession { return s.live.List() }

// KillLive ferme une connexion en cours ; false si elle est déjà terminée.
func (s *Service) KillLive(id string) bool { return s.live.Kill(id) }

// SetGrants remplace les accès temporaires approuvés (push Admin).
func (s *Service) SetGrants(list []AccessGrant) { s.grants.Replace(list) }

// SetAccessRequestHook fournit l'envoi des demandes d'accès vers l'Admin.
func (s *Service) SetAccessRequestHook(fn func(AccessRequest) error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onAccessRequest = fn
	if s.httpSrv != nil {
		s.httpSrv.onAccessRequest = fn
	}
}

// Policy retourne la politique d'accès courante.
func (s *Service) Policy() Policy {
	if p := s.policy.Load(); p != nil {
		return *p
	}
	return Policy{}
}

// reapLoop ferme les connexions inactives selon la politique, jusqu'à l'arrêt du service.
func (s *Service) reapLoop(stop <-chan struct{}) {
	tk := time.NewTicker(30 * time.Second)
	ticks := 0
	defer tk.Stop()
	for {
		select {
		case <-stop:
			return
		case <-tk.C:
			ticks++
			if ticks%120 == 0 {
				if days := s.Policy().RecordRetentionDays; days > 0 {
					if n := s.recordingStore().Purge(days, time.Now()); n > 0 {
						s.log.Info("portal: enregistrements expirés supprimés", "count", n)
					}
				}
			}
			mins := s.Policy().IdleTimeoutMin
			if mins <= 0 {
				continue
			}
			for _, m := range s.live.ReapIdle(time.Duration(mins)*time.Minute, time.Now()) {
				s.audit(AuditEvent{Actor: m.Actor, TargetID: m.TargetID, Facade: SessionFacade(m.Facade), Success: true, Detail: "idle_timeout"})
			}
		}
	}
}

func (s *Service) recordingStore() *RecordingStore {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rec
}

// startRecording ouvre l'enregistrement d'une session quand la politique le demande.
func (s *Service) startRecording(actor, targetID, facade, remote string) *Recording {
	if !s.Policy().RecordSessions {
		return nil
	}
	return s.recordingStore().Start(actor, targetID, facade, remote)
}

// ListRecordings retourne les enregistrements de sessions de cette passerelle.
func (s *Service) ListRecordings() ([]RecordingMeta, error) {
	st := s.recordingStore()
	if st == nil {
		return []RecordingMeta{}, nil
	}
	return st.List()
}

// ReadRecording retourne un enregistrement déchiffré (asciicast v2).
func (s *Service) ReadRecording(id string) ([]byte, error) {
	st := s.recordingStore()
	if st == nil {
		return nil, os.ErrNotExist
	}
	return st.Read(id)
}

// DeleteRecording supprime un enregistrement.
func (s *Service) DeleteRecording(id string) error {
	st := s.recordingStore()
	if st == nil {
		return os.ErrNotExist
	}
	return st.Delete(id)
}

// WatchLive s'abonne à la sortie d'une connexion en cours pour un administrateur qui l'observe ;
// l'observation est journalisée dans l'audit du portail.
func (s *Service) WatchLive(id string) (backlog []byte, out <-chan []byte, cancel func(), ok bool) {
	meta, backlog, out, cancel, ok := s.live.Subscribe(id)
	if !ok {
		return nil, nil, nil, false
	}
	if s.audit != nil {
		s.audit(AuditEvent{Actor: meta.Actor, TargetID: meta.TargetID, Facade: SessionFacade(meta.Facade), Success: true, Detail: "observed_by_admin"})
	}
	return backlog, out, cancel, true
}
