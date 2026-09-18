// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package admin implémente le Control Plane — API REST, auth, SQLite, gestion des routes.
package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/acme"
	"github.com/vincamok/goproxify/internal/admin/alerting"
	"github.com/vincamok/goproxify/internal/admin/analytics"
	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/archstore"
	"github.com/vincamok/goproxify/internal/admin/audit"
	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/backup"
	"github.com/vincamok/goproxify/internal/admin/corews"
	"github.com/vincamok/goproxify/internal/admin/crowdsec"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/fail2ban"
	"github.com/vincamok/goproxify/internal/admin/ha"
	"github.com/vincamok/goproxify/internal/admin/ipprofile"
	"github.com/vincamok/goproxify/internal/admin/logs"
	"github.com/vincamok/goproxify/internal/admin/mcp"
	"github.com/vincamok/goproxify/internal/admin/mfa"
	"github.com/vincamok/goproxify/internal/admin/monitor"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/admin/security"
	"github.com/vincamok/goproxify/internal/admin/setup"
	"github.com/vincamok/goproxify/internal/admin/ui"
	"github.com/vincamok/goproxify/internal/admin/vulnscan"
	"github.com/vincamok/goproxify/internal/buildinfo"
	"github.com/vincamok/goproxify/internal/config"
	coreWS "github.com/vincamok/goproxify/internal/core/ws"
)

// Server est le Control Plane de Goproxify.
type Server struct {
	cfg            *config.AdminConfig
	db             *sql.DB
	log            *slog.Logger
	srv            *http.Server
	haManager      *ha.Manager
	auditor        *audit.Logger
	alertingEngine *alerting.Engine
	logStore       *logs.Store
	wsManager      *corews.Manager // manager WS Admin→Core
	loginLimit     *loginLimiter
}

// New initialise le serveur Administration : ouvre SQLite, applique les migrations,
// gère le premier lancement.
func New(cfg *config.AdminConfig) (*Server, error) {
	level := parseLevel(cfg.App.LogLevel)
	stderrH := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})

	auth.ConfigureNodeTokenKey(cfg.Security.JWTSecret)

	db, err := admindb.Open(cfg.Storage.SQLiteDSN)
	if err != nil {
		return nil, err
	}

	setup.Init(db, cfg)

	logStore := logs.New(db)
	nodeName := cfg.HA.NodeID
	if nodeName == "" {
		nodeName = "admin"
	}
	storeH := &logs.StoreHandler{
		Store:     logStore,
		Level:     level,
		Component: "admin",
		NodeName:  nodeName,
	}
	log := slog.New(&logs.FanoutHandler{Handlers: []slog.Handler{stderrH, storeH}})

	s := &Server{
		cfg:            cfg,
		db:             db,
		log:            log,
		auditor:        audit.New(db, cfg.App.AuditRetentionDays),
		alertingEngine: alerting.New(db, log),
		logStore:       logStore,
		loginLimit:     newLoginLimiter(),
	}

	if cfg.HA.Enabled && cfg.HA.NodeID != "" {
		raftPort := cfg.HA.RaftPort
		if raftPort == 0 {
			raftPort = 9444
		}
		s.haManager = ha.New(ha.Config{
			NodeID:   cfg.HA.NodeID,
			Peers:    cfg.HA.Peers,
			RaftPort: raftPort,
		}, log)
	}

	return s, nil
}

// Start démarre le serveur HTTP/HTTPS de l'Administration.
func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	jwtSecret := s.cfg.Security.JWTSecret

	// Manager WS Admin→Core — HMAC partagé via GPX_PAIRING_SECRET
	hmacSecret := os.Getenv("GPX_PAIRING_SECRET")
	manager := corews.NewManager(hmacSecret, s.db, s.log)
	var archStore *archstore.Store
	if s.cfg.Storage.BasePath != "" {
		stateDir := filepath.Join(s.cfg.Storage.BasePath, "state")
		manager.SetDataDir(stateDir)
		archStore = archstore.New(stateDir)
		manager.SetArchStore(archStore)
	}
	s.wsManager = manager
	manager.SetSettings(s.runtimeSettings())
	manager.ConnectFromEnv(ctx)
	agentStore := api.NewAgentStore()
	manager.SetAgentPendingHandler(func(id, name, version string) {
		agentStore.Upsert(id, name, version, "pending")
		if api.NodeAutoAccept(s.db, name) || api.NodeAutoAccept(s.db, id) {
			manager.BroadcastApproveAgent(id)
			if name != "" && name != id {
				manager.BroadcastApproveAgent(name)
			}
			agentStore.Upsert(id, name, version, "approved")
			s.log.Info("pair: Agent auto-accepté (declared/bootstrap)", "id", id, "name", name)
		}
	})
	manager.SetLogBatchHandler(func(entries []coreWS.LogEntryPayload) {
		for _, item := range entries {
			ts, _ := time.Parse(time.RFC3339Nano, item.Ts)
			if ts.IsZero() {
				ts, _ = time.Parse(time.RFC3339, item.Ts)
			}
			if ts.IsZero() {
				ts = time.Now()
			}
			s.logStore.Write(logs.Entry{
				Ts:        ts,
				Level:     item.Level,
				Component: nvlStr(item.Component, "core"),
				NodeName:  item.NodeName,
				Domain:    item.Domain,
				Method:    item.Method,
				Path:      item.Path,
				Status:    item.Status,
				IP:        item.IP,
				LatencyMs: item.LatencyMs,
				Bytes:     item.Bytes,
				Message:   item.Message,
				Referrer:  item.Referrer,
			})
		}
	})

	backupSched := backup.New(s.db, s.log)
	if s.cfg.Storage.BasePath != "" {
		backupSched.SetSnapDir(filepath.Join(s.cfg.Storage.BasePath, "backups"))
	}
	proxiesH := &api.ProxiesHandler{DB: s.db, Log: s.log, Pusher: manager, Versioner: backupSched}
	backupH := &api.BackupHandler{DB: s.db, Log: s.log, Scheduler: backupSched, Pusher: manager}
	tokensH := &api.TokensHandler{
		DB: s.db, Log: s.log, Cores: manager, Pusher: manager,
		ArchStore: archStore,
		OnAgentRevoke: func(agentID string) {
			manager.BroadcastRevokeAgent(agentID)
		},
	}
	var userStore *archstore.UserStore
	if s.cfg.Storage.BasePath != "" {
		userStore = archstore.NewUserStore(filepath.Join(s.cfg.Storage.BasePath, "state"))
		// Restaurer depuis disque si DB vide, puis synchroniser
		_ = userStore.LoadIntoDB(ctx, s.db)
		go userStore.SyncFromDB(ctx, s.db) //nolint:errcheck
	}
	syncUsers := func() {
		if userStore != nil {
			go userStore.SyncFromDB(context.Background(), s.db) //nolint:errcheck
		}
	}
	var configStore *archstore.ConfigStore
	if s.cfg.Storage.BasePath != "" {
		configStore = archstore.NewConfigStore(filepath.Join(s.cfg.Storage.BasePath, "state"))
		_ = configStore.LoadIntoDB(ctx, s.db)
		go configStore.SyncFromDB(ctx, s.db) //nolint:errcheck
	}
	syncConfig := func() {
		if configStore != nil {
			go configStore.SyncFromDB(context.Background(), s.db) //nolint:errcheck
		}
	}
	usersH := &api.UsersHandler{DB: s.db, Log: s.log, OnChange: syncUsers}
	snippetsH := &api.SnippetsHandler{DB: s.db, Log: s.log, OnChange: syncConfig}
	errorPagesH := &api.ErrorPageTemplatesHandler{DB: s.db, Log: s.log, Pusher: manager, OnChange: syncConfig}
	portalPagesH := &api.PortalPageTemplatesHandler{DB: s.db, Log: s.log, Pusher: manager}
	authProvidersH := &api.AuthProvidersHandler{DB: s.db, Log: s.log, OnChange: syncConfig}
	portalH := &api.PortalHandler{DB: s.db, Log: s.log, Pusher: manager}
	// Fallback direct sur les vars d'env si Viper n'a pas résolu les clés imbriquées
	if !s.cfg.ACME.Enabled {
		s.cfg.ACME.Enabled = os.Getenv("GPX_ACME_ENABLED") == "true"
	}
	if s.cfg.ACME.Email == "" {
		s.cfg.ACME.Email = os.Getenv("GPX_ACME_EMAIL")
	}
	if s.cfg.ACME.DNS.Type == "" {
		s.cfg.ACME.DNS.Type = os.Getenv("GPX_ACME_DNS_TYPE")
	}
	// Fallback DB : si env/config n'ont pas fourni la config ACME, on lit la DB.
	// La DB permet de configurer ACME depuis l'UI sans variables d'env.
	if !s.cfg.ACME.Enabled || s.cfg.ACME.Email == "" {
		if dbCfg := acme.LoadConfig(s.db); dbCfg.Enabled && dbCfg.Email != "" {
			if !s.cfg.ACME.Enabled {
				s.cfg.ACME.Enabled = dbCfg.Enabled
			}
			if s.cfg.ACME.Email == "" {
				s.cfg.ACME.Email = dbCfg.Email
			}
			if s.cfg.ACME.DirectoryURL == "" {
				s.cfg.ACME.DirectoryURL = dbCfg.DirectoryURL
			}
			if s.cfg.ACME.DNS.Type == "" {
				s.cfg.ACME.DNS.Type = dbCfg.DNSType
			}
		}
	}
	buildACMEManager := func(email, directoryURL, dnsType string) *acme.Manager {
		if !s.cfg.ACME.Enabled && email == "" {
			return nil
		}
		var provider acme.DNSProvider
		if dnsType != "" {
			provCfg := acme.ProviderConfigFromEnv(dnsType)
			if len(s.cfg.ACME.DNS.Params) > 0 {
				provCfg.Params = s.cfg.ACME.DNS.Params
			}
			if p, err := acme.NewProvider(provCfg); err != nil {
				s.log.Warn("acme: fournisseur DNS indisponible", "err", err)
			} else {
				provider = p
			}
		}
		mgr := acme.New(s.db, s.log, manager, provider, email)
		mgr.DirectoryURL = directoryURL
		if s.cfg.Storage.BasePath != "" {
			mgr.SetCertDir(filepath.Join(s.cfg.Storage.BasePath, "certs"))
		}
		mgr.LoadCertsFromDisk(ctx)
		return mgr
	}
	var acmeMgr *acme.Manager
	if s.cfg.ACME.Enabled && s.cfg.ACME.Email != "" {
		acmeMgr = buildACMEManager(s.cfg.ACME.Email, s.cfg.ACME.DirectoryURL, s.cfg.ACME.DNS.Type)
	}
	certsH := &api.CertsHandler{DB: s.db, Log: s.log, Manager: acmeMgr}
	nodesH := &api.NodesHandler{DB: s.db, Log: s.log}
	autoConfigurer := &api.AgentAutoConfigurer{DB: s.db, Log: s.log, Nodes: nodesH}
	go autoConfigurer.Start(ctx)
	declaredNodesH := &api.DeclaredNodesHandler{DB: s.db, Log: s.log, CoreNodeName: s.cfg.Identity.CoreNodeName, Scheduler: backupSched, ArchStore: archStore}
	bootstrapH := &api.BootstrapHandler{
		DB:  s.db,
		Log: s.log,
		ResolvePublicURL: func(r *http.Request) string {
			if u := s.resolveAdminPublicURL(); u != "" {
				return u
			}
			return publicOriginFromRequest(r)
		},
	}
	heartbeatH := &api.HeartbeatHandler{DB: s.db, Log: s.log}
	nodeEventsH := &api.NodeEventsHandler{DB: s.db, Log: s.log, AlertingEngine: s.alertingEngine}
	healthH := &api.HealthHandler{
		DB:      s.db,
		Log:     s.log,
		Version: buildinfo.Admin,
		Webapp:  buildinfo.Webapp,
		Commit:  buildinfo.Commit,
		Built:   buildinfo.Built,
	}
	auditH := &api.AuditHandler{DB: s.db, Log: s.log, Auditor: s.auditor}
	channelsH := &api.ChannelsHandler{DB: s.db, Log: s.log, Engine: s.alertingEngine, OnChange: syncConfig}
	rulesH := &api.RulesHandler{DB: s.db, Log: s.log, Engine: s.alertingEngine, OnChange: syncConfig}
	logsH := &api.LogsHandler{Log: s.log, Store: s.logStore, DB: s.db}
	f2bEngine := fail2ban.New(s.db, s.log)
	vsScanner := vulnscan.New(s.db, s.log, "")
	csBouncer := crowdsec.New(s.db, s.log)
	if cfg := csBouncer.GetConfig(); !cfg.Enabled {
		s.log.Warn("crowdsec: désactivé par défaut — activer via Admin → Sécurité (LAPI) pour synchroniser les bans")
	}
	pushBans := func() {
		if manager != nil {
			go manager.PushBans(context.Background())
		}
	}
	f2bEngine.OnBan = func(ip, reason string) {
		if s.alertingEngine != nil {
			s.alertingEngine.Emit(alerting.Event{
				Trigger:   alerting.TriggerFail2BanBan,
				Severity:  alerting.SevWarning,
				Component: "admin",
				Detail:    map[string]any{"ip": ip, "reason": reason},
			})
		}
		pushBans()
	}
	csBouncer.OnChange = pushBans
	csBouncer.OnNewDecision = func(d crowdsec.Decision) {
		if s.alertingEngine != nil {
			s.alertingEngine.Emit(alerting.Event{
				Trigger:   alerting.TriggerCrowdSecCritical,
				Severity:  alerting.SevCritical,
				Component: "admin",
				Detail: map[string]any{
					"ip":       d.Value,
					"scenario": d.Scenario,
					"origin":   d.Origin,
					"type":     d.Type,
				},
			})
		}
	}
	securityH := &api.SecurityHandler{
		DB:           s.db,
		Log:          s.log,
		Store:        security.New(s.db),
		Fail2Ban:     f2bEngine,
		VulnScan:     vsScanner,
		CrowdSec:     csBouncer,
		ScanCtx:      ctx,
		OnBansChange: pushBans,
		OnThreatConfigChange: func(cfg any) {
			if manager != nil {
				go manager.PushThreatConfig(context.Background(), cfg)
			}
		},
		OnServerConfigChange: func(cfg any) {
			if manager != nil {
				go manager.PushServerConfig(context.Background(), cfg)
			}
		},
	}
	importH := &api.ImportHandler{DB: s.db, Log: s.log}
	prismH := &api.PrismHandler{DB: s.db}
	ipUpdater := ipprofile.New(s.db, s.log)
	ipProfilesH := &api.IPProfilesHandler{DB: s.db, Log: s.log, Updater: ipUpdater, OnChange: syncConfig}
	syncArch := func() {
		if archStore != nil {
			go archStore.SyncFromDB(context.Background(), s.db) //nolint:errcheck
		}
	}
	teamsH := &api.TeamsHandler{DB: s.db, Log: s.log, OnChange: syncUsers}
	discoveredH := &api.DiscoveredContainersHandler{DB: s.db, Log: s.log}
	backendsHealthH := &api.BackendsHealthHandler{DB: s.db, Log: s.log}
	domainsH := &api.DomainsHandler{DB: s.db, Log: s.log, Pusher: manager, OnChange: syncArch}
	agentsH := &api.AgentsHandler{
		Log:   s.log,
		Store: agentStore,
		OnApprove: func(agentID string) {
			// Broadcaster approve_agent à tous les Cores — le Core qui a l'Agent le traitera
			manager.BroadcastApproveAgent(agentID)
		},
		OnRevoke: func(agentID string) {
			manager.BroadcastRevokeAgent(agentID)
		},
	}
	if acmeMgr != nil {
		domainsH.Manager = acmeMgr
	}
	acmeSettingsH := &api.ACMESettingsHandler{
		DB:  s.db,
		Log: s.log,
		OnUpdate: func(cfg acme.DBConfig) {
			newMgr := buildACMEManager(cfg.Email, cfg.DirectoryURL, cfg.DNSType)
			certsH.Manager = newMgr
			domainsH.Manager = newMgr
			if newMgr != nil {
				newMgr.Start(ctx)
				s.log.Info("acme: manager réinitialisé", "email", cfg.Email)
			}
		},
	}

	geoResolver := &analytics.GeoResolver{DB: s.db, Log: s.log}
	geoResolver.Start(ctx)

	f2bEngine.Start(ctx)
	vsScanner.Start(ctx)
	csBouncer.Start(ctx)
	backupSched.Start(ctx)
	ipUpdater.Start(ctx)
	if acmeMgr != nil {
		acmeMgr.Start(ctx)
	}

	// Monitor : erreur rate & latence, avec seuils configurables.
	mon := monitor.New(s.db, s.log, s.alertingEngine, monitor.DefaultConfig())
	mon.Start(ctx)

	// Rétention des logs RGPD (lit logs.retention_access_days / logs.retention_system_days dans settings).
	s.logStore.StartRetentionLoop(ctx, func() (accessDays, systemDays int) {
		parseInt := func(key string, def int) int {
			v := admindb.GetSetting(s.db, key, "")
			if v == "" {
				return def
			}
			n := def
			fmt.Sscanf(v, "%d", &n) //nolint:errcheck
			return n
		}
		return parseInt("logs.retention_access_days", logs.DefaultRetentionAccessDays),
			parseInt("logs.retention_system_days", logs.DefaultRetentionSystemDays)
	})

	if s.haManager != nil {
		if err := s.haManager.Start(ctx); err != nil {
			s.log.Warn("ha: démarrage échoué (non bloquant)", "err", err)
		}
		mux.HandleFunc("GET /ha/status", s.haManager.HandleStatus)
	}

	// Interface web d'administration (SPA)
	mux.Handle("/", ui.Handler())

	// MFA handler
	waOrigin := admindb.GetSetting(s.db, "mfa.webauthn.origin", "")
	waRPID := admindb.GetSetting(s.db, "mfa.webauthn.rpid", "")
	waInstance, _ := mfa.NewWebAuthn(waRPID, waOrigin, "Goproxify")
	mfaH := &api.MFAHandler{
		DB:        s.db,
		Log:       s.log,
		Store:     mfa.NewStore(s.db),
		JWTSecret: jwtSecret,
		WebAuthn:  waInstance,
		OnChange:  syncUsers,
	}

	meH := &api.MeHandler{DB: s.db, Log: s.log, OnChange: syncUsers}

	// OpenAPI spec + Scalar UI
	openapiH := &api.OpenAPIHandler{}
	mux.Handle("GET /openapi.yaml", openapiH)
	mux.Handle("GET /api-docs", openapiH)

	// Routes publiques
	mux.Handle("GET /api/v1/health", healthH)
	mux.HandleFunc("GET /api/v1/setup/status", s.handleSetupStatus)
	mux.HandleFunc("POST /api/v1/setup/init", s.handleSetupInit)
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	// Tickets bootstrap architecture (QR / lien public)
	mux.HandleFunc("GET /i/{token}", bootstrapH.ServePublic)
	mux.HandleFunc("GET /api/v1/bootstrap/{token}", bootstrapH.ServePublic)
	// Routes MFA publiques (challenge pendant le login)
	mux.HandleFunc("POST /api/v1/auth/mfa/challenge", mfaH.ServeHTTP)
	mux.HandleFunc("POST /api/v1/auth/mfa/webauthn/login/begin", mfaH.ServeHTTP)
	mux.HandleFunc("POST /api/v1/auth/mfa/webauthn/login/finish", mfaH.ServeHTTP)

	// Routes internes — Cores et Agents (token d'appairage)
	mux.HandleFunc("POST /internal/v1/pair", s.handlePair)
	mux.HandleFunc("GET /internal/v1/pair/status", s.handlePairStatus)
	mux.Handle("POST /internal/v1/cores/register", auth.RequireBearerToken(s.db)(http.HandlerFunc(s.handleCoreRegister(manager))))
	mux.Handle("GET /internal/v1/routes", auth.RequireBearerToken(s.db)(http.HandlerFunc(s.handleCoreRoutes)))
	mux.Handle("GET /internal/v1/nodes/metrics", auth.RequireBearerToken(s.db)(http.HandlerFunc(s.handleNodeMetrics)))
	mux.Handle("/internal/v1/logs", auth.RequireBearerToken(s.db)(http.HandlerFunc(s.handleAgentLogs)))
	mux.Handle("/internal/v1/security/bans", auth.RequireBearerToken(s.db)(http.HandlerFunc(s.handleInternalBans)))
	mux.Handle("/internal/v1/security/threats", auth.RequireBearerToken(s.db)(http.HandlerFunc(s.handleInternalThreats)))
	mux.Handle("/internal/v1/security/cves", auth.RequireBearerToken(s.db)(http.HandlerFunc(s.handleInternalCVEs)))

	// Middleware d'accès : JWT session UI ou PAT utilisateur ; scopes PAT appliqués ensuite.
	// Les sessions UI (JWT) mémorisent l'origine publique pour les liens des pages d'erreur Core.
	protected := func(h http.Handler) http.Handler {
		return auth.RequireAuth(jwtSecret, s.db)(rbac.EnforcePATScope(s.db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if auth.AuthKindFromContext(r.Context()) == auth.AuthKindJWT {
				s.maybeRememberPublicURL(r)
			}
			h.ServeHTTP(w, r)
		})))
	}
	adminOnly := func(h http.Handler) http.Handler { return protected(rbac.RequireAdmin(s.db)(h)) }
	userTokensH := &api.UserTokensHandler{DB: s.db, Log: s.log, OnChange: syncUsers}

	// Routes proxies : lecture pour tous les authentifiés (filtrée par scope dans le handler),
	// écriture/suppression vérifiées dans le handler selon le rôle.
	mux.Handle("/api/v1/proxies", protected(proxiesH))
	mux.Handle("/api/v1/proxies/", protected(proxiesH))
	// Gestion des utilisateurs, tokens, équipes : admin uniquement
	mux.Handle("/api/v1/tokens", adminOnly(tokensH))
	mux.Handle("/api/v1/tokens/", adminOnly(tokensH))
	mux.Handle("/api/v1/users", adminOnly(usersH))
	mux.Handle("/api/v1/users/", adminOnly(usersH))
	mux.Handle("/api/v1/teams", adminOnly(teamsH))
	mux.Handle("/api/v1/teams/", adminOnly(teamsH))
	mux.Handle("/api/v1/snippets", protected(snippetsH))
	mux.Handle("/api/v1/snippets/", protected(snippetsH))
	mux.Handle("/api/v1/error-page-templates", adminOnly(errorPagesH))
	mux.Handle("/api/v1/error-page-templates/", adminOnly(errorPagesH))
	mux.Handle("/api/v1/portal-page-templates", adminOnly(portalPagesH))
	mux.Handle("/api/v1/portal-page-templates/", adminOnly(portalPagesH))
	mux.Handle("/api/v1/auth-providers", adminOnly(authProvidersH))
	mux.Handle("/api/v1/auth-providers/", adminOnly(authProvidersH))
	mux.Handle("/api/v1/portal", adminOnly(portalH))
	mux.Handle("/api/v1/portal/", adminOnly(portalH))
	mux.Handle("/api/v1/certs", protected(certsH))
	mux.Handle("/api/v1/certs/", protected(certsH))
	mux.Handle("/api/v1/nodes", protected(nodesH))
	mux.Handle("/api/v1/nodes/", protected(nodesH))
	mux.Handle("/api/v1/declared-nodes", protected(declaredNodesH))
	mux.Handle("/api/v1/declared-nodes/", protected(declaredNodesH))
	mux.Handle("POST /api/v1/bootstrap-tickets", protected(http.HandlerFunc(bootstrapH.ServeCreate)))
	mux.Handle("/api/v1/node-events", protected(nodeEventsH))
	mux.Handle("/api/v1/discovered-containers", protected(discoveredH))
	mux.Handle("/api/v1/backends/health", protected(backendsHealthH))
	mux.Handle("/api/v1/audit", protected(auditH))
	mux.Handle("/api/v1/audit/", protected(auditH))
	mux.Handle("/api/v1/alert-channels", protected(channelsH))
	mux.Handle("/api/v1/alert-channels/", protected(channelsH))
	mux.Handle("/api/v1/alert-rules", protected(rulesH))
	mux.Handle("/api/v1/alert-rules/", protected(rulesH))
	mux.Handle("/api/v1/logs", protected(logsH))
	mux.Handle("/api/v1/logs/", protected(logsH))
	mux.Handle("/api/v1/security", adminOnly(securityH))
	mux.Handle("/api/v1/security/", adminOnly(securityH))
	mux.Handle("GET /api/v1/cores/waf-status", protected(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rows, err := s.db.QueryContext(r.Context(),
			`SELECT key, value FROM settings WHERE key LIKE 'waf_reloaded_at:%'`)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer rows.Close()
		result := map[string]string{}
		for rows.Next() {
			var k, v string
			if rows.Scan(&k, &v) == nil {
				node := k[len("waf_reloaded_at:"):]
				result[node] = v
			}
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result) //nolint:errcheck
	})))
	mux.Handle("/api/v1/import", adminOnly(importH))
	mux.Handle("/api/v1/import/", adminOnly(importH))
	mux.Handle("/api/v1/backups", adminOnly(backupH))
	mux.Handle("/api/v1/backups/", adminOnly(backupH))
	mux.Handle("/api/v1/prism/", protected(prismH))
	mux.Handle("/api/v1/ip-profiles", protected(ipProfilesH))
	mux.Handle("/api/v1/ip-profiles/", protected(ipProfilesH))
	mux.Handle("/api/v1/domains", protected(domainsH))
	mux.Handle("/api/v1/domains/", protected(domainsH))
	mux.Handle("/api/v1/agents", adminOnly(agentsH))
	mux.Handle("/api/v1/agents/", adminOnly(agentsH))

	// Pairing secret — lecture réservée aux admins (wizard Infrastructure).
	mux.Handle("GET /api/v1/pairing-secret", adminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret := os.Getenv("GPX_PAIRING_SECRET")
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"secret": secret}) //nolint:errcheck
	})))

	// Profil utilisateur connecté
	mux.Handle("/api/v1/me", protected(meH))
	mux.Handle("/api/v1/me/", protected(meH))
	mux.Handle("/api/v1/me/tokens", protected(userTokensH))
	mux.Handle("/api/v1/me/tokens/", protected(userTokensH))
	mux.Handle("GET /api/v1/auth/me", protected(http.HandlerFunc(meH.GetMeHTTP)))

	// Routes MFA protégées (gestion du profil MFA)
	mux.Handle("/api/v1/auth/mfa", protected(mfaH))
	mux.Handle("/api/v1/auth/mfa/", protected(mfaH))

	// Settings MFA (admin — SMS provider, WebAuthn)
	mfaSettingsH := &api.MFASettingsHandler{DB: s.db, Log: s.log}
	mux.Handle("/api/v1/settings/mfa/", adminOnly(mfaSettingsH))
	mux.Handle("/api/v1/settings/smtp", adminOnly(&api.SMTPSettingsHandler{DB: s.db, Log: s.log}))
	mux.Handle("/api/v1/settings/smtp/", adminOnly(&api.SMTPSettingsHandler{DB: s.db, Log: s.log}))
	mux.Handle("/api/v1/settings/acme", adminOnly(acmeSettingsH))

	// MCP server — PAT utilisateur uniquement (pas de JWT session)
	mcpH := &mcp.Handler{
		DB: s.db, Log: s.log, Pusher: manager,
		Access: manager, AccessTemplates: manager,
		ResolvePublicURL: bootstrapH.ResolvePublicURL,
		ListAgents: func() []mcp.AgentInfo {
			raw := agentStore.List()
			out := make([]mcp.AgentInfo, 0, len(raw))
			for _, a := range raw {
				out = append(out, mcp.AgentInfo{
					ID: a.ID, Name: a.Name, Version: a.Version,
					Status: a.Status, SeenAt: a.SeenAt,
				})
			}
			return out
		},
		ApproveAgent: func(agentID string) {
			manager.BroadcastApproveAgent(agentID)
			agentStore.Upsert(agentID, agentID, "", "approved")
		},
		RevokeAgent: func(agentID string) {
			manager.BroadcastRevokeAgent(agentID)
			agentStore.Upsert(agentID, agentID, "", "revoked")
		},
		OnBansChange: pushBans,
	}
	mux.Handle("/mcp", auth.RequirePAT(s.db)(mcpH))
	mux.Handle("/mcp/", auth.RequirePAT(s.db)(mcpH))

	// Heartbeat et events — authentifiés par token d'appairage
	mux.Handle("/internal/v1/heartbeat", auth.RequireBearerToken(s.db)(heartbeatH))
	mux.Handle("/internal/v1/events", auth.RequireBearerToken(s.db)(nodeEventsH))

	addr := fmt.Sprintf("%s:%d", s.cfg.Server.ListenAddr, s.cfg.Server.APIPort)
	var handler http.Handler = s.logMiddleware(mux)
	if s.haManager != nil {
		handler = s.haManager.ForwardOrHandle(handler)
	}
	s.srv = &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	tlsCert := strings.TrimSpace(os.Getenv("GPX_ADMIN_TLS_CERT"))
	tlsKey := strings.TrimSpace(os.Getenv("GPX_ADMIN_TLS_KEY"))
	if tlsCert != "" && tlsKey != "" {
		s.log.Info("administration démarrée (HTTPS)", "addr", addr)
		go func() {
			if err := s.srv.ListenAndServeTLS(tlsCert, tlsKey); err != nil && err != http.ErrServerClosed {
				s.log.Error("admin server TLS", "err", err)
			}
		}()
	} else {
		s.log.Warn("administration en HTTP clair — terminaison TLS recommandée (reverse-proxy) ou GPX_ADMIN_TLS_CERT/KEY",
			"addr", addr)
		go func() {
			if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				s.log.Error("admin server", "err", err)
			}
		}()
	}

	// Port local de secours : accès direct sans passer par le Core.
	// Utile si Sentinel ou une règle de sécurité bloque l'accès proxifié.
	if s.cfg.Server.LocalPort > 0 {
		localAddr := fmt.Sprintf("0.0.0.0:%d", s.cfg.Server.LocalPort)
		localSrv := &http.Server{
			Addr:         localAddr,
			Handler:      s.logMiddleware(mux), // sans HA forward
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		}
		go func() {
			s.log.Info("administration (port local direct)", "addr", localAddr)
			if err := localSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				s.log.Error("admin local server", "err", err)
			}
		}()
	}

	return nil
}

// Stop arrête proprement le serveur.
func (s *Server) Stop(ctx context.Context) {
	if s.wsManager != nil {
		s.wsManager.Close()
	}
	if s.srv != nil {
		s.srv.Shutdown(ctx) //nolint:errcheck
	}
	if s.db != nil {
		s.db.Close() //nolint:errcheck
	}
	if s.haManager != nil {
		s.haManager.Stop()
	}
	if s.alertingEngine != nil {
		s.alertingEngine.Stop()
	}
}

// ResetPassword réinitialise le mot de passe d'un utilisateur (commande CLI).
func ResetPassword(cfg *config.AdminConfig, email, newPassword string) error {
	db, err := admindb.Open(cfg.Storage.SQLiteDSN)
	if err != nil {
		return err
	}
	defer db.Close()

	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	res, err := db.Exec(`UPDATE users SET password_hash=? WHERE email=?`, hash, email)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return &notFoundError{email}
	}
	return nil
}

func (s *Server) mfaStore() *mfa.Store { return mfa.NewStore(s.db) }

