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
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/acme"
	"github.com/vincamok/goproxify/internal/admin/alerting"
	"github.com/vincamok/goproxify/internal/admin/analytics"
	"github.com/vincamok/goproxify/internal/admin/api"
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
	"github.com/vincamok/goproxify/internal/core/router"
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
	proxiesH := &api.ProxiesHandler{DB: s.db, Log: s.log, Pusher: manager, Versioner: backupSched}
	backupH := &api.BackupHandler{DB: s.db, Log: s.log, Scheduler: backupSched, Pusher: manager}
	tokensH := &api.TokensHandler{
		DB: s.db, Log: s.log, Cores: manager, Pusher: manager,
		OnAgentRevoke: func(agentID string) {
			manager.BroadcastRevokeAgent(agentID)
		},
	}
	usersH := &api.UsersHandler{DB: s.db, Log: s.log}
	snippetsH := &api.SnippetsHandler{DB: s.db, Log: s.log}
	errorPagesH := &api.ErrorPageTemplatesHandler{DB: s.db, Log: s.log, Pusher: manager}
	portalPagesH := &api.PortalPageTemplatesHandler{DB: s.db, Log: s.log, Pusher: manager}
	authProvidersH := &api.AuthProvidersHandler{DB: s.db, Log: s.log}
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
	var acmeMgr *acme.Manager
	if s.cfg.ACME.Enabled && s.cfg.ACME.Email != "" {
		var provider acme.DNSProvider
		if s.cfg.ACME.DNS.Type != "" {
			provCfg := acme.ProviderConfigFromEnv(s.cfg.ACME.DNS.Type)
			if len(s.cfg.ACME.DNS.Params) > 0 {
				provCfg.Params = s.cfg.ACME.DNS.Params
			}
			if p, err := acme.NewProvider(provCfg); err != nil {
				s.log.Warn("acme: fournisseur DNS indisponible", "err", err)
			} else {
				provider = p
			}
		}
		mgr := acme.New(s.db, s.log, manager, provider, s.cfg.ACME.Email)
		mgr.DirectoryURL = s.cfg.ACME.DirectoryURL
		acmeMgr = mgr
	}
	certsH := &api.CertsHandler{DB: s.db, Log: s.log, Manager: acmeMgr}
	nodesH := &api.NodesHandler{DB: s.db, Log: s.log}
	declaredNodesH := &api.DeclaredNodesHandler{DB: s.db, Log: s.log}
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
	channelsH := &api.ChannelsHandler{DB: s.db, Log: s.log, Engine: s.alertingEngine}
	rulesH := &api.RulesHandler{DB: s.db, Log: s.log, Engine: s.alertingEngine}
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
	}
	importH := &api.ImportHandler{DB: s.db, Log: s.log}
	prismH := &api.PrismHandler{DB: s.db}
	ipUpdater := ipprofile.New(s.db, s.log)
	ipProfilesH := &api.IPProfilesHandler{DB: s.db, Log: s.log, Updater: ipUpdater}
	teamsH := &api.TeamsHandler{DB: s.db, Log: s.log}
	discoveredH := &api.DiscoveredContainersHandler{DB: s.db, Log: s.log}
	backendsHealthH := &api.BackendsHealthHandler{DB: s.db, Log: s.log}
	domainsH := &api.DomainsHandler{DB: s.db, Log: s.log, Pusher: manager}
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

	// Rétention des logs (lit logs.retention_days dans settings).
	s.logStore.StartRetentionLoop(ctx, func() int {
		v := admindb.GetSetting(s.db, "logs.retention_days", "30")
		n := 30
		if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
			n = 30
		}
		return n
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
	}

	meH := &api.MeHandler{DB: s.db, Log: s.log}

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
	userTokensH := &api.UserTokensHandler{DB: s.db, Log: s.log}

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

// --- Login ---------------------------------------------------------------

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handleSetupStatus(w http.ResponseWriter, r *http.Request) {
	initialized := !setup.IsFirstRun(s.db)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]bool{"initialized": initialized}) //nolint:errcheck
}

func (s *Server) handleSetupInit(w http.ResponseWriter, r *http.Request) {
	if !setup.IsFirstRun(s.db) {
		http.Error(w, "déjà initialisé", http.StatusConflict)
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" || req.Password == "" {
		http.Error(w, "email et password requis", http.StatusBadRequest)
		return
	}
	if err := setup.CreateFirstAdmin(s.db, req.Email, req.Password); err != nil {
		s.log.Error("setup: création admin", "err", err)
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "corps JSON invalide", http.StatusBadRequest)
		return
	}

	ip := clientIP(r.RemoteAddr)
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		ip = strings.TrimSpace(strings.Split(xf, ",")[0])
	}
	key := loginKey(ip, req.Email)
	if blocked, wait := s.loginLimit.blocked(key); blocked {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(wait.Seconds())+1))
		http.Error(w, "trop de tentatives — réessayez plus tard", http.StatusTooManyRequests)
		return
	}

	var id, hash string
	err := s.db.QueryRowContext(r.Context(),
		`SELECT id, password_hash FROM users WHERE email=?`, req.Email,
	).Scan(&id, &hash)
	if err != nil || !auth.CheckPassword(hash, req.Password) {
		s.loginLimit.fail(key)
		s.auditor.Log(r.Context(), audit.Event{
			Action: "login_failed", Actor: req.Email, IP: audit.IPFrom(r), Severity: audit.Warning,
		})
		s.alertingEngine.Emit(alerting.Event{
			Trigger: alerting.TriggerAdminAuthFailures, Severity: alerting.SevWarning,
			Component: "admin", Detail: map[string]any{"email": req.Email, "ip": audit.IPFrom(r)},
		})
		http.Error(w, "email ou mot de passe incorrect", http.StatusUnauthorized)
		return
	}

	s.loginLimit.success(key)

	s.auditor.Log(r.Context(), audit.Event{
		Action: "login", Actor: req.Email, UserID: id, IP: audit.IPFrom(r), Severity: audit.Info,
	})

	// Vérifier si l'appareil est déjà de confiance (bypass MFA)
	mfaStore := s.mfaStore()
	deviceToken := r.Header.Get("X-Device-Token")
	if deviceToken == "" {
		if c, err := r.Cookie(mfa.TrustedDeviceCookie); err == nil {
			deviceToken = c.Value
		}
	}
	if deviceToken != "" && mfaStore.IsTrustedDevice(r.Context(), id, mfa.HashDeviceToken(deviceToken)) {
		// Appareil de confiance → JWT complet directement
		token, err := auth.SignJWT(id, s.cfg.Security.JWTSecret, 24*time.Hour)
		if err != nil {
			http.Error(w, "erreur interne", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"token": token}) //nolint:errcheck
		return
	}

	// Vérifier si la MFA est activée pour cet utilisateur
	hasMFA, err := mfaStore.HasVerifiedMFA(r.Context(), id)
	if err == nil && hasMFA {
		// Retourner un token MFA intermédiaire (202)
		pending, err := auth.SignMFAPendingToken(id, s.cfg.Security.JWTSecret)
		if err != nil {
			http.Error(w, "erreur interne", http.StatusInternalServerError)
			return
		}
		// Lister les méthodes disponibles pour l'UI
		methods, _ := mfaStore.ListMethods(r.Context(), id)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"mfa_required": true,
			"mfa_token":    pending,
			"methods":      methods,
		})
		return
	}

	token, err := auth.SignJWT(id, s.cfg.Security.JWTSecret, 24*time.Hour)
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": token}) //nolint:errcheck
}

// --- Routes pour les Agents ----------------------------------------------

func (s *Server) handleAgentLogs(w http.ResponseWriter, r *http.Request) {
	var batch []struct {
		Ts        string `json:"ts"`
		Level     string `json:"level"`
		Component string `json:"component"`
		NodeName  string `json:"node_name"`
		Domain    string `json:"domain"`
		Method    string `json:"method"`
		Path      string `json:"path"`
		Status    int    `json:"status"`
		IP        string `json:"ip"`
		LatencyMs int64  `json:"latency_ms"`
		Bytes     int64  `json:"bytes"`
		Message   string `json:"message"`
		Referrer  string `json:"referrer"`
	}
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, "JSON invalide", http.StatusBadRequest)
		return
	}
	for _, item := range batch {
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
			Component: nvlStr(item.Component, "agent"),
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
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleInternalBans(w http.ResponseWriter, r *http.Request) {
	var batch []struct {
		IP        string `json:"ip"`
		Domain    string `json:"domain"`
		Reason    string `json:"reason"`
		Source    string `json:"source"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, "JSON invalide", http.StatusBadRequest)
		return
	}
	for _, b := range batch {
		src := b.Source
		if src == "" {
			src = "agent"
		}
		var exp any
		if b.ExpiresAt != "" {
			exp = b.ExpiresAt
		}
		s.db.Exec( //nolint:errcheck
			`INSERT OR IGNORE INTO security_bans (id, ip, domain, reason, source, expires_at) VALUES (?,?,?,?,?,?)`,
			fmt.Sprintf("%s-%s-%s", b.IP, b.Domain, b.Source), b.IP, b.Domain, b.Reason, src, exp,
		)
	}
	if s.wsManager != nil {
		go s.wsManager.PushBans(context.Background())
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleInternalThreats(w http.ResponseWriter, r *http.Request) {
	var batch []struct {
		IP       string `json:"ip"`
		Scenario string `json:"scenario"`
		Origin   string `json:"origin"`
		Type     string `json:"type"`
		Duration string `json:"duration"`
	}
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, "JSON invalide", http.StatusBadRequest)
		return
	}
	changed := false
	for _, t := range batch {
		if t.IP == "" {
			continue
		}
		typ := nvlStr(t.Type, "ban")
		res, err := s.db.Exec(
			`INSERT OR IGNORE INTO security_threats (ip, scenario, origin, type, duration) VALUES (?,?,?,?,?)`,
			t.IP, t.Scenario, t.Origin, typ, t.Duration,
		)
		if err != nil {
			continue
		}
		if rows, _ := res.RowsAffected(); rows > 0 {
			changed = true
		}
		if strings.EqualFold(typ, "ban") {
			id := "crowdsec:" + t.IP
			reason := t.Scenario
			if reason == "" {
				reason = "CrowdSec ban"
			}
			var expires any
			if d := strings.TrimSpace(t.Duration); d != "" && d != "-1" && d != "0" {
				if parsed, err := time.ParseDuration(d); err == nil && parsed > 0 {
					expires = time.Now().Add(parsed).UTC().Format(time.RFC3339)
				}
			}
			if _, err := s.db.Exec(
				`INSERT OR REPLACE INTO security_bans (id, ip, domain, reason, source, expires_at) VALUES (?,?,?,?,?,?)`,
				id, t.IP, "", reason, "crowdsec", expires,
			); err == nil {
				changed = true
			}
		}
	}
	if changed && s.wsManager != nil {
		go s.wsManager.PushBans(context.Background())
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleInternalCVEs(w http.ResponseWriter, r *http.Request) {
	var batch []struct {
		BackendURL  string  `json:"backend_url"`
		CVEID       string  `json:"cve_id"`
		CVSSScore   float64 `json:"cvss_score"`
		Description string  `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, "JSON invalide", http.StatusBadRequest)
		return
	}
	for _, c := range batch {
		s.db.Exec( //nolint:errcheck
			`INSERT OR IGNORE INTO security_cves (backend_url, cve_id, cvss_score, description) VALUES (?,?,?,?)`,
			c.BackendURL, c.CVEID, c.CVSSScore, c.Description,
		)
	}
	w.WriteHeader(http.StatusAccepted)
}

func nvlStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// --- Routes pour les Cores -----------------------------------------------

// handlePair traite la première connexion d'un nœud (Core ou Agent) via le pairing_secret.
// Flux : secret validé → nœud mis en état PENDING → Admin accepte → auth_token émis.
// Un nœud déjà accepté (token actif en DB) reçoit son token directement (reconnexion).
// Endpoint public : POST /internal/v1/pair
func (s *Server) handlePair(w http.ResponseWriter, r *http.Request) {
	configuredSecret := os.Getenv("GPX_PAIRING_SECRET")

	var req struct {
		Secret   string `json:"secret"`
		NodeName string `json:"node_name"`
		Role     string `json:"role"`
		Version  string `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "corps JSON invalide", http.StatusBadRequest)
		return
	}
	if configuredSecret == "" {
		http.Error(w, "pairing non configuré", http.StatusServiceUnavailable)
		return
	}
	if !auth.SecureEqual(configuredSecret, req.Secret) {
		http.Error(w, "secret invalide", http.StatusForbidden)
		return
	}

	role := req.Role
	if role != "core" && role != "agent" {
		role = "core"
	}
	nodeName := req.NodeName
	if nodeName == "" {
		if role == "agent" {
			nodeName = "agent-1"
		} else {
			nodeName = "core-1"
		}
	}

	// Reconnexion : token actif déjà en DB (nœud précédemment accepté) → retour immédiat.
	var existing string
	_ = s.db.QueryRowContext(r.Context(),
		`SELECT token FROM tokens WHERE role=? AND node_name=? AND revoked=0 LIMIT 1`,
		role, nodeName,
	).Scan(&existing)
	if existing != "" {
		if plain, err := auth.OpenNodeToken(existing); err == nil {
			existing = plain
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted", "token": existing})
		return
	}

	// Auto-acceptation des Cores : le pairing secret valide suffit — pas de validation manuelle.
	// Le Core est déployé par le même opérateur que l'Admin (même docker-compose / infra maîtrisée).
	// Sans cela, une DB Admin fraîche (volume recréé, restart) force l'opérateur à ré-accepter
	// manuellement à chaque fois, même si le Core n'a pas changé.
	// Agents déclarés via wizard architecture (auto_accept) : même traitement.
	if configuredSecret != "" && (role == "core" || api.NodeAutoAccept(s.db, nodeName)) {
		tok := auth.GenerateToken(role, nodeName)
		tokenID := uuid.New().String()
		stored, hash := auth.PrepareNodeTokenForStore(tok)
		if _, err := s.db.ExecContext(r.Context(),
			`INSERT INTO tokens (id, token, token_hash, role, rbac_role, node_name) VALUES (?, ?, ?, ?, 'admin', ?)`,
			tokenID, stored, hash, role, nodeName,
		); err != nil {
			s.log.Error("pair: auto-accept", "err", err, "role", role, "node", nodeName)
			http.Error(w, "erreur interne", http.StatusInternalServerError)
			return
		}
		// Nettoyer un éventuel pending résiduel.
		_, _ = s.db.ExecContext(r.Context(),
			`UPDATE pending_nodes SET status='accepted', token=? WHERE node_name=? AND role=? AND status='pending'`,
			tok, nodeName, role,
		)
		s.log.Info("pair: nœud auto-accepté", "role", role, "node", nodeName)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted", "token": tok})
		return
	}

	// Nœud déjà accepté mais en attente de récupération du token.
	var pendingStatus, pendingToken, pendingID string
	_ = s.db.QueryRowContext(r.Context(),
		`SELECT id, status, token FROM pending_nodes WHERE node_name=? AND role=?`,
		nodeName, role,
	).Scan(&pendingID, &pendingStatus, &pendingToken)

	if pendingStatus == "accepted" && pendingToken != "" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted", "token": pendingToken})
		return
	}
	if pendingStatus == "rejected" {
		http.Error(w, "connexion refusée par l'administrateur", http.StatusForbidden)
		return
	}

	// Première demande : créer l'entrée pending (idempotent via UNIQUE index).
	if pendingID == "" {
		pendingID = uuid.New().String()
		if _, err := s.db.ExecContext(r.Context(),
			`INSERT OR IGNORE INTO pending_nodes (id, node_name, role, version, remote_addr)
			 VALUES (?, ?, ?, ?, ?)`,
			pendingID, nodeName, role, req.Version, r.RemoteAddr,
		); err != nil {
			s.log.Error("pair: insertion pending_node", "err", err)
			http.Error(w, "erreur interne", http.StatusInternalServerError)
			return
		}
		// Re-lire l'ID au cas où un autre goroutine a inséré en parallèle.
		_ = s.db.QueryRowContext(r.Context(),
			`SELECT id FROM pending_nodes WHERE node_name=? AND role=?`, nodeName, role,
		).Scan(&pendingID)
		s.log.Info("pair: nœud en attente d'acceptation", "role", role, "node", nodeName, "pending_id", pendingID)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending", "pending_id": pendingID})
}

// handlePairStatus permet à un nœud de vérifier si son entrée pending a été acceptée.
// Endpoint public : GET /internal/v1/pair/status?pending_id=...
func (s *Server) handlePairStatus(w http.ResponseWriter, r *http.Request) {
	pendingID := r.URL.Query().Get("pending_id")
	if pendingID == "" {
		http.Error(w, "pending_id requis", http.StatusBadRequest)
		return
	}

	var status, token string
	err := s.db.QueryRowContext(r.Context(),
		`SELECT status, token FROM pending_nodes WHERE id=?`, pendingID,
	).Scan(&status, &token)
	if err != nil {
		// Entrée introuvable : expirée ou jamais créée.
		http.Error(w, "demande introuvable", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	switch status {
	case "accepted":
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "accepted", "token": token})
	case "rejected":
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "rejected"})
	default:
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
	}
}

func (s *Server) handleCoreRoutes(w http.ResponseWriter, r *http.Request) {
	// Identifie le token pour appliquer le filtre RBAC + délégations.
	bearerToken := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	tokenID, rbacRole := rbac.TokenRBACRole(r.Context(), s.db, bearerToken)

	rows, err := s.db.QueryContext(r.Context(),
		`SELECT config FROM proxies WHERE enabled=1`)
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var allRoutes []router.Route
	for rows.Next() {
		var cfg string
		if err := rows.Scan(&cfg); err != nil {
			continue
		}
		var route router.Route
		if err := json.Unmarshal([]byte(cfg), &route); err == nil {
			allRoutes = append(allRoutes, route)
		}
	}

	var nodeName string
	_ = s.db.QueryRowContext(r.Context(),
		`SELECT COALESCE(node_name,'') FROM tokens WHERE id=?`, tokenID).Scan(&nodeName)
	acc := rbac.LoadCoreAccess(r.Context(), s.db, tokenID, nodeName)
	if acc.Role != "" {
		rbacRole = acc.Role
	}

	var filtered []router.Route
	if s.wsManager != nil {
		filtered = s.wsManager.FilterRoutesForCore(r.Context(), tokenID, nodeName, rbacRole, acc.Scopes, allRoutes)
	} else {
		filtered = rbac.FilterRoutesByScopes(rbacRole, acc.Scopes, allRoutes)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(filtered) //nolint:errcheck
}

// handleCoreRegister met à jour l'endpoint d'un Core dans la table tokens
// et enregistre/met à jour le client WS Admin→Core dans le Manager.
func (s *Server) handleCoreRegister(mgr *corews.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Endpoint     string `json:"endpoint"`
			RaftEndpoint string `json:"raft_endpoint"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Endpoint == "" {
			http.Error(w, "endpoint requis", http.StatusBadRequest)
			return
		}

		// Identifie le token depuis l'en-tête Authorization.
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

		// Si l'endpoint fourni contient une IP Docker interne (172.x.x.x),
		// la remplacer par l'IP source de la requête afin qu'Admin puisse
		// joindre le Core cross-machine (Docker bridge → host NAT).
		if u, err := url.Parse(req.Endpoint); err == nil {
			host := u.Hostname()
			if ip := net.ParseIP(host); ip != nil {
				_, docker172, _ := net.ParseCIDR("172.16.0.0/12")
				if docker172.Contains(ip) {
					if srcIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
						u.Host = net.JoinHostPort(srcIP, u.Port())
						req.Endpoint = u.String()
					}
				}
			}
		}

		res, err := s.db.ExecContext(r.Context(),
			`UPDATE tokens SET node_endpoint=?, raft_endpoint=? WHERE token=? AND role='core' AND revoked=0`,
			req.Endpoint, req.RaftEndpoint, token,
		)
		if err != nil {
			s.log.Error("core register: update endpoint", "err", err)
			http.Error(w, "erreur interne", http.StatusInternalServerError)
			return
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			http.Error(w, "token introuvable ou révoqué", http.StatusNotFound)
			return
		}

		// Récupérer l'ID et le nom du Core pour l'enregistrement dans le Manager.
		var coreID, nodeName, rbacRole string
		_ = s.db.QueryRowContext(r.Context(),
			`SELECT id, COALESCE(node_name,''), COALESCE(rbac_role,'admin')
			 FROM tokens WHERE token=? AND role='core' AND revoked=0`,
			token,
		).Scan(&coreID, &nodeName, &rbacRole)

		s.log.Info("core enregistré", "endpoint", req.Endpoint, "node", nodeName)

		// Enregistrer/mettre à jour le client WS Admin→Core.
		// La connexion WS + le full_sync sont déclenchés automatiquement dans Register.
		settings := s.runtimeSettings()
		mgr.SetSettings(settings)
		if coreID != "" {
			mgr.Register(coreID, nodeName, req.Endpoint, rbacRole)
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleNodeMetrics(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.QueryContext(r.Context(),
		`SELECT endpoint, COALESCE(cpu_pct,0), COALESCE(mem_pct,0) FROM nodes WHERE status='online'`)
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type nodeMetric struct {
		Endpoint string  `json:"endpoint"`
		CPUPCT   float64 `json:"cpu_pct"`
		MemPCT   float64 `json:"mem_pct"`
	}
	result := make([]nodeMetric, 0)
	for rows.Next() {
		var m nodeMetric
		if err := rows.Scan(&m.Endpoint, &m.CPUPCT, &m.MemPCT); err != nil {
			continue
		}
		result = append(result, m)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result) //nolint:errcheck
}

// --- Middleware & helpers -------------------------------------------------

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.status = code
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	n, err := sw.ResponseWriter.Write(b)
	sw.bytes += int64(n)
	return n, err
}

func (sw *statusWriter) Flush() {
	if f, ok := sw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)

		if strings.HasPrefix(r.URL.Path, "/api/v1/health") ||
			strings.HasPrefix(r.URL.Path, "/api/v1/logs/live") ||
			strings.HasPrefix(r.URL.Path, "/internal/v1/") {
			return
		}
		latency := time.Since(start).Milliseconds()
		level := "info"
		if sw.status >= 500 {
			level = "error"
		} else if sw.status >= 400 {
			level = "warn"
		}
		ip := r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip = r.RemoteAddr
		}
		s.logStore.Write(logs.Entry{
			Level:     level,
			Component: "admin",
			Domain:    r.Host,
			Method:    r.Method,
			Path:      r.URL.Path,
			Status:    sw.status,
			IP:        ip,
			LatencyMs: latency,
			Bytes:     sw.bytes,
			Referrer:  r.Header.Get("Referer"),
		})
	})
}

// runtimeSettings construit les settings runtime poussés aux Cores.
func (s *Server) runtimeSettings() corews.Settings {
	return corews.Settings{
		TracingEndpoint: s.cfg.App.TracingEndpoint,
		LogLevel:        s.cfg.CoreDefaults.LogLevel,
		LogFormat:       s.cfg.CoreDefaults.LogFormat,
		AccessLogPath:   s.cfg.CoreDefaults.AccessLogPath,
		AdminPublicURL:  s.resolveAdminPublicURL(),
	}
}

// resolveAdminPublicURL retourne l'origine publique de l'Admin (env > settings > webauthn).
func (s *Server) resolveAdminPublicURL() string {
	if u := strings.TrimRight(strings.TrimSpace(os.Getenv("GPX_ADMIN_PUBLIC_URL")), "/"); u != "" {
		return u
	}
	if u := strings.TrimRight(admindb.GetSetting(s.db, "admin.public_url", ""), "/"); u != "" {
		return u
	}
	return strings.TrimRight(admindb.GetSetting(s.db, "mfa.webauthn.origin", ""), "/")
}

// publicOriginFromRequest déduit http(s)://host depuis la requête navigateur.
func publicOriginFromRequest(r *http.Request) string {
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = strings.TrimSpace(r.Host)
	}
	if host == "" {
		return ""
	}
	proto := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	origin := proto + "://" + host
	if _, err := url.ParseRequestURI(origin); err != nil {
		return ""
	}
	return strings.TrimRight(origin, "/")
}

// maybeRememberPublicURL mémorise l'origine vue par le navigateur et la pousse aux Cores.
// Ignoré si GPX_ADMIN_PUBLIC_URL est défini (override explicite).
func (s *Server) maybeRememberPublicURL(r *http.Request) {
	if os.Getenv("GPX_ADMIN_PUBLIC_URL") != "" {
		return
	}
	origin := publicOriginFromRequest(r)
	if origin == "" {
		return
	}
	cur := strings.TrimRight(admindb.GetSetting(s.db, "admin.public_url", ""), "/")
	if cur == origin {
		return
	}
	if err := admindb.SetSetting(s.db, "admin.public_url", origin); err != nil {
		s.log.Debug("admin.public_url: persistance échouée", "err", err)
		return
	}
	s.log.Info("admin.public_url mémorisée depuis la session UI", "url", origin)
	if s.wsManager != nil {
		settings := s.runtimeSettings()
		s.wsManager.PushSettings(context.Background(), settings)
	}
}

func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

type notFoundError struct{ email string }

func (e *notFoundError) Error() string { return "utilisateur introuvable : " + e.email }
