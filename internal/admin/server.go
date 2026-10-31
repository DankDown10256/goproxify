// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package admin implémente le Control Plane — API REST, auth, SQLite, gestion des routes.
package admin

import (
	"github.com/vincamok/goproxify/internal/launcher"
	"github.com/vincamok/goproxify/internal/pairing"
	"github.com/vincamok/goproxify/internal/httpx"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
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
	"github.com/vincamok/goproxify/internal/admin/asn"
	"github.com/vincamok/goproxify/internal/admin/audit"
	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/automation"
	autometrics "github.com/vincamok/goproxify/internal/admin/automation/metrics"
	"github.com/vincamok/goproxify/internal/admin/backup"
	"github.com/vincamok/goproxify/internal/admin/certdeploy"
	"github.com/vincamok/goproxify/internal/admin/crowdsec"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/edgelogs"
	"github.com/vincamok/goproxify/internal/admin/edgews"
	"github.com/vincamok/goproxify/internal/admin/fail2ban"
	"github.com/vincamok/goproxify/internal/admin/gdpr"
	"github.com/vincamok/goproxify/internal/admin/ha"
	"github.com/vincamok/goproxify/internal/admin/internalca"
	"github.com/vincamok/goproxify/internal/admin/ipprofile"
	"github.com/vincamok/goproxify/internal/admin/logs"
	"github.com/vincamok/goproxify/internal/admin/mcp"
	"github.com/vincamok/goproxify/internal/admin/mfa"
	"github.com/vincamok/goproxify/internal/admin/monitor"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/admin/security"
	"github.com/vincamok/goproxify/internal/admin/setup"
	"github.com/vincamok/goproxify/internal/admin/ui"
	"github.com/vincamok/goproxify/internal/admin/vulnscan"
	"github.com/vincamok/goproxify/internal/buildinfo"
	"github.com/vincamok/goproxify/internal/config"
	"github.com/vincamok/goproxify/internal/edge/geoip"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
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
	automation     *automation.Service
	logStore       *logs.Store
	logKey         []byte           // clé de pseudonymisation de l'Admin, aussi celle du volume de logs
	logVault       *edgelogs.Vault  // volume de logs de l'Admin (ADR 0018) ; nil sans dossier
	wsManager      *edgews.Manager // manager WS Admin→Passerelle
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
	// Clé de pseudonymisation RGPD : sans elle, l'IP réelle reçue est simplement ignorée
	// (l'IP tronquée par la passerelle est conservée), d'où une erreur non fatale.
	gdprKey, gdprErr := gdpr.EnsureKey(db)
	logStore.SetGDPRKey(gdprKey)
	logStore.SetPseudonymize(admindb.GetSetting(db, "logs.ip_pseudonymize", "false") == "true")
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
	if gdprErr != nil {
		log.Warn("rgpd: clé de pseudonymisation indisponible", "err", gdprErr)
	}
	applyMemoryLimit(log, os.ReadFile)

	s := &Server{
		cfg:            cfg,
		db:             db,
		log:            log,
		auditor:        audit.New(db, cfg.App.AuditRetentionDays),
		alertingEngine: alerting.New(db, log),
		logStore:       logStore,
		logKey:         gdprKey,
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

	// Manager WS Admin→Passerelle — HMAC partagé via GPX_PAIRING_SECRET
	hmacSecret := pairing.Secret("GPX_PAIRING_SECRET")
	manager := edgews.NewManager(hmacSecret, s.db, s.log)
	manager.SetRootKeys(pairing.RootKeys)
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
	if archStore != nil {
		groups := api.NewGroupResolver(archStore, s.db)
		api.MigrateGroupSettings(ctx, s.db, groups, s.log)
		api.MigratePortalGroups(ctx, s.db, groups, s.log)
		// Un membre qui quitte un groupe fait renouveler la clé du groupe ; la liste des membres est repoussée à tous.
		cards := &api.GroupCardSync{DB: s.db, Arch: archStore, Groups: groups, Pusher: manager, Log: s.log}
		manager.SetGroupCards(cards)
		go (&api.GroupMembership{DB: s.db, Groups: groups, Pusher: manager, Cards: cards, Tokens: manager, Log: s.log}).Run(ctx, 30*time.Second)
	}
	agentStore := api.NewAgentStore()
	manager.SetAgentPendingHandler(func(id, name, version string) {
		agentStore.Upsert(id, name, version, "pending")
		if api.NodeAutoAccept(s.db, name) || api.NodeAutoAccept(s.db, id) {
			manager.BroadcastApproveAgent(id)
			if name != "" && name != id {
				manager.BroadcastApproveAgent(name)
			}
			agentStore.Upsert(id, name, version, "approved")
			// Un Agent n'arrive pas par /internal/v1/pair : c'est ici que le ticket qui le couvre est consommé.
			api.ConsumeBootstrapTicket(s.db, name)
			s.log.Info("pair: Agent auto-accepté (declared/bootstrap)", "id", id, "name", name)
		}
	})
	// Une passerelle ne s'enrôle pas, l'Admin la joint : sa première connexion consomme le ticket qui la couvre.
	manager.SetEdgeConnectedHandler(func(nodeName string) { api.ConsumeBootstrapTicket(s.db, nodeName) })
	manager.SetLogBatchHandler(func(entries []edgeWS.LogEntryPayload) {
		batch := make([]logs.Entry, 0, len(entries))
		for _, item := range entries {
			batch = append(batch, edgews.LogEntryFromPayload(item))
		}
		// Une transaction par lot et non par entrée : voir logs.Store.WriteBatch.
		s.logStore.WriteBatch(batch)
	})
	// Lots numérotés lus dans la base de logs des passerelles : la position de chacune est enregistrée avec ses
	// lignes et annoncée à sa reconnexion, ce qui comble une coupure de l'Admin (ADR 0012).
	manager.SetLogStreamIngestor(s.newLogIngestor(manager.AnnouncedLast))

	backupSched := backup.New(s.db, s.log)
	if s.cfg.Storage.BasePath != "" {
		backupSched.SetSnapDir(filepath.Join(s.cfg.Storage.BasePath, "backups"))
		backupSched.SetExtraFiles(s.backupConfigFiles, filepath.Join(s.cfg.Storage.BasePath, "restored-config"))
		backupSched.SetSecretDirs(map[string]string{
			"state": filepath.Join(s.cfg.Storage.BasePath, "state"),
			"certs": filepath.Join(s.cfg.Storage.BasePath, "certs"),
		})
	}
	backupSched.SetNotifier(func(severity, title string, detail map[string]any) {
		if s.alertingEngine == nil {
			return
		}
		sev := alerting.SevCritical
		if severity == "warning" {
			sev = alerting.SevWarning
		}
		detail["title"] = title
		s.alertingEngine.Emit(alerting.Event{Trigger: alerting.TriggerBackupFailed, Severity: sev, Component: "admin", Detail: detail})
	})
	proxiesH := &api.ProxiesHandler{DB: s.db, Log: s.log, Pusher: manager, Versioner: backupSched}
	backupH := &api.BackupHandler{
		DB: s.db, Log: s.log, Scheduler: backupSched, Pusher: manager, Auditor: s.auditor,
		LauncherImage: launcher.Env{Registry: os.Getenv("GPX_DEPLOY_REGISTRY"), Tag: os.Getenv("GPX_DEPLOY_TAG")}.Image("launcher"),
	}
	if s.cfg.Storage.BasePath != "" {
		backupH.Keys = backup.NewKeyStore(filepath.Join(s.cfg.Storage.BasePath, "keys"))
	}
	tokensH := &api.TokensHandler{
		DB: s.db, Log: s.log, Edges: manager, Pusher: manager,
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
	pluginsH := &api.PluginsHandler{DB: s.db, Log: s.log, Pusher: manager}
	authProvidersH := &api.AuthProvidersHandler{DB: s.db, Log: s.log, OnChange: syncConfig}
	portalH := &api.PortalHandler{DB: s.db, Log: s.log, Pusher: manager}
	if archStore != nil {
		portalH.Groups = api.NewGroupResolver(archStore, s.db)
	}
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
	acmeProviderStore := acme.NewProviderStore(filepath.Join(s.cfg.Storage.BasePath, "state", "acme-providers.yaml"))
	buildACMEManager := func(email, directoryURL, dnsType string) *acme.Manager {
		if !s.cfg.ACME.Enabled && email == "" {
			return nil
		}
		var provider acme.DNSProvider
		if dnsType != "" {
			provCfg := acme.DefaultProviderConfig(dnsType, s.cfg.ACME.DNS.Params, acmeProviderStore)
			if p, err := acme.NewProvider(provCfg); err != nil {
				s.log.Warn("acme: fournisseur DNS indisponible", "err", err)
			} else {
				provider = p
			}
		}
		mgr := acme.New(s.db, s.log, manager, provider, email)
		mgr.DirectoryURL = directoryURL
		mgr.Providers = acmeProviderStore
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
	certDeployer := certdeploy.New(s.db, s.log)
	certDeployer.OnDeployFail = func(targetID, domain, typ, message string) {
		s.alertingEngine.Emit(alerting.Event{
			Trigger:  alerting.TriggerCertDeployFailed,
			Severity: alerting.SevWarning,
			Domain:   domain,
			Detail:   map[string]any{"target_id": targetID, "type": typ, "message": message},
		})
	}
	certDeployH := &api.CertDeployHandler{DB: s.db, Log: s.log, Deployer: certDeployer}
	certBundleH := &api.CertBundleHandler{DB: s.db, Log: s.log}

	if acmeMgr != nil {
		acmeMgr.OnCertObtained = func(ctx context.Context, certID string) {
			certDeployer.TriggerForCert(ctx, certID)
		}
		acmeMgr.OnCertExpiring = func(_ context.Context, domain string, daysLeft int) {
			sev := alerting.SevWarning
			if daysLeft <= 7 {
				sev = alerting.SevCritical
			}
			s.alertingEngine.Emit(alerting.Event{
				Trigger:  alerting.TriggerCertExpiringSoon,
				Severity: sev,
				Domain:   domain,
				Detail:   map[string]any{"days_left": daysLeft},
			})
		}
	}

	certsH := &api.CertsHandler{DB: s.db, Log: s.log, Manager: acmeMgr, Pusher: manager}
	internalCAMgr := internalca.New(s.db, s.log)
	if s.cfg.Storage.BasePath != "" {
		internalCAMgr.SetCertDir(filepath.Join(s.cfg.Storage.BasePath, "certs"))
	}
	internalCAH := &api.InternalCAHandler{Log: s.log, Manager: internalCAMgr}
	nodesH := &api.NodesHandler{DB: s.db, Log: s.log, Traffic: manager.RecentTraffic, RevokeStaleAdminTokens: manager.RevokeStaleAdminTokens, RotateEdgeToken: manager.RotateEdgeToken, OnTunnelSave: func(nodeID string) {
		ctx := context.Background()
		s.wsManager.PushTunnelConfig(ctx, nodeID)
	}}
	autoConfigurer := &api.AgentAutoConfigurer{DB: s.db, Log: s.log, Nodes: nodesH}
	go autoConfigurer.Start(ctx)
	declaredNodesH := &api.DeclaredNodesHandler{DB: s.db, Log: s.log, EdgeNodeName: s.cfg.Identity.EdgeNodeName, Scheduler: backupSched, ArchStore: archStore}
	architectureH := &api.ArchitectureHandler{DB: s.db, Log: s.log, Store: archStore, OnRestore: func() {
		if manager != nil {
			go manager.ReloadArchitecture(context.Background())
		}
	}, FetchCards: func(ctx context.Context, edges []string) ([]edgeWS.GroupCard, []string) {
		return fetchGroupCards(ctx, s.db, edges)
	}}
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
	hostsH := &api.HostsHandler{
		DB: s.db, Arch: archStore, Nodes: nodesH, Log: s.log,
		PublicURL: bootstrapH.ResolvePublicURL,
		Root:      func() string { return pairing.Secret("GPX_PAIRING_SECRET") },
		CertFile:  func() string { return os.Getenv("GPX_ADMIN_TLS_CERT") },
		Registry:  os.Getenv("GPX_DEPLOY_REGISTRY"), Tag: os.Getenv("GPX_DEPLOY_TAG"), TZ: os.Getenv("TZ"),
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
	logsH := &api.LogsHandler{Log: s.log, Store: s.logStore, DB: s.db, Pusher: manager, Live: manager, SIEM: manager, Retention: manager}
	if s.logVault != nil {
		logsH.EraseCopy = s.logVault.EraseIP
		logsH.OnVaultRetention = s.applyVaultRetention
	}
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
	pushUnban := func(ip string) {
		if manager != nil {
			go manager.PushUnban(context.Background(), []string{ip})
		}
	}
	logsH.OnUnban = pushUnban
	pushUnbanMany := func(ips []string) {
		if manager != nil {
			go manager.PushUnban(context.Background(), ips)
		}
	}
	asnStore := asn.NewStore(asnDBPath(s.cfg.Storage.BasePath), os.Getenv("GPX_ASN_DB_URL"), s.log)
	if manager != nil {
		manager.SetASNSource(asnStore.Compact)
	}
	// Les profils IP (dont la liste blanche des bans) ne partaient vers les passerelles qu'à leur
	// connexion : un changement depuis l'Admin n'était appliqué qu'à la reconnexion suivante.
	pushASN := func() {
		if manager != nil {
			go manager.OfferASN(context.Background())
		}
	}
	pushIPProfiles := func() {
		if manager != nil {
			go manager.PushIPProfiles(context.Background())
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
	prismSrc := &prismedge.Source{DB: s.db}
	securityH := &api.SecurityHandler{
		Proxies:      proxiesH,
		DB:           s.db,
		Edge:         prismSrc,
		Log:          s.log,
		Store:        security.New(s.db),
		Fail2Ban:     f2bEngine,
		VulnScan:     vsScanner,
		CrowdSec:     csBouncer,
		ScanCtx:      ctx,
		OnBansChange: pushBans,
		OnUnban:      pushUnban,
		OnUnbanMany:  pushUnbanMany,
		ASN:          asnStore,
		OnASNChange:  pushASN,
		OnWhitelistChange: pushIPProfiles,
		OnThreatConfigChange: func(scope string, cfg any) {
			if manager != nil {
				go manager.PushThreatConfig(context.Background(), scope, cfg)
			}
		},
		OnWAFConfigChange: func(scope string, cfg any) {
			if manager != nil {
				go manager.PushWAFConfig(context.Background(), scope, cfg)
			}
		},
		OnServerConfigChange: func(scope string, cfg any) {
			if manager != nil {
				go manager.PushServerConfig(context.Background(), scope, cfg)
			}
		},
	}
	if archStore != nil {
		securityH.Groups = api.NewGroupResolver(archStore, s.db)
	}
	// Flux d'automatisation (règles, planifications, playbooks) : un seul moteur.
	// Les métriques relevées sur les passerelles alimentent la condition metric_threshold.
	proxyMetricsH := api.NewProxyMetricsSampler(s.db, s.log)
	go proxyMetricsH.Run(ctx)
	metricStore := autometrics.New(api.AutomationMetrics,
		func() []autometrics.Sample { return toSamples(proxyMetricsH.AutomationSamples()) },
		func() []autometrics.Sample { return toSamples(api.AdminMetricSamples()) })
	go metricStore.Run(ctx.Done())
	var isLeader func() bool
	if s.haManager != nil {
		isLeader = s.haManager.IsLeader
	}
	autoSvc := automation.New(s.db, s.log, automation.Deps{
		DisableProxy: func(ctx context.Context, proxyID string) error {
			res, err := s.db.ExecContext(ctx,
				`UPDATE proxies SET enabled=0, updated_at=CURRENT_TIMESTAMP WHERE id=?`, proxyID)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return fmt.Errorf("proxy %q introuvable", proxyID)
			}
			if manager != nil {
				go manager.PushRoutes(context.Background())
			}
			return nil
		},
		CreateBan: func(ctx context.Context, ip, reason string, durationSec int) error {
			var expiresAt any
			if durationSec > 0 {
				expiresAt = time.Now().Add(time.Duration(durationSec) * time.Second).UTC().Format(time.RFC3339)
			}
			_, err := s.db.ExecContext(ctx,
				`INSERT OR IGNORE INTO security_bans (ip, reason, source, expires_at) VALUES (?,?,?,?)`,
				ip, reason, "automation", expiresAt)
			if err == nil {
				pushBans()
			}
			return err
		},
		Emit: func(ev alerting.Event) {
			if s.alertingEngine != nil {
				s.alertingEngine.Emit(ev)
			}
		},
		F2BLastActivity:  f2bEngine.LastActivity,
		CrowdSecLastSync: csBouncer.LastSync,
		RunBackup: func(_ context.Context, name string, retention int) error {
			return backupSched.TakeSnapshot(name, "", retention)
		},
		Metrics: metricStore,
	}, automation.Options{
		IsLeader:          isLeader,
		OnEdgeRulesChange: func() { go manager.PushAutoRules(context.Background()) },
	})
	if s.alertingEngine != nil {
		s.alertingEngine.Subscribe(autoSvc.OnEvent)
	}
	manager.SetAutomation(autoSvc)
	autoSvc.Start()
	s.automation = autoSvc
	automationH := &api.AutomationHandler{Svc: autoSvc}
	importH := &api.ImportHandler{DB: s.db, Log: s.log, Scheduler: backupSched}
	prismH := &api.PrismHandler{DB: s.db, Edge: prismSrc}
	ipUpdater := ipprofile.New(s.db, s.log)
	ipUpdater.OnRefreshFail = func(id, name string, failures int, cause error, lastUpdatedAt string) {
		s.alertingEngine.Emit(alerting.Event{
			Trigger:   alerting.TriggerIPProfileRefreshFailed,
			Severity:  alerting.SevWarning,
			Component: "admin",
			Detail: map[string]any{
				"profile_id": id, "profile": name, "consecutive_failures": failures,
				"error": cause.Error(), "last_updated_at": lastUpdatedAt,
			},
		})
	}
	ipProfilesH := &api.IPProfilesHandler{DB: s.db, Log: s.log, Updater: ipUpdater, OnChange: func() {
		syncConfig()
		pushIPProfiles()
	}}
	syncArch := func() {
		if archStore != nil {
			go archStore.SyncDomainsFromDB(context.Background(), s.db) //nolint:errcheck
		}
	}
	teamsH := &api.TeamsHandler{DB: s.db, Log: s.log, OnChange: syncUsers}
	workspacesH := &api.WorkspacesHandler{DB: s.db, Log: s.log}
	discoveredH := &api.DiscoveredContainersHandler{DB: s.db, Log: s.log, Pusher: manager}
	if archStore != nil {
		discoveredH.Groups = api.NewGroupResolver(archStore, s.db)
	}
	backendsHealthH := &api.BackendsHealthHandler{DB: s.db, Log: s.log}
	domainsH := &api.DomainsHandler{DB: s.db, Log: s.log, Pusher: manager, OnChange: syncArch}
	if archStore != nil {
		domainsH.Groups = api.NewGroupResolver(archStore, s.db)
	}
	agentsH := &api.AgentsHandler{
		Log:   s.log,
		Store: agentStore,
		OnApprove: func(agentID string) {
			// Broadcaster approve_agent à toutes les passerelles — la passerelle qui a l'Agent le traitera
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

	geoResolver := &analytics.GeoResolver{DB: s.db, Log: s.log, MMDBPath: s.cfg.GeoIP.CityDBPath, AllowExternal: s.cfg.GeoIP.AllowExternalLookup}
	prismSrc.Geo = geoResolver
	if s.cfg.GeoIP.AutoDownload && s.cfg.GeoIP.CityDBPath != "" {
		// Téléchargement en arrière-plan (plusieurs dizaines de Mo) : d'ici là, ip-api.com sert de repli.
		go func() {
			if err := geoip.Ensure(s.cfg.GeoIP.CityDBPath, s.cfg.GeoIP.CityDBURL, s.log); err != nil {
				s.log.Warn("geoip: base GeoLite2-City indisponible", "err", err)
			}
		}()
	}
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

	admindb.StartMaintenance(ctx, s.db, s.log)

	// Rétention des logs RGPD (lit logs.retention_access_days / logs.retention_system_days dans settings).
	s.logStore.StartRetentionLoop(ctx, func() (accessDays, systemDays, banDays int) {
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
			parseInt("logs.retention_system_days", logs.DefaultRetentionSystemDays),
			parseInt("logs.retention_ban_days", logs.DefaultRetentionBanDays)
	})
	go func() {
		n, err := s.logStore.BackfillIPIndex(ctx)
		if err != nil && !errors.Is(err, logs.ErrNoGDPRKey) && ctx.Err() == nil {
			s.log.Warn("rgpd: index d'effacement des IP pseudonymisées incomplet", "err", err, "done", n)
		} else if n > 0 {
			s.log.Info("rgpd: index d'effacement des IP pseudonymisées complété", "entries", n)
		}
	}()

	if s.haManager != nil {
		if err := s.haManager.Start(ctx); err != nil {
			s.log.Warn("ha: démarrage échoué (non bloquant)", "err", err)
		}
		mux.HandleFunc("GET /ha/status", s.haManager.HandleStatus)
	}

	// Fond de carte vectoriel auto-hébergé (PMTiles), avant la SPA qui répond à toute route.
	mux.Handle("GET "+basemapRoute, basemapHandler(basemapPath(s.cfg.Storage.BasePath)))

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

	meH := &api.MeHandler{DB: s.db, Log: s.log, OnChange: syncUsers, JWTSecret: jwtSecret}

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
	// Description d'un hôte qui rejoint (launcher) : le ticket de 15 minutes fait foi (ADR 0019).
	mux.HandleFunc("GET /api/v1/join/{token}", hostsH.ServeSpec)
	// Routes MFA publiques (challenge pendant le login)
	mux.HandleFunc("POST /api/v1/auth/mfa/challenge", mfaH.ServeHTTP)
	mux.HandleFunc("POST /api/v1/auth/mfa/send", mfaH.ServeHTTP)
	mux.HandleFunc("POST /api/v1/auth/mfa/webauthn/login/begin", mfaH.ServeHTTP)
	mux.HandleFunc("POST /api/v1/auth/mfa/webauthn/login/finish", mfaH.ServeHTTP)

	// Routes internes — passerelles et Agents (token d'appairage)
	mux.HandleFunc("POST /internal/v1/pair", s.handlePair)
	mux.HandleFunc("GET /internal/v1/pair/status", s.handlePairStatus)
	mux.Handle("POST /internal/v1/edges/register", auth.RequireBearerToken(s.db)(http.HandlerFunc(s.handleEdgeRegister(manager))))
	mux.Handle("GET /internal/v1/routes", auth.RequireBearerToken(s.db)(http.HandlerFunc(s.handleEdgeRoutes)))
	mux.Handle("GET /internal/v1/nodes/metrics", auth.RequireBearerToken(s.db)(http.HandlerFunc(s.handleNodeMetrics)))
	mux.Handle("/internal/v1/logs", auth.RequireBearerToken(s.db)(http.HandlerFunc(s.handleAgentLogs)))
	mux.Handle("/internal/v1/security/bans", auth.RequireBearerToken(s.db)(http.HandlerFunc(s.handleInternalBans)))
	mux.Handle("/internal/v1/security/threats", auth.RequireBearerToken(s.db)(http.HandlerFunc(s.handleInternalThreats)))
	mux.Handle("/internal/v1/security/cves", auth.RequireBearerToken(s.db)(http.HandlerFunc(s.handleInternalCVEs)))

	// Middleware d'accès : JWT session UI ou PAT utilisateur ; scopes PAT appliqués ensuite.
	// Les sessions UI (JWT) mémorisent l'origine publique pour les liens des pages d'erreur passerelle.
	protected := func(h http.Handler) http.Handler {
		return auth.RequireAuth(jwtSecret, s.db)(rbac.EnforcePATScope(s.db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if auth.AuthKindFromContext(r.Context()) == auth.AuthKindJWT {
				s.maybeRememberPublicURL(r)
			}
			h.ServeHTTP(w, r)
		})))
	}
	adminOnly := func(h http.Handler) http.Handler { return protected(rbac.RequireAdmin(s.db)(h)) }
	// Lecture pour tout authentifié ; mutations réservées admin (ou operator), JWT comme PAT.
	adminWrites := func(h http.Handler) http.Handler { return protected(rbac.RequireAdminForWrites(s.db)(h)) }
	operatorWrites := func(h http.Handler) http.Handler { return protected(rbac.RequireOperatorForWrites(s.db)(h)) }
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
	mux.Handle("/api/v1/workspaces", adminOnly(workspacesH))
	mux.Handle("/api/v1/workspaces/", adminOnly(workspacesH))
	mux.Handle("/api/v1/detector-types", operatorWrites(api.DetectorTypesHandler{}))
	mux.Handle("/api/v1/snippets", operatorWrites(snippetsH))
	mux.Handle("/api/v1/snippets/", operatorWrites(snippetsH))
	mux.Handle("/api/v1/error-page-templates", adminOnly(errorPagesH))
	mux.Handle("/api/v1/error-page-templates/", adminOnly(errorPagesH))
	mux.Handle("/api/v1/portal-page-templates", adminOnly(portalPagesH))
	mux.Handle("/api/v1/portal-page-templates/", adminOnly(portalPagesH))
	pluginReposH := &api.PluginReposHandler{DB: s.db, Log: s.log, Plugins: pluginsH}
	mux.Handle("/api/v1/plugin-repos", adminOnly(pluginReposH))
	mux.Handle("/api/v1/plugin-repos/", adminOnly(pluginReposH))
	mux.Handle("/api/v1/plugin-keys", adminOnly(&api.PluginKeysHandler{DB: s.db, Log: s.log}))
	mux.Handle("/api/v1/plugin-keys/", adminOnly(&api.PluginKeysHandler{DB: s.db, Log: s.log}))
	mux.Handle("/api/v1/plugins", adminOnly(pluginsH))
	mux.Handle("/api/v1/plugins/", adminOnly(pluginsH))
	mux.Handle("/api/v1/auth-provider-types", adminOnly(api.AuthProviderTypesHandler{}))
	mux.Handle("/api/v1/auth-providers", adminOnly(authProvidersH))
	mux.Handle("/api/v1/auth-providers/", adminOnly(authProvidersH))
	mux.Handle("/api/v1/portal", adminOnly(portalH))
	mux.Handle("/api/v1/portal/", adminOnly(portalH))
	mcpAccessH := &api.McpAccessHandler{DB: s.db, Log: s.log}
	mux.Handle("/api/v1/mcp-access/", adminOnly(mcpAccessH))
	mux.Handle("/api/v1/certs", adminWrites(certsH))
	mux.Handle("/api/v1/certs/", adminWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/certs/")
		parts := strings.SplitN(path, "/", 3)
		if len(parts) >= 2 && (parts[1] == "deploy-targets" || parts[1] == "pull-tokens") {
			certDeployH.ServeHTTP(w, r)
		} else {
			certsH.ServeHTTP(w, r)
		}
	})))
	mux.Handle("/api/v1/cert-bundle", http.HandlerFunc(certBundleH.ServeHTTP))
	mux.Handle("/api/v1/cert-deploy-types", adminWrites(api.CertDeployTypesHandler{}))
	mux.Handle("/api/v1/internal-ca", adminOnly(internalCAH))
	mux.Handle("/api/v1/internal-ca/", adminOnly(internalCAH))
	mux.Handle("/api/v1/nodes", protected(nodesH))
	mux.Handle("/api/v1/nodes/", protected(nodesH))
	mux.Handle("/api/v1/declared-nodes", adminWrites(declaredNodesH))
	mux.Handle("/api/v1/declared-nodes/", adminWrites(declaredNodesH))
	mux.Handle("/api/v1/architecture", adminOnly(architectureH))
	mux.Handle("GET /api/v1/architecture/groups", protected(architectureH))
	mux.Handle("/api/v1/architecture/", adminOnly(architectureH))
	mux.Handle("POST /api/v1/bootstrap-tickets", adminOnly(http.HandlerFunc(bootstrapH.ServeCreate)))
	mux.Handle("GET /api/v1/hosts", adminOnly(http.HandlerFunc(hostsH.ServeList)))
	mux.Handle("POST /api/v1/hosts/{name}/join-ticket", adminOnly(http.HandlerFunc(hostsH.ServeCreateTicket)))
	mux.Handle("/api/v1/node-events", protected(nodeEventsH))
	mux.Handle("/api/v1/discovered-containers", protected(discoveredH))
	mux.Handle("/api/v1/discovered-containers/", protected(discoveredH))
	mux.Handle("/api/v1/backends/health", protected(backendsHealthH))
	mux.Handle("/api/v1/metrics/proxies", protected(proxyMetricsH))
	mux.Handle("/api/v1/metrics/summary", protected(http.HandlerFunc(proxyMetricsH.ServeSummary)))
	mux.Handle("/api/v1/audit", protected(auditH))
	mux.Handle("/api/v1/audit/", protected(auditH))
	mux.Handle("/api/v1/alert-channel-types", protected(api.ChannelTypesHandler{}))
	mux.Handle("/api/v1/alert-channels", adminWrites(channelsH))
	mux.Handle("/api/v1/alert-channels/", adminWrites(channelsH))
	alertEventsH := &api.AlertEventsHandler{DB: s.db}
	mux.Handle("/api/v1/alert-events", adminWrites(alertEventsH))
	mux.Handle("/api/v1/alert-events/", adminWrites(alertEventsH))
	mux.Handle("/api/v1/alert-rules", adminWrites(rulesH))
	mux.Handle("/api/v1/alert-rules/", adminWrites(rulesH))
	mux.Handle("/api/v1/logs", adminWrites(logsH))
	mux.Handle("/api/v1/logs/", adminWrites(logsH))
	// Révélation : ouverte aux détenteurs de gdpr:reveal (rôle dpo, droit délégué), pas
	// seulement aux admins ; le handler vérifie la permission.
	mux.Handle("/api/v1/logs/reveal-ip", protected(logsH))
	// L'exporteur SIEM porte des jetons et des adresses internes : administrateurs seulement, en lecture aussi.
	mux.Handle("/api/v1/logs/siem", adminOnly(logsH))
	mux.Handle("/api/v1/logs/siem/status", adminOnly(logsH))
	mux.Handle("/api/v1/security/engine-types", adminOnly(api.EngineTypesHandler{}))
	mux.Handle("/api/v1/security", adminOnly(securityH))
	mux.Handle("/api/v1/security/", adminOnly(securityH))
	mux.Handle("/api/v1/automation/", adminOnly(automationH))
	mux.Handle("GET /api/v1/edges/waf-status", protected(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	mux.Handle("/api/v1/ip-profiles", adminWrites(ipProfilesH))
	mux.Handle("/api/v1/ip-profiles/", adminWrites(ipProfilesH))
	mux.Handle("/api/v1/domains", adminWrites(domainsH))
	mux.Handle("/api/v1/domains/", adminWrites(domainsH))
	mux.Handle("/api/v1/agents", adminOnly(agentsH))
	mux.Handle("/api/v1/agents/", adminOnly(agentsH))

	// Pairing secret — lecture réservée aux admins (wizard Infrastructure).
	mux.Handle("GET /api/v1/pairing-secret", adminOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secret := pairing.Secret("GPX_PAIRING_SECRET")
		w.Header().Set("Content-Type", "application/json")
		// secret : pour les passerelles ; agent_key : pour les Agents, qui ne doivent pas détenir le secret racine.
		out := map[string]string{"secret": secret, "agent_key": pairing.AgentKey(secret)}
		// ?node=<identifiant ou nom> : la clé du canal Admin → cette passerelle, à lui donner (GPX_EDGE_CHANNEL_KEY) à la
		// place du secret racine. Elle se dérive de l'identifiant de la passerelle, qui survit à un renommage.
		if node := strings.TrimSpace(r.URL.Query().Get("node")); node != "" {
			id, ok := manager.EdgeIDOf(node)
			if !ok {
				http.Error(w, "passerelle inconnue de l'Admin : "+node, http.StatusNotFound)
				return
			}
			out["edge_channel_key"] = pairing.EdgeChannelKey(secret, id)
			out["node_id"] = id
			// Pour un déploiement qui ne connaît pas l'identifiant d'avance (Helm, démarrage rapide) : la clé du nom.
			if name := manager.EdgeNameOf(id); name != "" {
				out["edge_channel_key_by_name"] = pairing.EdgeChannelKey(secret, name)
			}
		}
		json.NewEncoder(w).Encode(out) //nolint:errcheck
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
	echH := &api.ECHHandler{DB: s.db, Log: s.log, Pusher: manager}
	mux.Handle("/api/v1/ech", adminOnly(echH))
	mux.Handle("/api/v1/ech/", adminOnly(echH))
	acmeProvidersH := &api.ACMEProvidersHandler{Store: acmeProviderStore, Log: s.log}
	mux.Handle("/api/v1/acme/provider-types", adminOnly(api.ACMEProviderTypesHandler{}))
	mux.Handle("/api/v1/discovery-sources", adminOnly(api.DiscoverySourcesHandler{}))
	mux.Handle("/api/v1/acme/providers", adminOnly(acmeProvidersH))
	mux.Handle("/api/v1/acme/providers/", adminOnly(acmeProvidersH))

	// MCP server — PAT utilisateur uniquement (pas de JWT session)
	var banGroups api.GroupResolver
	if archStore != nil {
		banGroups = api.NewGroupResolver(archStore, s.db)
	}
	mcpH := &mcp.Handler{
		ProxyMetrics: func(points int) (any, any) { return proxyMetricsH.Snapshot(points) },
		SIEMStatus:   manager.SIEMStatus,
		ArchStore:    archStore,
		DNSProviders: acmeProviderStore,
		DB:           s.db, Log: s.log, Pusher: manager,
		Access: manager, AccessTemplates: manager,
		ResolvePublicURL: bootstrapH.ResolvePublicURL,
		Hosts:            hostsH,
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
		OnUnban:      pushUnban,
		OnUnbanMany:  pushUnbanMany,
		ASN:          asnStore,
		OnWhitelistChange: pushIPProfiles,
		Automation:   s.automation,
		Groups:       banGroups,
		CertDeployer: certDeployer,
		InternalCA:   internalCAMgr,
	}
	mux.Handle("/mcp", auth.RequirePAT(s.db)(mcpH))
	mux.Handle("/mcp/", auth.RequirePAT(s.db)(mcpH))

	// Heartbeat et events — authentifiés par token d'appairage
	mux.Handle("/internal/v1/heartbeat", auth.RequireBearerToken(s.db)(heartbeatH))
	mux.Handle("/internal/v1/events", auth.RequireBearerToken(s.db)(nodeEventsH))

	addr := fmt.Sprintf("%s:%d", s.cfg.Server.ListenAddr, s.cfg.Server.APIPort)
	var handler http.Handler = limitRequestBodies(s.logMiddleware(mux))
	if s.haManager != nil {
		handler = s.haManager.ForwardOrHandle(handler)
	}
	s.srv = httpx.Harden(&http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	})

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

	// Port local de secours : accès direct sans passer par la passerelle.
	// Utile si Ephor ou une règle de sécurité bloque l'accès proxifié.
	if s.cfg.Server.LocalPort > 0 {
		localAddr := fmt.Sprintf("0.0.0.0:%d", s.cfg.Server.LocalPort)
		localSrv := httpx.Harden(&http.Server{
			Addr:         localAddr,
			Handler:      limitRequestBodies(s.logMiddleware(mux)), // sans HA forward
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		})
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
	s.closeLogVault()
	// Avant la base : les étapes en cours enregistrent leur avancement.
	if s.automation != nil {
		s.automation.Stop()
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
	res, err := db.Exec(`UPDATE users SET password_hash=?, tokens_valid_after=? WHERE email=?`, hash, time.Now().Unix(), email)
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

func toSamples(points []api.MetricPoint) []autometrics.Sample {
	out := make([]autometrics.Sample, len(points))
	for i, p := range points {
		out[i] = autometrics.Sample{Key: p.Key, Entity: p.Entity, Value: p.Value}
	}
	return out
}
