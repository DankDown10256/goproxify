// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/vincamok/goproxify/internal/edge/plugins"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vincamok/goproxify/internal/asncompact"
	"github.com/vincamok/goproxify/internal/config"
	edgeagent "github.com/vincamok/goproxify/internal/edge/agent"
	"github.com/vincamok/goproxify/internal/edge/bansdb"
	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	edgecrowdsec "github.com/vincamok/goproxify/internal/edge/crowdsec"
	"github.com/vincamok/goproxify/internal/edge/errorpages"
	edgef2b "github.com/vincamok/goproxify/internal/edge/fail2ban"
	"github.com/vincamok/goproxify/internal/edge/geoip"
	"github.com/vincamok/goproxify/internal/edge/lastua"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/logserve"
	"github.com/vincamok/goproxify/internal/edge/logstore"
	"github.com/vincamok/goproxify/internal/edge/logthrottle"
	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/middleware"
	"github.com/vincamok/goproxify/internal/edge/portal"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/proxypipeline"
	"github.com/vincamok/goproxify/internal/edge/proxyproto"
	"github.com/vincamok/goproxify/internal/edge/proxystore"
	edgequic "github.com/vincamok/goproxify/internal/edge/quic"
	"github.com/vincamok/goproxify/internal/edge/router"
	edgere "github.com/vincamok/goproxify/internal/edge/rulesengine"
	"github.com/vincamok/goproxify/internal/edge/siem"
	"github.com/vincamok/goproxify/internal/edge/fingerprint"
	"github.com/vincamok/goproxify/internal/edge/surface"
	"github.com/vincamok/goproxify/internal/edge/threat"
	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
	"github.com/vincamok/goproxify/internal/edge/tlsfp"
	edgetokens "github.com/vincamok/goproxify/internal/edge/tokens"
	"github.com/vincamok/goproxify/internal/edge/tracing"
	"github.com/vincamok/goproxify/internal/edge/tunnel"
	"github.com/vincamok/goproxify/internal/edge/waf"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
	"github.com/vincamok/goproxify/internal/nodeident"
	"github.com/vincamok/goproxify/internal/pairing"
)

// Server est le Data Plane — reverse proxy HTTP/TLS/TCP/UDP.
type Server struct {
	logGate      *logserve.Gate // plafond des recherches simultanées dans la base de logs
	logGateOnce  sync.Once
	cfg          *config.EdgeConfig
	log          *edgelog.DynamicLogger
	accessLog    *edgelog.AccessLogger
	logStore     *logstore.Store // base de logs locale (ADR 0012) ; nil si elle n'a pas pu s'ouvrir
	siemExporter *siem.Manager   // exporteur SIEM (ADR 0012) ; nil sans base de logs
	logStreams   logStreams      // envoi des logs de la base vers chaque Admin connecté
	logLive      logLives        // vues Live ouvertes par chaque Admin (lignes envoyées à la demande)
	agentLogs    agentLogDedup   // dernière ligne gardée par conteneur d'Agent

	table           *router.Table
	certStore       *edgetls.CertStore
	ech             *edgetls.ECHManager
	snippetStore    *router.SnippetStore
	pluginMgr       *plugins.Manager // plugins WASM installés (ADR 0008)
	pluginLog       pluginLogQueue   // appels du hook log, hors du chemin de la réponse
	pluginGuard     pluginGuard      // refus des plugins de détection, comptés par IP
	providerStore   *router.AuthProviderStore
	profileStore    *router.IPProfileStore
	banStore        *router.BanStore
	blockLog        *logthrottle.Limiter // regroupe les refus répétés d'une même IP dans le journal
	lastUA          *lastua.Tracker      // dernier User-Agent par IP, joint aux bans automatiques
	bansDB          *bansdb.DB
	threatEngine    *threat.Engine
	f2bEngine       *edgef2b.Engine
	crowdSecBouncer *edgecrowdsec.Bouncer
	rulesEngine     *edgere.Engine
	autoMetrics     *localMetrics
	tunnelManager   *tunnel.Manager

	// bansMu sérialise reloadBanStore : une relecture de la DB plus ancienne ne doit pas remplacer
	// le BanStore après une plus récente (bans posés en parallèle depuis les requêtes).
	bansMu     sync.Mutex
	cache      *edgecache.Store
	proxyStore *proxystore.Store
	proxyPipe  *proxypipeline.Pipeline
	health     *proxy.BackendHealth
	metrics    *proxy.AgentMetricsStore
	peers      *proxy.PeerRegistry
	peerHealth peerHealth
	nodeStore  *edgeagent.NodeStore
	tokenStore *edgetokens.Store

	httpSrv        *http.Server
	httpsSrv       *http.Server
	intSrv         *http.Server // API interne :8000
	quicSrv        *edgequic.QUICServer
	wsHub          *edgews.Hub
	portal         *portal.Service
	portalRepl     *portalReplicator             // réplication du portail vers les pairs du groupe HA
	agentRepl      agentReplicator               // réplication des HMAC d'Agents vers les pairs du groupe HA
	agentGen       agentGenerations              // dernière génération d'état complet acceptée par (Agent, source, scope)
	agentStates    agentStateStore               // derniers états complets acceptés, pour les pairs du groupe HA
	adminDocs      pushedJournal                 // derniers documents poussés par l'Admin, pour les pairs du groupe HA
	disabledRoutes disabledRoutes                // hôtes dont la route issue d'un conteneur est désactivée
	groupCard      groupCardHolder               // fiche du groupe HA, déclarée par l'Admin
	peerSeen       peerLiveness                  // dernier échange réussi avec chaque pair, pour choisir l'exécutant des actions uniques
	ruleReports    ruleReports                   // déclenchements de notification déjà remontés à l'Admin
	ruleReportHook func(edgews.RuleFiredPayload) // observe les déclenchements remontés (tests)
	agentStatePush agentStatePusher

	implicitSkeleton sync.Map // ID de route implicite → route telle que générée, sans surcouche

	tracingShutdown func(context.Context) error
	wafEngine       *waf.Engine
	behavior        *behavior.Store               // magasin comportemental commun à Ephor et au WAF (ADR 0011)
	asnDB           atomic.Pointer[asncompact.DB] // base IP → ASN poussée par l'Admin (copie chiffrée locale)
	asnAsm          asnAssembly

	surface       *surface.Collector                  // profils de surface des proxies en apprentissage (ADR 0016)
	apps          *fingerprint.Store                  // applications que les réponses des backends annoncent (ADR 0017)
	geoCountry    atomic.Pointer[func(net.IP) string] // pays d'une IP, ouvert quand la base MaxMind existe
	geoCountryTry atomic.Int64

	mu            sync.Mutex
	tcpPorts      map[string]interface{ Stop() }
	l4            l4State // rapprochement des écouteurs TCP/UDP avec la table (l4.go)
	pushedTracing string  // endpoint OTLP poussé par Admin (utilisé si cfg.Engine.TracingEndpoint est vide)
	activeTracing string  // endpoint OTLP réellement exporté (démarrage ou poussé par Admin)

	pushedMu sync.Mutex
	pushed   pushedSettings // cumul des réglages poussés par l'Admin, persisté (settingsPath)

	serverCfgMu sync.Mutex
	serverCfg   pushedServerConfig // cumul des timeouts poussés par l'Admin, persisté (serverConfigPath)

	// saveCache debounce (revue P1 #8)
	saveCacheMu    sync.Mutex
	saveCacheTimer *time.Timer

	// adminToken : token HMAC partagé par toutes les passerelles (reçu via TypeAdminToken).
	// Utilisé pour relayer les routes agent aux passerelles déléguées.
	adminTokenMu sync.RWMutex
	adminToken   string

	// Cache de chaînes dispatch invalidé par génération (revue P1 #3)
	dispatchGen      atomic.Uint64
	dispatchHandlers sync.Map // key -> *cachedDispatch
	dispatchBuildMu  sync.Mutex
}

// New initialise la passerelle à partir de la configuration.
func New(cfg *config.EdgeConfig) (*Server, error) {
	cfg.Identity.NodeName = nodeident.Resolve("edge")

	log := edgelog.New(cfg.Engine.LogLevel, cfg.Engine.LogFormat, cfg.Engine.SystemLogPath)
	accessLog := edgelog.NewAccessLogger()
	accessLog.SetIPAnonymize(cfg.Engine.IPAnonymize)
	accessLog.SetDisabled(cfg.Engine.AccessLogDisabled)
	metrics.SetRequestMetricsDisabled(cfg.Engine.MetricsDisabled)

	if created, err := edgecache.EnsureNodeKey(); err != nil {
		log.Logger().Warn("clé locale: génération impossible, la clé dérivée du secret d'appairage reste en service", "err", err)
	} else if created {
		log.Logger().Warn("clé locale générée dans le volume (" + edgecache.NodeKeyPath() + ") : à inclure dans les sauvegardes du volume ; GPX_NODE_KEY ou GPX_NODE_KEY_FILE la remplacent par une clé hors du disque")
	}
	secret := edgecache.ResolveSecret(cfg.ControlPlane.AuthToken)
	cachePath := "/etc/goproxify/edge-cache.gpx"
	if p := os.Getenv("GPX_EDGE_CACHE_PATH"); p != "" {
		cachePath = p
	}
	_ = os.MkdirAll(filepath.Dir(cachePath), 0755)
	// GeoIP : dossier volume + téléchargement auto de GeoLite2-Country si absent.
	_ = os.MkdirAll("/etc/goproxify/geoip", 0755)
	if err := geoip.Bootstrap(cfg.GeoIP.AutoDownload, cfg.GeoIP.DBPath, cfg.GeoIP.DBURL, log.Logger()); err != nil {
		log.Logger().Warn("geoip: bootstrap base MaxMind échoué", "err", err)
	}

	tracingShutdown, err := tracing.Init(cfg.Engine.TracingEndpoint, cfg.Engine.TracingSampleRatio)
	if err != nil {
		// Non bloquant : le tracing est optionnel
		tracingShutdown = func(context.Context) error { return nil }
	}

	bdb, err := bansdb.Open("")
	if err != nil {
		log.Logger().Warn("edge: ouverture bansdb échouée, fallback mémoire", "err", err)
	}
	s := &Server{
		cfg:             cfg,
		log:             log,
		accessLog:       accessLog,
		table:           &router.Table{},
		certStore:       edgetls.NewCertStore(),
		ech:             edgetls.NewECHManager(),
		snippetStore:    router.NewSnippetStore(),
		providerStore:   router.NewAuthProviderStore(),
		profileStore:    router.NewIPProfileStore(),
		banStore:        router.NewBanStore(),
		blockLog:        logthrottle.New(blockLogWindow),
		lastUA:          lastua.New(),
		bansDB:          bdb,
		cache:           edgecache.New(cachePath, secret),
		tcpPorts:        make(map[string]interface{ Stop() }),
		tracingShutdown: tracingShutdown,
		activeTracing:   cfg.Engine.TracingEndpoint,
		nodeStore:       edgeagent.NewNodeStore(),
		tunnelManager:   tunnel.New(log.Logger()),
	}
	s.initLogStore()
	s.initProxyStore()
	if u := os.Getenv("GPX_ADMIN_PUBLIC_URL"); u != "" {
		errorpages.SetAdminBaseURL(u)
		log.Logger().Info("errorpages: URL publique Admin (env)", "url", errorpages.GetAdminBaseURL())
	}
	if err := errorpages.DefaultStore().LoadFromDisk(); err != nil {
		log.Logger().Warn("errorpages: chargement volume", "err", err)
	} else {
		log.Logger().Info("errorpages: templates chargés depuis le volume", "dir", errorpages.Dir())
	}
	s.health = proxy.NewBackendHealth(log.Logger())
	s.health.OnDown = func(url string) {
		payload := edgews.BackendDownPayload{URL: url, NodeName: cfg.Identity.NodeName}
		if msg, err := edgews.NewMessage(0, edgews.TypeBackendDown, payload); err == nil {
			s.wsHub.BroadcastToAdmins(msg)
		}
	}
	s.metrics = proxy.NewAgentMetricsStore()
	s.peers = proxy.NewPeerRegistry()
	s.behavior = behavior.NewStore(0)
	s.surface = newSurfaceCollector(s)
	s.apps = fingerprint.NewStore()
	s.wafEngine = waf.NewEngine(nil, log.Logger())
	s.wafEngine.SetBehaviorStore(s.behavior)
	s.wafEngine.SetBanCallback(waf.BanCallback(s.threatBanCallback()))
	log.Logger().Info("waf: moteur prêt — activer par route (label goproxify.waf=detect|block ou snippet), coupable pour la passerelle (moteurs de sécurité)")
	s.portal = portal.NewService(log.Logger())
	s.portalRepl = &portalReplicator{}
	s.portal.SetStoreChangeHook(s.schedulePortalReplicaPush)

	// Token store local — source de vérité pour l'auth de l'API interne.
	tokensPath := "/etc/goproxify/edge-tokens.db"
	ts, err := edgetokens.Open(tokensPath)
	if err != nil {
		return nil, fmt.Errorf("token store: %w", err)
	}
	// Chaque appairage d'un Agent ajoute un jeton et rien ne les retirait : on borne le magasin à chaque démarrage.
	if n, perr := ts.PruneAll(edgetokens.RoleAgent, edgetokens.KeepAgentTokens); perr != nil {
		log.Logger().Warn("token store: purge des anciens jetons d'Agent", "err", perr)
	} else if n > 0 {
		log.Logger().Info("token store: anciens jetons d'Agent purgés", "supprimés", n, "gardés par Agent", edgetokens.KeepAgentTokens)
	}
	// Bootstrap : si aucun token n'existe, créer le token initial depuis la config.
	if cfg.ControlPlane.AuthToken != "" {
		nodeName := cfg.Identity.NodeName
		if nodeName == "" {
			nodeName = "admin"
		}
		if bErr := ts.Bootstrap("admin-"+nodeName, cfg.ControlPlane.AuthToken, edgetokens.RoleAdmin); bErr != nil {
			log.Logger().Warn("token store: bootstrap", "err", bErr)
		}
	}
	s.tokenStore = ts

	// Amorçage via GPX_EDGE_TOKEN : injecter le token dans le store local.
	if prebuilt := os.Getenv("GPX_EDGE_TOKEN"); prebuilt != "" {
		nodeName := cfg.Identity.NodeName
		if nodeName == "" {
			nodeName = "edge-1"
		}
		_ = ts.EnsureToken("admin-"+nodeName, prebuilt, edgetokens.RoleAdmin)
		log.Logger().Info("edge: token pré-configuré (GPX_EDGE_TOKEN)")
	}

	// Hub WebSocket plan de contrôle — HMAC partagé via GPX_PAIRING_SECRET
	s.wsHub = edgews.NewHub("", log.Logger())
	s.wsHub.SetAdminKeys(pairing.EdgeAdminKeys)
	s.wsHub.HMACStore().SetOnChange(s.scheduleAgentReplicaPush)
	s.wsHub.SetEdgeEndpointsProvider(s.groupEdgeEndpoints)
	s.wsHub.SetAdminMessageHandler(s.handleWSAdminMessage)
	s.wsHub.SetAgentMessageHandler(s.handleWSAgentMessage)
	s.portal.SetShellBroker(portal.NewShellBroker(s.wsHub))
	s.portal.SetInviteCompletedHook(func(userID string) {
		msg, err := edgews.NewMessage(0, edgews.TypePortalInviteCompleted, map[string]string{"user_id": userID})
		if err != nil {
			return
		}
		s.wsHub.BroadcastToAdmins(msg)
	})
	s.portal.SetEmailOTPSender(func(email, code string) error {
		if s.wsHub.ConnectedAdmins() == 0 {
			return fmt.Errorf("aucun Admin connecté")
		}
		msg, err := edgews.NewMessage(0, edgews.TypePortalSendEmailOTP, map[string]string{
			"email": email, "code": code,
		})
		if err != nil {
			return err
		}
		s.wsHub.BroadcastToAdmins(msg)
		return nil
	})
	s.portal.SetAuditHook(func(e portal.AuditEvent) {
		payload := map[string]any{
			"ts": e.Ts.UTC().Format(time.RFC3339), "actor": e.Actor,
			"target_id": e.TargetID, "facade": string(e.Facade),
			"success": e.Success, "detail": e.Detail,
			"node_name": s.cfg.Identity.NodeName,
		}
		msg, err := edgews.NewMessage(0, edgews.TypePortalAudit, payload)
		if err != nil {
			return
		}
		s.wsHub.BroadcastToAdmins(msg)
	})
	s.portal.SetLiveHook(s.sendPortalLive)
	s.portal.SetAccessRequestHook(func(req portal.AccessRequest) error {
		msg, err := edgews.NewMessage(0, edgews.TypePortalAccessRequest, map[string]any{
			"node_name": s.cfg.Identity.NodeName, "user_id": req.UserID, "username": req.Username,
			"target_id": req.TargetID, "reason": req.Reason, "duration_min": req.DurationMin,
		})
		if err != nil {
			return err
		}
		s.wsHub.BroadcastToAdmins(msg)
		return nil
	})
	s.portal.SetAuthProviders(s.providerStore)

	// Access logs + system logs → Admin (Prism / Logs) : la passerelle garde ses lignes dans sa base (logstore) et
	// l'Admin demande celles qui lui manquent à chaque connexion (TypeLogResume, voir logstream.go) : rien n'est perdu
	// pendant une coupure. Sans cette base la passerelle ne diffuse plus ses lignes (l'ancien envoi en direct, perdu
	// si aucun Admin n'était connecté, a disparu). Convention : status>0 = access HTTP ; status=0 = système.
	s.accessLog.SetNodeName(cfg.Identity.NodeName)
	s.log.SetNodeName(cfg.Identity.NodeName)
	s.wsHub.SetAgentPendingCallback(func(agentID, agentName, version string) {
		s.log.Info("ws/agent: nouvel Agent en attente", "id", agentID, "name", agentName)
		s.nodeStore.SetPending(agentID, agentName, version)
		// Notifier tous les Admins connectés pour affichage immédiat dans la topologie
		if msg, err := edgews.NewMessage(0, edgews.TypeAgentPending, edgews.AgentPendingPayload{
			AgentID:   agentID,
			AgentName: agentName,
			Version:   version,
		}); err == nil {
			s.wsHub.BroadcastToAdmins(msg)
		}
	})
	// Ne pas révoquer le join token à la connexion WS : il sert aussi de Bearer HTTP
	// pour le heartbeat de secours (quand le WS est temporairement déconnecté).
	// La révocation interviendrait et empêcherait le fallback HTTP de fonctionner,
	// ce qui ferait passer le nœud en "Inactif" après 90 s.
	s.wsHub.SetJoinTokenUsedCallback(func(joinToken string) {
		s.log.Info("ws/agent: JOIN_TOKEN utilisé pour connexion WS (conservé pour heartbeat HTTP)")
	})
	s.wsHub.SetTokenChecker(func(agentName string) bool {
		if s.tokenStore == nil {
			return false
		}
		return s.tokenStore.HasActiveAgent(agentName)
	})

	return s, nil
}

// Start démarre la passerelle.
func (s *Server) Start(ctx context.Context) error {
	if err := s.loadFromAdminOrCache(ctx); err != nil {
		return err
	}

	if p := s.cfg.Engine.WAFCustomRulesPath; p != "" {
		go s.wafEngine.WatchCustomRulesFile(ctx, p)
	}
	s.loadWAFConfigFromDisk()
	s.loadPushedJournalFromDisk()
	s.loadGroupCardFromDisk()

	// Ephor, sur sa dernière config connue, avant l'API interne : une config poussée par l'Admin
	// ne peut pas arriver avant le moteur.
	s.threatEngine = threat.New(s.log.Logger(), s.threatBanCallback())
	s.threatEngine.SetPriorBansFunc(s.priorThreatBans)
	s.threatEngine.SetBehaviorStore(s.behavior)
	s.behavior.SetASNLookup(s.lookupASN)
	s.loadASNFromDisk()
	s.loadThreatConfigFromDisk()
	s.loadThreatStateFromDisk()
	s.threatEngine.Start(ctx)
	s.loadPluginsFromDisk(ctx)

	// Réglages poussés (protection des IP, journalisation…) avant le premier access log.
	s.loadPushedSettingsFromDisk()
	s.loadTunnelConfigFromDisk()
	s.loadServerConfigFromDisk()
	s.loadGatewayPeersFromDisk()
	s.loadPortalTemplatesFromDisk()

	// API interne (push de routes depuis l'Admin)
	if err := s.startInternalAPI(); err != nil {
		return err
	}

	// Serveur HTTP
	if err := s.startHTTP(); err != nil {
		return err
	}

	// Serveur HTTPS
	if err := s.startHTTPS(); err != nil {
		return err
	}

	// Serveur HTTP/3 QUIC
	if err := s.startQUIC(); err != nil {
		s.log.Warn("quic: démarrage échoué (non bloquant)", "err", err)
	}

	// Heartbeat passerelle → Admin via WebSocket
	go s.wsHeartbeatLoop(ctx)
	go s.trafficLoop(ctx)
	s.startSIEM(ctx)
	go s.logInfoLoop(ctx)
	go s.portalLiveLoop(ctx)

	// Marquage offline des Agents inactifs
	go s.agentOfflineLoop(ctx)

	// Mise à jour périodique du cache
	go s.autosaveLoop(ctx)
	go s.ocspLoop(ctx)

	// Sondes de santé : suivent la table (proxies fichiers, révisions, agents) sans l'Admin.
	go s.healthSyncLoop(ctx)

	// Sync pools discovery depuis les passerelles pairs (LB cross-passerelle)
	s.startPeerSyncLoop(ctx)
	go s.surfaceStatusLoop(ctx)
	// Écouteurs TCP/UDP des routes L4 : suivent la table, et se rouvrent après un redémarrage sans l'Admin.
	s.table.SetOnChange(s.scheduleL4Sync)
	s.scheduleL4Sync()
	s.startQuotaSyncLoop(ctx)

	// Restauration du magasin comportemental (notes, historique propre, références apprises) depuis la copie chiffrée locale.
	s.loadBehaviorStateFromDisk()
	s.loadSurfaceStateFromDisk()
	s.loadAppsStateFromDisk()

	// Moteur Fail2Ban — autonome, lit les access logs, bans locaux.
	s.f2bEngine = edgef2b.New()
	s.f2bEngine.UpdateConfig(s.loadF2BConfig())
	s.f2bEngine.OnBan = s.onF2BBan
	s.accessLog.SetF2BTap(s.feedF2B)
	s.f2bEngine.Start(ctx)
	// Les bans relus au démarrage l'ont été avant la liste blanche Fail2Ban.
	s.reloadBanStore()

	// Bouncer CrowdSec — autonome, sync LAPI, bans locaux.
	s.crowdSecBouncer = edgecrowdsec.New(s.log.Logger())
	s.crowdSecBouncer.UpdateConfig(s.loadCrowdSecConfig())
	s.crowdSecBouncer.OnBansChanged = s.onCrowdSecBansChanged
	s.crowdSecBouncer.OnDecisions = s.onCrowdSecDecisions
	s.crowdSecBouncer.Start(ctx)

	s.autoMetrics = newLocalMetrics(s.cfg.Identity.NodeName)
	go s.autoMetrics.run(ctx)

	// Moteur de règles automatiques — autonome, évalue règles poussées par Admin.
	s.rulesEngine = edgere.New(s.log.Logger(), edgere.Deps{
		GetRecentBanCount:   s.recentBanCount,
		GetRepeatBanIP:      s.repeatBanIP,
		GetF2BLastActivity:  func() time.Time { return s.f2bEngine.LastBan() },
		GetCrowdSecLastSync: func() time.Time { return s.crowdSecBouncer.LastSync() },
		GetProxyErrorRate:   s.proxyErrorRate,
		QueryMetric:         s.autoMetrics.query,
		DisableProxy: func(id string) error {
			s.table.DisableByIDOrHost(id)
			s.saveCache()
			return nil
		},
		BanIP: func(ip, reason string, duration time.Duration) error {
			s.addRuleBan(ip, reason, duration)
			return nil
		},
		EnableStrictF2B: func(dur time.Duration) error {
			cfg := s.f2bEngine.GetConfig()
			orig := cfg.MaxErrors
			cfg.MaxErrors = 5
			s.f2bEngine.UpdateConfig(cfg)
			go func() {
				time.Sleep(dur)
				c := s.f2bEngine.GetConfig()
				if c.MaxErrors == 5 {
					c.MaxErrors = orig
					s.f2bEngine.UpdateConfig(c)
				}
			}()
			return nil
		},
		EmitNotify: s.onRuleNotify,
	})
	s.rulesEngine.OnRuleFired = s.onRuleFired
	s.loadAutoRulesFromDisk()
	s.accessLog.SetProxyTap(s.recordProxyEvent)
	s.rulesEngine.Start()
	go s.bansDBPurgeLoop(ctx)

	// Portail d'accès : activable via env (dev) ou push Admin.
	if os.Getenv("GPX_PORTAL_ENABLED") == "true" || os.Getenv("GPX_PORTAL_ENABLED") == "1" {
		pcfg := portal.Config{Enabled: true, PublicHost: os.Getenv("GPX_PORTAL_PUBLIC_HOST")}
		if p := os.Getenv("GPX_PORTAL_SSH_PORT"); p != "" {
			fmt.Sscanf(p, "%d", &pcfg.SSHPort)
		}
		if p := os.Getenv("GPX_PORTAL_HTTP_PORT"); p != "" {
			fmt.Sscanf(p, "%d", &pcfg.HTTPPort)
		}
		if err := s.portal.ApplyConfig(pcfg); err != nil {
			s.log.Warn("portal: démarrage env échoué", "err", err)
		} else {
			s.ensurePortalPublicRoute()
		}
	}

	s.loadPortalConfigFromDisk()

	s.log.Info("edge démarré",
		"http", fmt.Sprintf(":%d", s.cfg.Network.HTTPPort),
		"https", fmt.Sprintf(":%d", s.cfg.Network.HTTPSPort),
		"internal", fmt.Sprintf(":%d", s.cfg.Network.InternalAPIPort),
	)
	return nil
}

// Stop arrête proprement la passerelle.
func (s *Server) Stop(ctx context.Context) {
	if s.httpSrv != nil {
		s.httpSrv.Shutdown(ctx) //nolint:errcheck
	}
	if s.httpsSrv != nil {
		s.httpsSrv.Shutdown(ctx) //nolint:errcheck
	}
	if s.intSrv != nil {
		s.intSrv.Shutdown(ctx) //nolint:errcheck
	}
	if s.quicSrv != nil {
		s.quicSrv.Stop()
	}
	if s.tracingShutdown != nil {
		s.tracingShutdown(ctx) //nolint:errcheck
	}
	s.pluginLog.stop()
	s.l4.stop()
	s.mu.Lock()
	for _, l := range s.tcpPorts {
		l.Stop()
	}
	s.mu.Unlock()
	if s.portal != nil {
		s.portal.Stop()
	}
	if s.tokenStore != nil {
		s.tokenStore.Close() //nolint:errcheck
	}
	if s.threatEngine != nil {
		s.threatEngine.Stop()
	}
	if s.f2bEngine != nil {
		s.accessLog.SetF2BTap(nil)
		s.f2bEngine.Stop()
	}
	if s.crowdSecBouncer != nil {
		s.crowdSecBouncer.Stop()
	}
	if s.rulesEngine != nil {
		s.accessLog.SetProxyTap(nil)
		s.rulesEngine.Stop()
	}
	s.logStreams.stopAll()
	s.logLive.stopAll()
	if s.siemExporter != nil {
		s.siemExporter.Close()
	}
	if s.logStore != nil {
		_ = s.logStore.Close()
	}
	if s.bansDB != nil {
		_ = s.bansDB.Close()
	}
	s.saveThreatState()
	s.saveBehaviorState()
	s.saveSurfaceState()
	s.saveAppsState()
}

// --- Chargement initial ---------------------------------------------------

func (s *Server) loadFromAdminOrCache(ctx context.Context) error {
	// Profils IP : snapshot disque dédié (indépendant du cache chiffré).
	s.loadIPProfilesFromDisk()
	s.loadBansFromDisk()

	// Cache local en priorité — la passerelle est autonome.
	// Fallbacks : ancien auth_token + clé vide (compose historiquement sans auth_token).
	snap, err := s.cache.LoadWithFallbacks(s.cfg.ControlPlane.AuthToken, "")
	if err != nil {
		s.log.Warn("edge: cache local illisible — démarrage sans config (Admin doit resynchroniser)",
			"err", err)
		return nil
	}
	if snap != nil {
		s.applySnapshot(snap)
		s.log.Info("edge: démarrage depuis cache local",
			"saved_at", snap.SavedAt.Format(time.RFC3339),
			"routes", len(snap.Routes),
			"certs", len(snap.Certs),
			"snippets", len(snap.Snippets),
			"providers", len(snap.AuthProviders),
			"ip_profiles", s.profileStore.Len(),
			"bans", s.banStore.Len(),
		)
	} else {
		s.log.Info("edge: aucun cache local — démarrage sans config, en attente du full_sync Admin",
			"ip_profiles", s.profileStore.Len(),
			"bans", s.banStore.Len(),
		)
	}
	// Certs disque = fallback si le cache AES-GCM était absent ou corrompu.
	s.loadCertsFromDisk()
	// Fichiers proxies/*.json = source de vérité des proxies manuels (après cache).
	s.loadProductionProxies()
	return nil
}

// refreshEphorWhitelists relit toutes les routes de la table et met à jour la whitelist du moteur.
func (s *Server) refreshEphorWhitelists() {
	if s.threatEngine == nil {
		return
	}
	s.threatEngine.MergeRouteWhitelists(collectEphorWhitelists(s.table.All()))
	s.reloadBanStore()
}

// collectEphorWhitelists agrège les entrées ephor_whitelist de toutes les routes.
func collectEphorWhitelists(routes []*router.Route) []string {
	var out []string
	for _, r := range routes {
		out = append(out, r.EphorWhitelist...)
	}
	return out
}

// applySnapshot charge toutes les ressources d'un snapshot en mémoire.
func (s *Server) applySnapshot(snap *edgecache.Snapshot) {
	if snap.Routes != nil {
		s.table.Replace(snap.Routes) //nolint:errcheck
		s.syncHealthChecks()
		if s.threatEngine != nil {
			s.threatEngine.MergeRouteWhitelists(collectEphorWhitelists(snap.Routes))
		}
	}
	for _, c := range snap.Certs {
		if err := s.certStore.StorePEM(c.Name, c.CertPEM, c.KeyPEM); err != nil {
			s.log.Warn("edge: cert cache invalide", "name", c.Name, "err", err)
		}
	}
	if snap.Snippets != nil {
		s.snippetStore.Replace(snap.Snippets)
	}
	if snap.AuthProviders != nil {
		s.providerStore.Replace(snap.AuthProviders)
	}
	if len(snap.ECHKeys) > 0 || snap.ECHVersion > 0 {
		if err := s.ech.Restore(snap.ECHKeys, snap.ECHVersion); err != nil {
			s.log.Warn("edge: clés ECH du cache invalides", "err", err)
		}
	}
}

// --- Serveurs HTTP -------------------------------------------------------

// serverTimeouts retourne les timeouts HTTP depuis la config, avec les defaults si non configurés.
func (s *Server) serverTimeouts() (readHeader, read, write, idle time.Duration) {
	t := s.cfg.Timeouts
	readHeader = durationOrDefault(t.ReadHeaderSeconds, 10)
	read = durationOrDefault(t.ReadSeconds, 30)
	write = durationOrDefault(t.WriteSeconds, 60)
	idle = durationOrDefault(t.IdleSeconds, 120)
	return
}

func durationOrDefault(seconds, defaultSeconds int) time.Duration {
	if seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return time.Duration(defaultSeconds) * time.Second
}

func (s *Server) startHTTP() error {
	if s.cfg.Network.HTTPPort == 0 {
		s.cfg.Network.HTTPPort = 80
	}
	addr := fmt.Sprintf("%s:%d", s.cfg.Network.BindAddress, s.cfg.Network.HTTPPort)
	rh, r, w, idle := s.serverTimeouts()
	s.httpSrv = &http.Server{
		Addr:              addr,
		Handler:           tracing.Middleware(requestIDMiddleware(s.accessLog.Middleware(s.httpMux()))),
		ReadHeaderTimeout: rh,
		ReadTimeout:       r,
		WriteTimeout:      w,
		IdleTimeout:       idle,
		MaxHeaderBytes:    s.cfg.MaxHeaderBytes(),
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("écoute TCP %s : %w", addr, err)
	}
	if ln, err = s.withProxyProtocol(ln); err != nil {
		return err
	}
	go func() {
		if err := s.httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.log.Error("http server", "err", err)
		}
	}()
	return nil
}

// withProxyProtocol enveloppe ln pour lire l'en-tête PROXY quand network.proxy_protocol est activé.
func (s *Server) withProxyProtocol(ln net.Listener) (net.Listener, error) {
	pp := s.cfg.Network.ProxyProtocol
	if !pp.Enabled {
		return ln, nil
	}
	trusted, err := proxyproto.ParseTrusted(pp.TrustedCIDRs)
	if err == nil && len(trusted) == 0 {
		err = errors.New("proxy_protocol : trusted_cidrs requis (sans source de confiance, n'importe quel client pourrait usurper son IP)")
	}
	if err != nil {
		ln.Close()
		return nil, err
	}
	return proxyproto.NewListener(ln, trusted), nil
}

func (s *Server) startHTTPS() error {
	if s.cfg.Network.HTTPSPort == 0 {
		s.cfg.Network.HTTPSPort = 443
	}
	addr := fmt.Sprintf("%s:%d", s.cfg.Network.BindAddress, s.cfg.Network.HTTPSPort)
	tlsCfg := &tls.Config{
		GetCertificate: s.certStore.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1", edgetls.ACMETLSALPNProto},
		MinVersion:     tls.VersionTLS12,
	}
	// Raw TCP listener : le peek SNI doit voir le ClientHello brut AVANT que Go TLS
	// ne consomme le handshake. On wrappera chaque connexion en tls.Server() après.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("écoute TCP %s : %w", addr, err)
	}
	if ln, err = s.withProxyProtocol(ln); err != nil {
		return err
	}

	s.ech.Bind(tlsCfg)
	// Empreintes JA3/JA4 des connexions TLS vivantes, retrouvées par http.Server via ConnContext.
	fps := &sync.Map{}
	sniLn := &sniListener{inner: ln, table: s.table, log: s.log.Logger(), tlsCfg: tlsCfg, ech: s.ech, fps: fps}

	rh, r, w, idle := s.serverTimeouts()
	s.httpsSrv = &http.Server{
		Handler:           tracing.Middleware(requestIDMiddleware(s.accessLog.Middleware(s.httpMux()))),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: rh,
		ReadTimeout:       r,
		WriteTimeout:      w,
		IdleTimeout:       idle,
		MaxHeaderBytes:    s.cfg.MaxHeaderBytes(),
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			if fp, ok := fps.Load(c); ok {
				return tlsfp.WithContext(ctx, fp.(*tlsfp.Fingerprint))
			}
			return ctx
		},
		ConnState: func(conn net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
				fps.Delete(conn)
				if tc, ok := conn.(*tls.Conn); ok {
					sni := tc.ConnectionState().ServerName
					metrics.TLS.ActiveConns.WithLabelValues(sni).Dec()
				}
			}
		},
	}
	go func() {
		if err := s.httpsSrv.Serve(sniLn); err != nil && err != http.ErrServerClosed && err != io.EOF {
			s.log.Error("https server", "err", err)
		}
	}()
	return nil
}

// sniListener intercepte les connexions TCP brutes pour détecter le SNI du ClientHello
// avant que la couche TLS ne soit établie.
type sniListener struct {
	inner  net.Listener
	table  *router.Table
	log    *slog.Logger
	tlsCfg *tls.Config
	ech    *edgetls.ECHManager // clés ECH courantes ; la config TLS est choisie par connexion
	fps    *sync.Map           // *tls.Conn → *tlsfp.Fingerprint, vidé à la fermeture (ConnState)
}

func (l *sniListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.inner.Accept()
		if err != nil {
			return nil, err // erreur du listener sous-jacent (ex: fermé) → on propage
		}
		// Deadline courte : les scanners qui ouvrent TCP sans envoyer de ClientHello
		// ne doivent pas bloquer la boucle Accept indéfiniment.
		conn.SetReadDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
		sni, fp, peeked, err := edgetls.PeekClientHello(conn)
		conn.SetReadDeadline(time.Time{}) //nolint:errcheck
		if err != nil {
			conn.Close()
			continue
		}
		sni = strings.ToLower(strings.TrimSpace(sni))
		route, ok := l.table.PassthroughRoute(sni)
		if ok {
			go l.doPassthrough(peeked, route)
			continue
		}
		// Retourner *tls.Conn directement : http.Server fait une type assertion sur
		// *tls.Conn pour router les connexions h2 via TLSNextProto. Un wrapper custom
		// ferait échouer cette assertion et forcerait toutes les connexions en HTTP/1.1,
		// provoquant ERR_HTTP2_PROTOCOL_ERROR quand le client a négocié h2 via ALPN.
		cfg := l.tlsCfg
		if c := l.ech.Config(); c != nil {
			cfg = c
		}
		tlsConn := tls.Server(peeked, cfg)
		if fp != nil && l.fps != nil {
			l.fps.Store(tlsConn, fp)
		}
		go l.measureHandshake(tlsConn, sni)
		return tlsConn, nil
	}
}

func (l *sniListener) Close() error   { return l.inner.Close() }
func (l *sniListener) Addr() net.Addr { return l.inner.Addr() }

// measureHandshake enregistre la durée du handshake TLS et les connexions actives.
// tls.Conn.Handshake() est idempotent : l'appel concurrent avec celui de http.Server est sans danger.
// Le Dec() des connexions actives est géré par le ConnState hook du http.Server (voir startHTTPS).
func (l *sniListener) measureHandshake(c *tls.Conn, sni string) {
	start := time.Now()
	if err := c.Handshake(); err != nil {
		return
	}
	metrics.TLS.ActiveConns.WithLabelValues(sni).Inc()
	metrics.TLS.HandshakeDuration.WithLabelValues(sni).Observe(time.Since(start).Seconds())
}

func (l *sniListener) doPassthrough(client net.Conn, route *router.Route) {
	defer client.Close()
	if len(route.Backends) == 0 {
		l.log.Warn("passthrough: aucun backend", "host", route.Host, "id", route.ID)
		return
	}
	target := strings.TrimPrefix(strings.TrimPrefix(route.Backends[0].URL, "https://"), "http://")
	upstream, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		l.log.Warn("passthrough dial failed", "host", route.Host, "target", target, "err", err)
		return
	}
	defer upstream.Close()
	if v := route.ProxyProtocol; v == "v1" || v == "v2" {
		hdr := proxyproto.Header(v, proxyproto.AddrPort(client.RemoteAddr()), proxyproto.AddrPort(client.LocalAddr()))
		if _, err := upstream.Write(hdr); err != nil {
			l.log.Warn("passthrough: écriture PROXY protocol", "host", route.Host, "err", err)
			return
		}
	}
	l.log.Debug("passthrough", "host", route.Host, "target", target, "id", route.ID)

	buf := middleware.GetBuf()
	defer middleware.PutBuf(buf)
	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		b := middleware.GetBuf()
		defer middleware.PutBuf(b)
		copyConn(dst, src, *b)
	}
	go pipe(upstream, client)
	go pipe(client, upstream)
	<-done
}

func copyConn(dst, src net.Conn, buf []byte) {
	for {
		n, err := src.Read(buf)
		if n > 0 {
			dst.Write(buf[:n]) //nolint:errcheck
		}
		if err != nil {
			return
		}
	}
}

func (s *Server) startQUIC() error {
	s.quicSrv = &edgequic.QUICServer{}
	return s.quicSrv.Start(s.cfg, tracing.Middleware(requestIDMiddleware(s.accessLog.Middleware(s.httpMux()))), s.certStore)
}

// syncHealthChecks aligne les sondes actives sur la table de routes courante.
func (s *Server) syncHealthChecks() {
	s.health.Sync(s.table.All())
}

func (s *Server) healthSyncLoop(ctx context.Context) {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		s.syncHealthChecks()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
