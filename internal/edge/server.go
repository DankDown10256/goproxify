// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"crypto/tls"
	"fmt"
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

	"github.com/vincamok/goproxify/internal/config"
	edgeagent "github.com/vincamok/goproxify/internal/edge/agent"
	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	"github.com/vincamok/goproxify/internal/edge/bansdb"
	"github.com/vincamok/goproxify/internal/edge/cluster"
	edgef2b "github.com/vincamok/goproxify/internal/edge/fail2ban"
	edgecrowdsec "github.com/vincamok/goproxify/internal/edge/crowdsec"
	edgere "github.com/vincamok/goproxify/internal/edge/rulesengine"
	"github.com/vincamok/goproxify/internal/edge/errorpages"
	"github.com/vincamok/goproxify/internal/edge/geoip"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/middleware"
	"github.com/vincamok/goproxify/internal/edge/portal"
	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/proxypipeline"
	"github.com/vincamok/goproxify/internal/edge/proxystore"
	edgequic "github.com/vincamok/goproxify/internal/edge/quic"
	"github.com/vincamok/goproxify/internal/edge/raft"
	"github.com/vincamok/goproxify/internal/edge/router"
	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
	edgetokens "github.com/vincamok/goproxify/internal/edge/tokens"
	"github.com/vincamok/goproxify/internal/edge/tracing"
	"github.com/vincamok/goproxify/internal/edge/waf"
	"github.com/vincamok/goproxify/internal/edge/threat"
	"github.com/vincamok/goproxify/internal/edge/tunnel"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
	"github.com/vincamok/goproxify/internal/nodeident"
)

// Server est le Data Plane — reverse proxy HTTP/TLS/TCP/UDP.
type Server struct {
	cfg       *config.EdgeConfig
	cfgPath   string // chemin de edge.json — utilisé pour persister les timeouts
	log       *edgelog.DynamicLogger
	accessLog *edgelog.AccessLogger

	table         *router.Table
	certStore     *edgetls.CertStore
	snippetStore  *router.SnippetStore
	providerStore *router.AuthProviderStore
	profileStore  *router.IPProfileStore
	banStore      *router.BanStore
	bansDB        *bansdb.DB
	threatEngine    *threat.Engine
	f2bEngine       *edgef2b.Engine
	crowdSecBouncer *edgecrowdsec.Bouncer
	rulesEngine     *edgere.Engine
	tunnelManager   *tunnel.Manager

	// Bans threat : merge avec les bans Admin sans écraser.
	bansMu            sync.Mutex
	pendingThreatBans []*router.RuntimeBan
	cache         *edgecache.Store
	proxyStore    *proxystore.Store
	proxyPipe     *proxypipeline.Pipeline
	health        *proxy.BackendHealth
	metrics       *proxy.AgentMetricsStore
	peers         *proxy.PeerRegistry
	nodeStore     *edgeagent.NodeStore
	tokenStore    *edgetokens.Store

	httpSrv  *http.Server
	httpsSrv *http.Server
	intSrv   *http.Server // API interne :8000
	quicSrv  *edgequic.QUICServer
	wsHub    *edgews.Hub
	portal   *portal.Service

	tracingShutdown func(context.Context) error
	clusterGroup    *cluster.Group
	wafEngine       *waf.Engine

	mu            sync.Mutex
	tcpPorts      map[string]interface{ Stop() }
	pushedTracing string // endpoint OTLP poussé par Admin (utilisé si cfg.Engine.TracingEndpoint est vide)
	activeTracing string // endpoint OTLP réellement exporté (démarrage ou poussé par Admin)

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
}


// New initialise la passerelle à partir de la configuration.
func New(cfg *config.EdgeConfig, cfgPath ...string) (*Server, error) {
	cfg.Identity.NodeName = nodeident.Resolve("edge")

	log := edgelog.New(cfg.Engine.LogLevel, cfg.Engine.LogFormat, cfg.Engine.SystemLogPath)
	accessLog := edgelog.NewAccessLogger(cfg.Engine.AccessLogPath)
	accessLog.SetIPAnonymize(cfg.Engine.IPAnonymize)

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

	var path string
	if len(cfgPath) > 0 {
		path = cfgPath[0]
	}
	bdb, err := bansdb.Open("")
	if err != nil {
		log.Logger().Warn("edge: ouverture bansdb échouée, fallback mémoire", "err", err)
	}
	s := &Server{
		cfg:             cfg,
		cfgPath:         path,
		log:             log,
		accessLog:       accessLog,
		table:           &router.Table{},
		certStore:       edgetls.NewCertStore(),
		snippetStore:    router.NewSnippetStore(),
		providerStore:   router.NewAuthProviderStore(),
		profileStore:    router.NewIPProfileStore(),
		banStore:        router.NewBanStore(),
		bansDB:          bdb,
		cache:           edgecache.New(cachePath, secret),
		tcpPorts:        make(map[string]interface{ Stop() }),
		tracingShutdown: tracingShutdown,
		activeTracing:   cfg.Engine.TracingEndpoint,
		nodeStore:       edgeagent.NewNodeStore(),
		tunnelManager:   tunnel.New(log.Logger()),
	}
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
	s.wafEngine = waf.NewEngine(nil, log.Logger())
	s.accessLog.SetWAFExtractor(func(r *http.Request) []string {
		matches := waf.MatchesFromContext(r.Context())
		if len(matches) == 0 {
			return nil
		}
		seen := make(map[string]bool, len(matches))
		cats := make([]string, 0, len(matches))
		for _, m := range matches {
			if !seen[m.Category] {
				seen[m.Category] = true
				cats = append(cats, m.Category)
			}
		}
		return cats
	})
	s.wafEngine.SetBanCallback(waf.BanCallback(s.threatBanCallback()))
	log.Logger().Info("waf: moteur prêt — activer par route (label goproxify.waf=detect|block ou snippet)")
	s.accessLog.SetThreatExtractor(func(r *http.Request) string {
		return threat.SignalFromContext(r.Context())
	})
	s.portal = portal.NewService(log.Logger())

	// Token store local — source de vérité pour l'auth de l'API interne.
	tokensPath := "/etc/goproxify/edge-tokens.db"
	ts, err := edgetokens.Open(tokensPath)
	if err != nil {
		return nil, fmt.Errorf("token store: %w", err)
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
	s.wsHub = edgews.NewHub(os.Getenv("GPX_PAIRING_SECRET"), log.Logger())
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
	s.portal.SetAuthProviders(s.providerStore)

	// Access logs + system logs → Admin (Prism / Logs) via WS dès qu'un Admin est connecté.
	// Convention : status>0 = access HTTP ; status=0 = système (slog passerelle).
	shipLogs := func(batch []edgelog.ShipEntry) {
		payload := make([]edgews.LogEntryPayload, len(batch))
		for i, e := range batch {
			payload[i] = edgews.LogEntryPayload{
				Ts:        e.Ts,
				Level:     e.Level,
				Component: e.Component,
				NodeName:  e.NodeName,
				Domain:    e.Domain,
				Method:    e.Method,
				Path:      e.Path,
				Status:    e.Status,
				IP:        e.IP,
				RealIP:    e.RealIP,
				LatencyMs: e.LatencyMs,
				Bytes:     e.Bytes,
				Message:   e.Message,
				Referrer:  e.Referrer,
			}
		}
		msg, err := edgews.NewMessage(0, edgews.TypeAccessLog, payload)
		if err != nil {
			return
		}
		s.wsHub.BroadcastToAdmins(msg)
	}
	s.accessLog.SetNodeName(cfg.Identity.NodeName)
	s.accessLog.SetForwarder(shipLogs)
	s.log.SetNodeName(cfg.Identity.NodeName)
	s.log.SetForwarder(shipLogs)
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

	// Cluster Raft (optionnel)
	if cfg.Cluster.Enabled {
		nodeID := cfg.Cluster.NodeID
		if nodeID == "" {
			nodeID = cfg.Identity.NodeName
		}
		raftPort := cfg.Cluster.RaftPort
		if raftPort == 0 {
			raftPort = 8002
		}
		grp := cluster.NewGroup(cluster.Config{
			NodeID:    nodeID,
			GroupName: cfg.Cluster.GroupName,
			Peers:     cfg.Cluster.Peers,
			RaftPort:  raftPort,
			ApplyFunc: func(entry raft.LogEntry) {
				s.applyClusterCommand(entry)
			},
		}, log.Logger())
		s.clusterGroup = grp
	}
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

	// Cluster Raft
	if s.clusterGroup != nil {
		if err := s.clusterGroup.Start(ctx); err != nil {
			s.log.Warn("cluster: démarrage échoué (non bloquant)", "err", err)
		}
	}

	// Heartbeat passerelle → Admin via WebSocket
	go s.wsHeartbeatLoop(ctx)

	// Marquage offline des Agents inactifs
	go s.agentOfflineLoop(ctx)

	// Mise à jour périodique du cache
	go s.autosaveLoop(ctx)

	// Sync pools discovery depuis les passerelles pairs (LB cross-passerelle)
	s.startPeerSyncLoop(ctx)

	// Restauration des profils comportementaux WAF depuis le snapshot disque.
	s.wafEngine.LoadSnapshot("/etc/goproxify/waf-behavior.json")

	// Moteur de détection automatique des menaces.
	s.threatEngine = threat.New(s.log.Logger(), s.threatBanCallback())
	s.threatEngine.Start(ctx)

	// Moteur Fail2Ban — autonome, lit les access logs, bans locaux.
	s.f2bEngine = edgef2b.New()
	s.f2bEngine.UpdateConfig(edgef2b.LoadConfig(""))
	s.f2bEngine.OnBan = s.onF2BBan
	s.accessLog.SetF2BTap(s.f2bEngine.Feed)
	s.f2bEngine.Start(ctx)

	// Bouncer CrowdSec — autonome, sync LAPI, bans locaux.
	s.crowdSecBouncer = edgecrowdsec.New(s.log.Logger())
	s.crowdSecBouncer.UpdateConfig(edgecrowdsec.LoadConfig(""))
	s.crowdSecBouncer.OnBansChanged = s.onCrowdSecBansChanged
	s.crowdSecBouncer.OnDecisions = s.onCrowdSecDecisions
	s.crowdSecBouncer.Start(ctx)

	// Moteur de règles automatiques — autonome, évalue règles poussées par Admin.
	s.rulesEngine = edgere.New(s.log.Logger(), edgere.Deps{
		GetRecentBanCount:   s.recentBanCount,
		GetRepeatBanIP:      s.repeatBanIP,
		GetF2BLastActivity:  func() time.Time { return s.f2bEngine.LastBan() },
		GetCrowdSecLastSync: func() time.Time { return s.crowdSecBouncer.LastSync() },
		GetProxyErrorRate:   s.proxyErrorRate,
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
	if s.clusterGroup != nil {
		s.clusterGroup.Stop()
	}
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
	if s.bansDB != nil {
		_ = s.bansDB.Close()
	}
	// Sauvegarde des profils comportementaux WAF à l'arrêt.
	if err := s.wafEngine.SaveSnapshot("/etc/goproxify/waf-behavior.json"); err != nil {
		s.log.Warn("waf: sauvegarde snapshot échouée", "err", err)
	}
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

// refreshSentinelWhitelists relit toutes les routes de la table et met à jour la whitelist du moteur.
func (s *Server) refreshSentinelWhitelists() {
	if s.threatEngine == nil {
		return
	}
	s.threatEngine.MergeRouteWhitelists(collectSentinelWhitelists(s.table.All()))
}

// collectSentinelWhitelists agrège les entrées sentinel_whitelist de toutes les routes.
func collectSentinelWhitelists(routes []*router.Route) []string {
	var out []string
	for _, r := range routes {
		out = append(out, r.SentinelWhitelist...)
	}
	return out
}


// applySnapshot charge toutes les ressources d'un snapshot en mémoire.
func (s *Server) applySnapshot(snap *edgecache.Snapshot) {
	if snap.Routes != nil {
		s.table.Replace(snap.Routes) //nolint:errcheck
		s.health.StartChecksFromRoutes(snap.Routes)
		if s.threatEngine != nil {
			s.threatEngine.MergeRouteWhitelists(collectSentinelWhitelists(snap.Routes))
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
	go func() {
		if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.Error("http server", "err", err)
		}
	}()
	return nil
}

func (s *Server) startHTTPS() error {
	if s.cfg.Network.HTTPSPort == 0 {
		s.cfg.Network.HTTPSPort = 443
	}
	addr := fmt.Sprintf("%s:%d", s.cfg.Network.BindAddress, s.cfg.Network.HTTPSPort)
	tlsCfg := &tls.Config{
		GetCertificate: s.certStore.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1"},
		MinVersion:     tls.VersionTLS12,
	}
	// Raw TCP listener : le peek SNI doit voir le ClientHello brut AVANT que Go TLS
	// ne consomme le handshake. On wrappera chaque connexion en tls.Server() après.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("écoute TCP %s : %w", addr, err)
	}

	sniLn := &sniListener{inner: ln, table: s.table, log: s.log.Logger(), tlsCfg: tlsCfg}

	rh, r, w, idle := s.serverTimeouts()
	s.httpsSrv = &http.Server{
		Handler:           tracing.Middleware(requestIDMiddleware(s.accessLog.Middleware(s.httpMux()))),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: rh,
		ReadTimeout:       r,
		WriteTimeout:      w,
		IdleTimeout:       idle,
		MaxHeaderBytes:    s.cfg.MaxHeaderBytes(),
		ConnState: func(conn net.Conn, state http.ConnState) {
			if state == http.StateClosed || state == http.StateHijacked {
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
		sni, peeked, err := edgetls.PeekSNI(conn)
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
		tlsConn := tls.Server(peeked, l.tlsCfg)
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

