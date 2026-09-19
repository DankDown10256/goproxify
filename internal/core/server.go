// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package core

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
	coreagent "github.com/vincamok/goproxify/internal/core/agent"
	corecache "github.com/vincamok/goproxify/internal/core/cache"
	"github.com/vincamok/goproxify/internal/core/cluster"
	coref2b "github.com/vincamok/goproxify/internal/core/fail2ban"
	corecrowdsec "github.com/vincamok/goproxify/internal/core/crowdsec"
	"github.com/vincamok/goproxify/internal/core/errorpages"
	"github.com/vincamok/goproxify/internal/core/geoip"
	corelog "github.com/vincamok/goproxify/internal/core/logger"
	"github.com/vincamok/goproxify/internal/core/middleware"
	"github.com/vincamok/goproxify/internal/core/portal"
	"github.com/vincamok/goproxify/internal/core/metrics"
	"github.com/vincamok/goproxify/internal/core/proxy"
	"github.com/vincamok/goproxify/internal/core/proxypipeline"
	"github.com/vincamok/goproxify/internal/core/proxystore"
	corequic "github.com/vincamok/goproxify/internal/core/quic"
	"github.com/vincamok/goproxify/internal/core/raft"
	"github.com/vincamok/goproxify/internal/core/router"
	coretls "github.com/vincamok/goproxify/internal/core/tls"
	coretokens "github.com/vincamok/goproxify/internal/core/tokens"
	"github.com/vincamok/goproxify/internal/core/tracing"
	"github.com/vincamok/goproxify/internal/core/waf"
	"github.com/vincamok/goproxify/internal/core/threat"
	corews "github.com/vincamok/goproxify/internal/core/ws"
	"github.com/vincamok/goproxify/internal/nodeident"
)

// Server est le Data Plane — reverse proxy HTTP/TLS/TCP/UDP.
type Server struct {
	cfg       *config.CoreConfig
	cfgPath   string // chemin de core.json — utilisé pour persister les timeouts
	log       *corelog.DynamicLogger
	accessLog *corelog.AccessLogger

	table         *router.Table
	certStore     *coretls.CertStore
	snippetStore  *router.SnippetStore
	providerStore *router.AuthProviderStore
	profileStore  *router.IPProfileStore
	banStore      *router.BanStore
	threatEngine  *threat.Engine
	f2bEngine       *coref2b.Engine
	crowdSecBouncer *corecrowdsec.Bouncer

	// Bans threat : merge avec les bans Admin sans écraser.
	bansMu            sync.Mutex
	lastBanList       []*router.RuntimeBan
	pendingThreatBans []*router.RuntimeBan
	cache         *corecache.Store
	proxyStore    *proxystore.Store
	proxyPipe     *proxypipeline.Pipeline
	health        *proxy.BackendHealth
	metrics       *proxy.AgentMetricsStore
	peers         *proxy.PeerRegistry
	nodeStore     *coreagent.NodeStore
	tokenStore    *coretokens.Store

	httpSrv  *http.Server
	httpsSrv *http.Server
	intSrv   *http.Server // API interne :8000
	quicSrv  *corequic.QUICServer
	wsHub    *corews.Hub
	portal   *portal.Service

	tracingShutdown func(context.Context) error
	clusterGroup    *cluster.Group
	wafEngine       *waf.Engine

	mu            sync.Mutex
	tcpPorts      map[string]interface{ Stop() }
	pushedTracing string // endpoint OTLP poussé par Admin (utilisé si cfg.Engine.TracingEndpoint est vide)

	// saveCache debounce (revue P1 #8)
	saveCacheMu    sync.Mutex
	saveCacheTimer *time.Timer

	// adminToken : token HMAC partagé par tous les Cores (reçu via TypeAdminToken).
	// Utilisé pour relayer les routes agent aux Cores délégués.
	adminTokenMu sync.RWMutex
	adminToken   string

	// Cache de chaînes dispatch invalidé par génération (revue P1 #3)
	dispatchGen      atomic.Uint64
	dispatchHandlers sync.Map // key -> *cachedDispatch
}


// New initialise le Core à partir de la configuration.
func New(cfg *config.CoreConfig, cfgPath ...string) (*Server, error) {
	cfg.Identity.NodeName = nodeident.Resolve("core")

	log := corelog.New(cfg.Engine.LogLevel, cfg.Engine.LogFormat, cfg.Engine.SystemLogPath)
	accessLog := corelog.NewAccessLogger(cfg.Engine.AccessLogPath)

	secret := corecache.ResolveSecret(cfg.ControlPlane.AuthToken)
	cachePath := "/etc/goproxify/core-cache.gpx"
	if p := os.Getenv("GPX_CORE_CACHE_PATH"); p != "" {
		cachePath = p
	}
	_ = os.MkdirAll(filepath.Dir(cachePath), 0755)
	// GeoIP : dossier volume + téléchargement auto de GeoLite2-Country si absent.
	_ = os.MkdirAll("/etc/goproxify/geoip", 0755)
	if err := geoip.Bootstrap(cfg.GeoIP.AutoDownload, cfg.GeoIP.DBPath, cfg.GeoIP.DBURL, log.Logger()); err != nil {
		log.Logger().Warn("geoip: bootstrap base MaxMind échoué", "err", err)
	}

	tracingShutdown, err := tracing.Init(cfg.Engine.TracingEndpoint)
	if err != nil {
		// Non bloquant : le tracing est optionnel
		tracingShutdown = func(context.Context) error { return nil }
	}

	var path string
	if len(cfgPath) > 0 {
		path = cfgPath[0]
	}
	s := &Server{
		cfg:             cfg,
		cfgPath:         path,
		log:             log,
		accessLog:       accessLog,
		table:           &router.Table{},
		certStore:       coretls.NewCertStore(),
		snippetStore:    router.NewSnippetStore(),
		providerStore:   router.NewAuthProviderStore(),
		profileStore:    router.NewIPProfileStore(),
		banStore:        router.NewBanStore(),
		cache:           corecache.New(cachePath, secret),
		tcpPorts:        make(map[string]interface{ Stop() }),
		tracingShutdown: tracingShutdown,
		nodeStore:       coreagent.NewNodeStore(),
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
		payload := corews.BackendDownPayload{URL: url, NodeName: cfg.Identity.NodeName}
		if msg, err := corews.NewMessage(0, corews.TypeBackendDown, payload); err == nil {
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
	tokensPath := "/etc/goproxify/core-tokens.db"
	ts, err := coretokens.Open(tokensPath)
	if err != nil {
		return nil, fmt.Errorf("token store: %w", err)
	}
	// Bootstrap : si aucun token n'existe, créer le token initial depuis la config.
	if cfg.ControlPlane.AuthToken != "" {
		nodeName := cfg.Identity.NodeName
		if nodeName == "" {
			nodeName = "admin"
		}
		if bErr := ts.Bootstrap("admin-"+nodeName, cfg.ControlPlane.AuthToken, coretokens.RoleAdmin); bErr != nil {
			log.Logger().Warn("token store: bootstrap", "err", bErr)
		}
	}
	s.tokenStore = ts

	// Amorçage via GPX_CORE_TOKEN : injecter le token dans le store local.
	if prebuilt := os.Getenv("GPX_CORE_TOKEN"); prebuilt != "" {
		nodeName := cfg.Identity.NodeName
		if nodeName == "" {
			nodeName = "core-1"
		}
		_ = ts.EnsureToken("admin-"+nodeName, prebuilt, coretokens.RoleAdmin)
		log.Logger().Info("core: token pré-configuré (GPX_CORE_TOKEN)")
	}

	// Hub WebSocket plan de contrôle — HMAC partagé via GPX_PAIRING_SECRET
	s.wsHub = corews.NewHub(os.Getenv("GPX_PAIRING_SECRET"), log.Logger())
	s.wsHub.SetAdminMessageHandler(s.handleWSAdminMessage)
	s.wsHub.SetAgentMessageHandler(s.handleWSAgentMessage)
	s.portal.SetShellBroker(portal.NewShellBroker(s.wsHub))
	s.portal.SetInviteCompletedHook(func(userID string) {
		msg, err := corews.NewMessage(0, corews.TypePortalInviteCompleted, map[string]string{"user_id": userID})
		if err != nil {
			return
		}
		s.wsHub.BroadcastToAdmins(msg)
	})
	s.portal.SetEmailOTPSender(func(email, code string) error {
		if s.wsHub.ConnectedAdmins() == 0 {
			return fmt.Errorf("aucun Admin connecté")
		}
		msg, err := corews.NewMessage(0, corews.TypePortalSendEmailOTP, map[string]string{
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
		msg, err := corews.NewMessage(0, corews.TypePortalAudit, payload)
		if err != nil {
			return
		}
		s.wsHub.BroadcastToAdmins(msg)
	})
	s.portal.SetAuthProviders(s.providerStore)

	// Access logs + system logs → Admin (Prism / Logs) via WS dès qu'un Admin est connecté.
	// Convention : status>0 = access HTTP ; status=0 = système (slog Core).
	shipLogs := func(batch []corelog.ShipEntry) {
		payload := make([]corews.LogEntryPayload, len(batch))
		for i, e := range batch {
			payload[i] = corews.LogEntryPayload{
				Ts:        e.Ts,
				Level:     e.Level,
				Component: e.Component,
				NodeName:  e.NodeName,
				Domain:    e.Domain,
				Method:    e.Method,
				Path:      e.Path,
				Status:    e.Status,
				IP:        e.IP,
				LatencyMs: e.LatencyMs,
				Bytes:     e.Bytes,
				Message:   e.Message,
				Referrer:  e.Referrer,
			}
		}
		msg, err := corews.NewMessage(0, corews.TypeAccessLog, payload)
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
		if msg, err := corews.NewMessage(0, corews.TypeAgentPending, corews.AgentPendingPayload{
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

// Start démarre le Core.
func (s *Server) Start(ctx context.Context) error {
	if err := s.loadFromAdminOrCache(ctx); err != nil {
		return err
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

	// Heartbeat Core → Admin via WebSocket
	go s.wsHeartbeatLoop(ctx)

	// Marquage offline des Agents inactifs
	go s.agentOfflineLoop(ctx)

	// Mise à jour périodique du cache
	go s.autosaveLoop(ctx)

	// Sync pools discovery depuis les Cores pairs (LB cross-Core)
	s.startPeerSyncLoop(ctx)

	// Restauration des profils comportementaux WAF depuis le snapshot disque.
	s.wafEngine.LoadSnapshot("/etc/goproxify/waf-behavior.json")

	// Moteur de détection automatique des menaces.
	s.threatEngine = threat.New(s.log.Logger(), s.threatBanCallback())
	s.threatEngine.Start(ctx)

	// Moteur Fail2Ban — autonome, lit les access logs, bans locaux.
	s.f2bEngine = coref2b.New()
	s.f2bEngine.UpdateConfig(coref2b.LoadConfig(""))
	s.f2bEngine.OnBan = s.onF2BBan
	s.accessLog.SetF2BTap(s.f2bEngine.Feed)
	s.f2bEngine.Start(ctx)

	// Bouncer CrowdSec — autonome, sync LAPI, bans locaux.
	s.crowdSecBouncer = corecrowdsec.New(s.log.Logger())
	s.crowdSecBouncer.UpdateConfig(corecrowdsec.LoadConfig(""))
	s.crowdSecBouncer.OnBansChanged = s.onCrowdSecBansChanged
	s.crowdSecBouncer.OnDecisions = s.onCrowdSecDecisions
	s.crowdSecBouncer.Start(ctx)

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

	s.log.Info("core démarré",
		"http", fmt.Sprintf(":%d", s.cfg.Network.HTTPPort),
		"https", fmt.Sprintf(":%d", s.cfg.Network.HTTPSPort),
		"internal", fmt.Sprintf(":%d", s.cfg.Network.InternalAPIPort),
	)
	return nil
}

// Stop arrête proprement le Core.
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

	// Cache local en priorité — le Core est autonome.
	// Fallbacks : ancien auth_token + clé vide (compose historiquement sans auth_token).
	snap, err := s.cache.LoadWithFallbacks(s.cfg.ControlPlane.AuthToken, "")
	if err != nil {
		s.log.Warn("core: cache local illisible — démarrage sans config (Admin doit resynchroniser)",
			"err", err)
		return nil
	}
	if snap != nil {
		s.applySnapshot(snap)
		s.log.Info("core: démarrage depuis cache local",
			"saved_at", snap.SavedAt.Format(time.RFC3339),
			"routes", len(snap.Routes),
			"certs", len(snap.Certs),
			"snippets", len(snap.Snippets),
			"providers", len(snap.AuthProviders),
			"ip_profiles", s.profileStore.Len(),
			"bans", s.banStore.Len(),
		)
	} else {
		s.log.Info("core: aucun cache local — démarrage sans config, en attente du full_sync Admin",
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
func (s *Server) applySnapshot(snap *corecache.Snapshot) {
	if snap.Routes != nil {
		s.table.Replace(snap.Routes) //nolint:errcheck
		s.health.StartChecksFromRoutes(snap.Routes)
		if s.threatEngine != nil {
			s.threatEngine.MergeRouteWhitelists(collectSentinelWhitelists(snap.Routes))
		}
	}
	for _, c := range snap.Certs {
		if err := s.certStore.StorePEM(c.Name, c.CertPEM, c.KeyPEM); err != nil {
			s.log.Warn("core: cert cache invalide", "name", c.Name, "err", err)
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
		sni, peeked, err := coretls.PeekSNI(conn)
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
	s.quicSrv = &corequic.QUICServer{}
	return s.quicSrv.Start(s.cfg, tracing.Middleware(requestIDMiddleware(s.accessLog.Middleware(s.httpMux()))), s.certStore)
}

