// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
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

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vincamok/goproxify/internal/agent/telemetry"
	"github.com/vincamok/goproxify/internal/buildinfo"
	"github.com/vincamok/goproxify/internal/config"
	coreagent "github.com/vincamok/goproxify/internal/core/agent"
	"github.com/vincamok/goproxify/internal/core/bans"
	corecache "github.com/vincamok/goproxify/internal/core/cache"
	"github.com/vincamok/goproxify/internal/core/cluster"
	"github.com/vincamok/goproxify/internal/core/errorpages"
	"github.com/vincamok/goproxify/internal/core/geoip"
	"github.com/vincamok/goproxify/internal/core/ipprofiles"
	corelog "github.com/vincamok/goproxify/internal/core/logger"
	"github.com/vincamok/goproxify/internal/core/metrics"
	"github.com/vincamok/goproxify/internal/core/middleware"
	"github.com/vincamok/goproxify/internal/core/portal"
	"github.com/vincamok/goproxify/internal/core/proxy"
	corequic "github.com/vincamok/goproxify/internal/core/quic"
	"github.com/vincamok/goproxify/internal/core/raft"
	"github.com/vincamok/goproxify/internal/core/router"
	coretls "github.com/vincamok/goproxify/internal/core/tls"
	coretokens "github.com/vincamok/goproxify/internal/core/tokens"
	"github.com/vincamok/goproxify/internal/core/tracing"
	"github.com/vincamok/goproxify/internal/core/waf"
	corews "github.com/vincamok/goproxify/internal/core/ws"
	"github.com/vincamok/goproxify/internal/nodeident"
)

// Server est le Data Plane — reverse proxy HTTP/TLS/TCP/UDP.
type Server struct {
	cfg       *config.CoreConfig
	log       *corelog.DynamicLogger
	accessLog *corelog.AccessLogger

	table         *router.Table
	certStore     *coretls.CertStore
	snippetStore  *router.SnippetStore
	providerStore *router.AuthProviderStore
	profileStore  *router.IPProfileStore
	banStore      *router.BanStore
	cache         *corecache.Store
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

	// Cache de chaînes dispatch invalidé par génération (revue P1 #3)
	dispatchGen      atomic.Uint64
	dispatchHandlers sync.Map // key -> *cachedDispatch
}

type cachedDispatch struct {
	gen uint64
	h   http.Handler
}

// New initialise le Core à partir de la configuration.
func New(cfg *config.CoreConfig) (*Server, error) {
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

	s := &Server{
		cfg:             cfg,
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
	s.metrics = proxy.NewAgentMetricsStore()
	s.peers = proxy.NewPeerRegistry()
	s.wafEngine = waf.NewEngine(nil, log.Logger())
	log.Logger().Info("waf: moteur prêt — activer par route (label goproxify.waf=detect|block ou snippet)")
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
	s.wsHub.SetJoinTokenUsedCallback(func(joinToken string) {
		if s.tokenStore == nil {
			return
		}
		if err := s.tokenStore.RevokeByRaw(joinToken); err != nil {
			s.log.Debug("ws/agent: révocation JOIN_TOKEN locale", "err", err)
		} else {
			s.log.Info("ws/agent: JOIN_TOKEN consommé et révoqué dans le store local")
		}
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
		return nil
	}

	s.log.Info("core: aucun cache local — démarrage sans config, en attente du full_sync Admin",
		"ip_profiles", s.profileStore.Len(),
		"bans", s.banStore.Len(),
	)
	return nil
}

// applySnapshot charge toutes les ressources d'un snapshot en mémoire.
func (s *Server) applySnapshot(snap *corecache.Snapshot) {
	if snap.Routes != nil {
		s.table.Replace(snap.Routes) //nolint:errcheck
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

func (s *Server) startHTTP() error {
	if s.cfg.Network.HTTPPort == 0 {
		s.cfg.Network.HTTPPort = 80
	}
	addr := fmt.Sprintf("%s:%d", s.cfg.Network.BindAddress, s.cfg.Network.HTTPPort)
	s.httpSrv = &http.Server{
		Addr:    addr,
		Handler: tracing.Middleware(requestIDMiddleware(s.accessLog.Middleware(s.httpMux()))),
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

	s.httpsSrv = &http.Server{
		Handler:   tracing.Middleware(requestIDMiddleware(s.accessLog.Middleware(s.httpMux()))),
		TLSConfig: tlsCfg,
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
		// Connexion normale : wrapper en TLS pour que http.Server gère HTTP/2 via ALPN.
		return tls.Server(peeked, l.tlsCfg), nil
	}
}

func (l *sniListener) Close() error   { return l.inner.Close() }
func (l *sniListener) Addr() net.Addr { return l.inner.Addr() }

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

// --- Mux HTTP ------------------------------------------------------------

func (s *Server) httpMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.dispatch)
	mux.Handle("/metrics", promhttp.Handler())
	return mux
}

// serveDefaultError écrit la page d'erreur par défaut Goproxify (sans contexte de route).
func serveDefaultError(w http.ResponseWriter, r *http.Request, status int) {
	html := errorpages.Render(status, r.Host, r.Header.Get("X-Request-ID"), r.Header.Get("Accept-Language"))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	w.Write([]byte(html)) //nolint:errcheck
}

// serveErrorPageAsset sert /_goproxify/error-pages/{id}/{filename} depuis le volume Core.
func (s *Server) serveErrorPageAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, errorpages.PublicPathPref)
	parts := strings.SplitN(rest, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.NotFound(w, r)
		return
	}
	content, ct, ok := errorpages.DefaultStore().GetAsset(parts[0], parts[1])
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(content) //nolint:errcheck
	}
}

func (s *Server) handlePushErrorPages(w http.ResponseWriter, r *http.Request) {
	var tpls []errorpages.Template
	if err := json.NewDecoder(r.Body).Decode(&tpls); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := errorpages.DefaultStore().ReplaceAll(tpls); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.log.Info("error pages mises à jour", "count", len(tpls))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) dispatch(w http.ResponseWriter, r *http.Request) {
	// Assets des pages d'erreur custom (images, CSS…) — avant le routage par host.
	if strings.HasPrefix(r.URL.Path, errorpages.PublicPathPref) {
		s.serveErrorPageAsset(w, r)
		return
	}

	host := r.Host
	// Enlever le port si présent
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Vérification globale des profils IP (deny lists) avant le routage.
	// Utilise CF-Connecting-IP / X-Forwarded-For si disponible (Cloudflare, reverse proxy).
	remoteIP := corelog.RealIP(r)
	if blocked, reason := s.profileStore.CheckBlocked(remoteIP); blocked {
		s.log.Warn("ip bloquée par profil", "ip", remoteIP, "profile", reason)
		serveDefaultError(w, r, http.StatusForbidden)
		return
	}
	// Bans Fail2Ban / CrowdSec / natifs — les profils allow (et IPs privées) passent outre.
	if !s.profileStore.IsAllowed(remoteIP) {
		if blocked, reason := s.banStore.CheckBlocked(remoteIP); blocked {
			s.log.Warn("ip bloquée par ban", "ip", remoteIP, "reason", reason)
			serveDefaultError(w, r, http.StatusForbidden)
			return
		}
	}

	route, ok := s.table.ByHost(host)
	if !ok {
		serveDefaultError(w, r, http.StatusNotFound)
		return
	}

	// Résoudre les snippets et le fournisseur d'auth avant de construire la chaîne.
	route = router.ResolveSnippets(route, s.snippetStore)
	route = router.ResolveAuthProvider(route, s.providerStore)

	locPath := ""
	if loc := router.MatchLocation(route, r.URL.Path); loc != nil {
		locPath = loc.Path
		route = router.MergeLocation(route, loc)
	}

	h := s.handlerForRoute(route, locPath)

	// Métriques
	start := time.Now()
	rw := &statusCapture{ResponseWriter: w}
	h.ServeHTTP(rw, r)
	metrics.Core.RequestsTotal.WithLabelValues(host, r.Method, fmt.Sprintf("%d", rw.status)).Inc()
	metrics.Core.RequestDuration.WithLabelValues(host).Observe(time.Since(start).Seconds())
}

func (s *Server) invalidateDispatchCache() {
	s.dispatchGen.Add(1)
}

func (s *Server) handlerForRoute(route *router.Route, locPath string) http.Handler {
	gen := s.dispatchGen.Load()
	key := route.ID + "\x00" + locPath
	if v, ok := s.dispatchHandlers.Load(key); ok {
		if c := v.(*cachedDispatch); c.gen == gen {
			return c.h
		}
	}

	h := http.Handler(proxy.NewHandler(route, s.health, s.metrics, s.peers, s.log.Logger()))
	if route.CachePath != "" {
		h = proxy.New(route.CachePath).Middleware(h)
	}
	h = middleware.SSOAuth(route.SSO)(h)
	h = middleware.JWTValidation(route.JWT)(h)
	h = middleware.MTLSValidation(route.MTLS)(h)
	h = middleware.CORS(route.CORS)(h)
	h = middleware.SecurityHeaders(route.Headers)(h)
	var geoIPMW func(http.Handler) http.Handler
	if route.GeoIP != nil {
		dbPath := route.GeoIP.DBPath
		if dbPath == "" && s.cfg != nil {
			dbPath = s.cfg.GeoIP.DBPath
		}
		if dbPath == "" {
			dbPath = geoip.DefaultDBPath
		}
		geoIPMW = middleware.GeoIP(dbPath, route.GeoIP.Mode, route.GeoIP.Countries)
	} else {
		geoIPMW = middleware.GeoIP("", "", nil)
	}
	h = geoIPMW(h)
	h = middleware.IPFilter(route.IPFilter)(h)
	h = middleware.RateLimit(route.RateLimit)(h)
	h = middleware.BotProtection(route.Bot)(h)
	if route.WAF != nil && route.WAF.Enabled {
		h = s.wafEngine.Middleware(route.WAF, h)
	}

	s.dispatchHandlers.Store(key, &cachedDispatch{gen: gen, h: h})
	return h
}

type statusCapture struct {
	http.ResponseWriter
	status int
}

func (sc *statusCapture) WriteHeader(code int) {
	sc.status = code
	sc.ResponseWriter.WriteHeader(code)
}

func (sc *statusCapture) Flush() {
	if f, ok := sc.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (sc *statusCapture) Unwrap() http.ResponseWriter { return sc.ResponseWriter }

func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if reqID == "" {
			reqID = newRequestID()
			r.Header.Set("X-Request-ID", reqID)
		}
		w.Header().Set("X-Request-ID", reqID)
		next.ServeHTTP(w, r)
	})
}

func newRequestID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("gpx-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// --- API interne :8000 ---------------------------------------------------

func (s *Server) startInternalAPI() error {
	if s.cfg.Network.InternalAPIPort == 0 {
		s.cfg.Network.InternalAPIPort = 8000
	}
	addr := fmt.Sprintf("%s:%d", s.cfg.Network.BindAddress, s.cfg.Network.InternalAPIPort)
	mux := http.NewServeMux()

	// WebSocket — plan de contrôle (pas soumis à authMiddleware)
	mux.HandleFunc("/ws/admin", s.wsHub.ServeAdmin)
	mux.HandleFunc("/ws/agent", s.wsHub.ServeAgent)

	mux.HandleFunc("POST /internal/v1/routes", s.handlePushRoutes)
	mux.HandleFunc("DELETE /internal/v1/routes/{id}", s.handleDeleteRoute)
	mux.HandleFunc("POST /internal/v1/delegations", s.handlePushDelegations)
	mux.HandleFunc("POST /internal/v1/certs", s.handlePushCerts)
	mux.HandleFunc("POST /internal/v1/snippets", s.handlePushSnippets)
	mux.HandleFunc("POST /internal/v1/error-pages", s.handlePushErrorPages)
	mux.HandleFunc("POST /internal/v1/auth-providers", s.handlePushAuthProviders)
	mux.HandleFunc("POST /internal/v1/ip-profiles", s.handlePushIPProfiles)
	mux.HandleFunc("POST /internal/v1/bans", s.handlePushBans)
	mux.HandleFunc("POST /internal/v1/settings", s.handlePushSettings)
	mux.HandleFunc("POST /internal/v1/portal", s.handlePushPortal)
	mux.HandleFunc("POST /internal/v1/cluster/peers", s.handlePushClusterPeers)
	mux.HandleFunc("POST /internal/v1/gateway/peers", s.handlePushGatewayPeers)
	mux.HandleFunc("POST /internal/v1/gateway/tunnel", s.handleGatewayTunnel)
	mux.HandleFunc("GET /internal/v1/lb/scores", s.handleLBScores)
	mux.HandleFunc("GET /internal/v1/health", s.handleInternalHealth)
	mux.HandleFunc("GET /internal/v1/backends/health", s.handleBackendsHealth)

	// Endpoints Agent → Core
	mux.HandleFunc("POST /internal/v1/agent/heartbeat", s.handleAgentHeartbeat)
	mux.HandleFunc("POST /internal/v1/agent/containers", s.handleAgentContainerStart)
	mux.HandleFunc("DELETE /internal/v1/agent/containers", s.handleAgentContainerStop)
	mux.HandleFunc("POST /internal/v1/agent/events", s.handleAgentEvent)
	mux.HandleFunc("POST /internal/v1/agent/logs", s.handleAgentLogs)

	// Relay Admin → Agent (Admin appelle Core, Core relaie à l'Agent)
	mux.HandleFunc("POST /internal/v1/agent/{name}/rescan", s.handleAgentRescanRelay)
	mux.HandleFunc("POST /internal/v1/agent/{name}/command", s.handleAgentCommandRelay)

	// Endpoints Core → Admin (lecture de l'état des nœuds et conteneurs)
	mux.HandleFunc("GET /internal/v1/nodes", s.handleListNodes)
	mux.HandleFunc("GET /internal/v1/node-events", s.handleListNodeEvents)
	mux.HandleFunc("GET /internal/v1/agent/containers", s.handleListAgentContainers)

	// Appairage local Agent → Core (protégé par GPX_PAIRING_SECRET, fail-closed)
	mux.HandleFunc("POST /internal/v1/pair", s.handleCorePair)

	s.intSrv = &http.Server{Addr: addr, Handler: s.authMiddleware(mux)}
	go func() {
		if err := s.intSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.Error("internal api", "err", err)
		}
	}()
	return nil
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Ces chemins ont leur propre authentification — ils bypassent le bearer token.
		// /ws/admin  : HMAC-SHA256 validé dans ServeAdmin (ValidateAdminHMAC)
		// /ws/agent  : join token ou agent_hmac validés dans ServeAgent
		// /internal/v1/pair : protégé par GPX_PAIRING_SECRET
		switch r.URL.Path {
		case "/ws/admin", "/ws/agent", "/internal/v1/pair":
			next.ServeHTTP(w, r)
			return
		}
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer == "" {
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}
		ok, err := s.tokenStore.Validate(bearer)
		if err != nil || !ok {
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handlePushDelegations reçoit les routes synthétiques de délégation inter-Core.
// Contrairement à handlePushRoutes (qui remplace tout), les délégations sont
// fusionnées : les routes normales restent intactes, seules les routes "deleg-*" sont mises à jour.
func (s *Server) handlePushDelegations(w http.ResponseWriter, r *http.Request) {
	var routes []*router.Route
	if err := json.NewDecoder(r.Body).Decode(&routes); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.applyDelegationRoutes(routes)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) applyDelegationRoutes(routes []*router.Route) {
	// Supprimer les anciennes routes de délégation, puis upsert les nouvelles
	for _, existing := range s.table.All() {
		if strings.HasPrefix(existing.ID, "deleg-") {
			s.table.Delete(existing.ID)
		}
	}
	for _, route := range routes {
		if route == nil {
			continue
		}
		// Délégation : respecter TLSPassthrough du payload (terminate vs passthrough).
		// TLSSkipVerify n'est plus forcé ici — uniquement si le payload Admin l'indique.
		if strings.HasPrefix(route.ID, "deleg-") {
			route.TLSEnabled = true
			if !route.TLSPassthrough {
				// Terminate : proxy HTTP(S) — SNI backend géré via hostSNITransport.
				if route.PreserveHost == nil {
					t := true
					route.PreserveHost = &t
				}
			}
			s.log.Info("délégation appliquée",
				"id", route.ID, "host", route.Host,
				"tls_passthrough", route.TLSPassthrough,
				"backend", backendURL(route),
			)
		}
		s.table.Upsert(route)
	}
	// Purge les proxies exacts locaux qui masqueraient un passthrough (délégation).
	removed := s.purgeRoutesShadowedByPassthrough()
	s.saveCache()
	s.log.Info("délégations mises à jour", "count", len(routes), "purged_conflicts", removed)
}

func backendURL(r *router.Route) string {
	if r == nil || len(r.Backends) == 0 {
		return ""
	}
	return r.Backends[0].URL
}

// purgeRoutesShadowedByPassthrough retire les routes non-passthrough dont le host
// est couvert par une délégation wildcard (deleg-* *.domaine).
func (s *Server) purgeRoutesShadowedByPassthrough() int {
	var patterns []string
	for _, r := range s.table.All() {
		// Critère principal : ID deleg-* (fiable même si le bool a été perdu en transit).
		if strings.HasPrefix(r.ID, "deleg-") && strings.HasPrefix(r.Host, "*.") {
			patterns = append(patterns, r.Host)
			continue
		}
		if r.TLSPassthrough && strings.HasPrefix(r.Host, "*.") {
			patterns = append(patterns, r.Host)
		}
	}
	if len(patterns) == 0 {
		return 0
	}
	removed := 0
	for _, r := range s.table.All() {
		if r.TLSPassthrough || strings.HasPrefix(r.ID, "deleg-") {
			continue
		}
		shadowed := false
		for _, p := range patterns {
			if router.HostCoveredByPattern(r.Host, p) {
				shadowed = true
				break
			}
			for _, a := range r.Aliases {
				if router.HostCoveredByPattern(a, p) {
					shadowed = true
					break
				}
			}
			if shadowed {
				break
			}
		}
		if shadowed {
			s.table.Delete(r.ID)
			removed++
			s.log.Info("route locale purgée (masquée par délégation passthrough)",
				"id", r.ID, "host", r.Host)
		}
	}
	return removed
}

func (s *Server) handlePushRoutes(w http.ResponseWriter, r *http.Request) {
	var routes []*router.Route
	if err := json.NewDecoder(r.Body).Decode(&routes); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Préserver les routes injectées par les agents (docker:*, k8s:*, deleg-*)
	// qui ne sont pas gérées par Admin et ne doivent pas être effacées.
	for _, rt := range s.table.All() {
		if isAgentRoute(rt.ID) {
			routes = append(routes, rt)
		}
	}
	if err := s.table.Replace(routes); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.ensurePortalPublicRoute()
	purged := s.purgeRoutesShadowedByPassthrough()
	metrics.Core.RouteCount.Set(float64(s.table.Len()))
	s.saveCache()
	s.log.Info("routes remplacées", "count", len(routes), "purged_conflicts", purged)
	w.WriteHeader(http.StatusNoContent)
}

func isAgentRoute(id string) bool {
	return id == portalPublicRouteID ||
		strings.HasPrefix(id, "docker:") ||
		strings.HasPrefix(id, "docker-host:") ||
		strings.HasPrefix(id, "k8s:") ||
		strings.HasPrefix(id, "deleg-")
}

func (s *Server) handlePushCerts(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Name    string `json:"name"`
		CertPEM []byte `json:"cert_pem"`
		KeyPEM  []byte `json:"key_pem"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.certStore.StorePEM(payload.Name, payload.CertPEM, payload.KeyPEM); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	metrics.Core.CertCount.Set(float64(s.certStore.Len()))
	s.saveCache()
	s.log.Info("certificat mis à jour", "name", payload.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.table.Delete(id) {
		metrics.Core.RouteCount.Set(float64(s.table.Len()))
		s.saveCache()
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePushSnippets(w http.ResponseWriter, r *http.Request) {
	var snippets []*router.Snippet
	if err := json.NewDecoder(r.Body).Decode(&snippets); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.snippetStore.Replace(snippets)
	s.saveCache()
	s.log.Info("snippets mis à jour", "count", len(snippets))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePushAuthProviders(w http.ResponseWriter, r *http.Request) {
	var providers []*router.AuthProvider
	if err := json.NewDecoder(r.Body).Decode(&providers); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.providerStore.Replace(providers)
	s.saveCache()
	s.log.Info("fournisseurs auth mis à jour", "count", len(providers))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePushIPProfiles(w http.ResponseWriter, r *http.Request) {
	var profiles []*router.IPProfile
	if err := json.NewDecoder(r.Body).Decode(&profiles); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.applyIPProfiles(profiles)
	s.log.Info("profils IP mis à jour", "count", len(profiles))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePushBans(w http.ResponseWriter, r *http.Request) {
	var list []*router.RuntimeBan
	if err := json.NewDecoder(r.Body).Decode(&list); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.applyBans(list)
	s.log.Info("bans IP mis à jour", "count", len(list))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleInternalHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"status":         "ok",
		"routes":         s.table.Len(),
		"certs":          s.certStore.Len(),
		"snippets":       s.snippetStore.Len(),
		"auth_providers": s.providerStore.Len(),
	})
}

// handleBackendsHealth expose l'état runtime des backends (quarantaine / health checks).
func (s *Server) handleBackendsHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	backends := map[string]string{}
	if s.health != nil {
		backends = s.health.Snapshot()
	}
	json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
		"backends": backends,
	})
}

// pushedSettings est le payload runtime poussé par Admin (HTTP ou WS).
type pushedSettings struct {
	TracingEndpoint string `json:"tracing_endpoint"`
	LogLevel        string `json:"log_level"`
	LogFormat       string `json:"log_format"`
	AccessLogPath   string `json:"access_log_path"`
	AdminPublicURL  string `json:"admin_public_url"`
}

// handlePushSettings reçoit les paramètres runtime poussés par Admin.
// La config locale (cfg.Engine.*) a toujours la priorité sur chaque champ.
func (s *Server) handlePushSettings(w http.ResponseWriter, r *http.Request) {
	var payload pushedSettings
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.applyPushedSettings(payload)
	w.WriteHeader(http.StatusNoContent)
}

// applyPushedSettings applique les settings Admin (local wins sur engine.*).
func (s *Server) applyPushedSettings(payload pushedSettings) {
	// Tracing endpoint — local wins
	if s.cfg.Engine.TracingEndpoint == "" && payload.TracingEndpoint != "" {
		s.mu.Lock()
		s.pushedTracing = payload.TracingEndpoint
		s.mu.Unlock()
		s.log.Info("settings: tracing endpoint reçu depuis Admin", "endpoint", payload.TracingEndpoint)
	}

	// Log level + format — rechargement à chaud, local wins
	level := payload.LogLevel
	format := payload.LogFormat
	if s.cfg.Engine.LogLevel != "" {
		level = s.cfg.Engine.LogLevel
	}
	if s.cfg.Engine.LogFormat != "" {
		format = s.cfg.Engine.LogFormat
	}
	if level != "" || format != "" {
		s.log.Reload(level, format, s.cfg.Engine.SystemLogPath)
		s.log.Info("settings: logger rechargé depuis Admin", "level", level, "format", format)
	}

	// Access log path — rechargement à chaud, local wins
	if s.cfg.Engine.AccessLogPath == "" && payload.AccessLogPath != "" {
		s.accessLog.Reopen(payload.AccessLogPath)
		s.log.Info("settings: access log redirigé depuis Admin", "path", payload.AccessLogPath)
	}

	// URL publique Admin — pour les liens des pages d'erreur (sauf override env local).
	if os.Getenv("GPX_ADMIN_PUBLIC_URL") == "" && payload.AdminPublicURL != "" {
		prev := errorpages.GetAdminBaseURL()
		errorpages.SetAdminBaseURL(payload.AdminPublicURL)
		if prev != errorpages.GetAdminBaseURL() {
			s.log.Info("settings: URL publique Admin reçue", "url", errorpages.GetAdminBaseURL())
		}
	}
}

// portalPushPayload est le body Admin → Core pour le portail d'accès.
type portalPushPayload struct {
	Enabled              bool                   `json:"enabled"`
	SSHPort              int                    `json:"ssh_port"`
	HTTPPort             int                    `json:"http_port"`
	PublicHost           string                 `json:"public_host"`
	AuthProviderID       string                 `json:"auth_provider_id"`
	DBPath               string                 `json:"db_path"`
	AllowPersonalTargets bool                   `json:"allow_personal_targets"`
	Require2FA           bool                   `json:"require_2fa"`
	SessionTTLSec        int                    `json:"session_ttl_sec"`
	SessionMode          string                 `json:"session_mode"`
	Catalog              []portal.CatalogTarget `json:"catalog"`
	Users                []portal.SyncedUser    `json:"users"`
}

func (s *Server) handlePushPortal(w http.ResponseWriter, r *http.Request) {
	var payload portalPushPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.applyPortalPush(payload)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) applyPortalPush(payload portalPushPayload) {
	if s.portal == nil {
		return
	}
	cfg := portal.Config{
		Enabled:              payload.Enabled,
		SSHPort:              payload.SSHPort,
		HTTPPort:             payload.HTTPPort,
		PublicHost:           payload.PublicHost,
		AuthProviderID:       payload.AuthProviderID,
		DBPath:               payload.DBPath,
		AllowPersonalTargets: payload.AllowPersonalTargets,
		Require2FA:           payload.Require2FA,
		SessionTTLSec:        payload.SessionTTLSec,
		SessionMode:          payload.SessionMode,
	}
	if err := s.portal.ApplyConfig(cfg); err != nil {
		s.log.Error("portal: apply config", "err", err)
		return
	}
	if payload.Enabled {
		if payload.Catalog != nil {
			if err := s.portal.SetCatalog(payload.Catalog); err != nil {
				s.log.Warn("portal: catalog", "err", err)
			}
		}
		if payload.Users != nil {
			if err := s.portal.SyncUsers(payload.Users); err != nil {
				s.log.Warn("portal: users", "err", err)
			}
		}
	}
	s.ensurePortalPublicRoute()
}

// portalPublicRouteID identifie la route HTTP auto-injectée pour le portail.
const portalPublicRouteID = "gpx-portal-public"

// Client HTTP pour les relais Core→Agent (évite DefaultClient sans timeout — revue P1 #7).
var agentRelayHTTP = &http.Client{Timeout: 30 * time.Second}

// ensurePortalPublicRoute publie PublicHost → http://127.0.0.1:HTTPPort (TLS sur l'entrée).
// Rejoué après chaque Replace de routes pour survivre aux full-sync Admin.
func (s *Server) ensurePortalPublicRoute() {
	if s.portal == nil || s.table == nil {
		return
	}
	cfg := s.portal.Config()
	if !cfg.Enabled || strings.TrimSpace(cfg.PublicHost) == "" {
		if s.table.Delete(portalPublicRouteID) {
			s.log.Info("portal: route publique retirée")
		}
		return
	}
	cfg.Defaults()
	host := strings.TrimSpace(strings.ToLower(cfg.PublicHost))
	backend := fmt.Sprintf("http://127.0.0.1:%d", cfg.HTTPPort)
	s.table.Upsert(&router.Route{
		ID:         portalPublicRouteID,
		Host:       host,
		Type:       router.RouteHTTP,
		TLSEnabled: true,
		Backends:   []router.Backend{{URL: backend, Weight: 1}},
	})
	s.log.Info("portal: route HTTPS publique", "host", host, "backend", backend)
}

// handlePushClusterPeers reçoit la topologie Raft poussée par Admin.
// Si le Core a déjà une config Peers locale non vide, elle est ignorée (local wins).
func (s *Server) handlePushClusterPeers(w http.ResponseWriter, r *http.Request) {
	if len(s.cfg.Cluster.Peers) > 0 {
		// Config locale définie : Admin ne peut pas l'écraser.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	var peers map[string]string
	if err := json.NewDecoder(r.Body).Decode(&peers); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.clusterGroup != nil && len(peers) > 0 {
		s.clusterGroup.UpdatePeers(peers)
		s.log.Info("cluster: topologie reçue depuis Admin", "peers", len(peers))
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- Cache & reconnexion -------------------------------------------------

// applyIPProfiles met à jour le store en mémoire et persiste sur le volume Core.
func (s *Server) applyIPProfiles(profiles []*router.IPProfile) {
	s.profileStore.Replace(profiles)
	if err := ipprofiles.Save(ipprofiles.Dir(), profiles); err != nil {
		s.log.Warn("core: persistance profils IP échouée", "err", err)
		return
	}
	s.log.Debug("core: profils IP persistés", "count", len(profiles), "dir", ipprofiles.Dir())
}

func (s *Server) loadIPProfilesFromDisk() {
	profiles, err := ipprofiles.Load(ipprofiles.Dir())
	if err != nil {
		s.log.Warn("core: lecture profils IP disque échouée", "err", err)
		return
	}
	if profiles == nil {
		return
	}
	s.profileStore.Replace(profiles)
	s.log.Info("core: profils IP chargés depuis le disque",
		"count", len(profiles),
		"dir", ipprofiles.Dir(),
	)
}

// applyBans met à jour le store en mémoire et persiste sur le volume Core.
func (s *Server) applyBans(list []*router.RuntimeBan) {
	s.banStore.Replace(list)
	if err := bans.Save(bans.Dir(), list); err != nil {
		s.log.Warn("core: persistance bans échouée", "err", err)
		return
	}
	s.log.Debug("core: bans persistés", "count", len(list), "dir", bans.Dir())
}

func (s *Server) loadBansFromDisk() {
	list, err := bans.Load(bans.Dir())
	if err != nil {
		s.log.Warn("core: lecture bans disque échouée", "err", err)
		return
	}
	if list == nil {
		return
	}
	s.banStore.Replace(list)
	s.log.Info("core: bans chargés depuis le disque",
		"count", len(list),
		"dir", bans.Dir(),
	)
}

func (s *Server) saveCache() {
	// Invalider immédiatement les chaînes dispatch ; le flush disque est debouncé.
	s.invalidateDispatchCache()
	s.saveCacheMu.Lock()
	defer s.saveCacheMu.Unlock()
	if s.saveCacheTimer != nil {
		s.saveCacheTimer.Stop()
	}
	s.saveCacheTimer = time.AfterFunc(500*time.Millisecond, s.saveCacheNow)
}

func (s *Server) saveCacheNow() {
	snap := &corecache.Snapshot{
		SavedAt:       time.Now(),
		Routes:        s.table.All(),
		Certs:         s.certStore.AllPEMs(),
		Snippets:      s.snippetStore.All(),
		AuthProviders: s.providerStore.All(),
	}
	if err := s.cache.Save(snap); err != nil {
		s.log.Warn("core: sauvegarde cache échouée", "err", err)
		return
	}
	s.log.Debug("core: cache local sauvegardé",
		"routes", len(snap.Routes),
		"certs", len(snap.Certs),
	)
}

func (s *Server) autosaveLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.saveCacheNow()
		}
	}
}

func (s *Server) applyClusterCommand(entry raft.LogEntry) {
	cmd, err := cluster.DecodeCommand(entry)
	if err != nil {
		s.log.Warn("cluster: commande invalide", "err", err)
		return
	}
	switch cmd.Type {
	case cluster.CmdPushRoutes:
		var payload cluster.RoutesPayload
		if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
			s.log.Warn("cluster: décode routes", "err", err)
			return
		}
		var routes []*router.Route
		for _, raw := range payload.Routes {
			var r router.Route
			if err := json.Unmarshal(raw, &r); err == nil {
				routes = append(routes, &r)
			}
		}
		s.table.Replace(routes) //nolint:errcheck
		metrics.Core.RouteCount.Set(float64(s.table.Len()))
		s.saveCache()
		s.log.Info("cluster: routes appliquées", "count", len(routes))

	case cluster.CmdPushCert:
		var payload cluster.CertPayload
		if err := json.Unmarshal(cmd.Payload, &payload); err != nil {
			s.log.Warn("cluster: décode cert", "err", err)
			return
		}
		if err := s.certStore.StorePEM(payload.Name, payload.CertPEM, payload.KeyPEM); err != nil {
			s.log.Warn("cluster: store cert", "err", err)
			return
		}
		metrics.Core.CertCount.Set(float64(s.certStore.Len()))
		s.log.Info("cluster: certificat appliqué", "name", payload.Name)
	}
}

// wsHeartbeatLoop envoie un heartbeat Core → Admin toutes les 30 s via WebSocket.
func (s *Server) wsHeartbeatLoop(ctx context.Context) {
	send := func() {
		var cpuPct, memPct float64
		if prev, err := telemetry.ReadCPUStat(); err == nil {
			time.Sleep(200 * time.Millisecond)
			if cur, err := telemetry.ReadCPUStat(); err == nil {
				cpuPct = telemetry.CPUUsagePct(prev, cur)
			}
		}
		if mem, err := telemetry.ReadMemStat(); err == nil {
			memPct = mem.UsagePct()
		}
		msg, _ := corews.NewMessage(0, corews.TypeCoreHeartbeat, corews.CoreHeartbeatPayload{
			NodeName: s.cfg.Identity.NodeName,
			Role:     "core",
			Version:  buildinfo.Core,
			CPUPct:   cpuPct,
			MemPct:   memPct,
		})
		s.wsHub.BroadcastToAdmins(msg)
	}

	send()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			send()
		}
	}
}

// --- Handlers Agent → Core -----------------------------------------------

type agentHeartbeatPayload struct {
	NodeName          string   `json:"node_name"`
	Role              string   `json:"role"`
	Version           string   `json:"version"`
	Endpoint          string   `json:"endpoint"`
	CPUPCT            float64  `json:"cpu_pct"`
	MemPCT            float64  `json:"mem_pct"`
	ContainerRuntimes []string `json:"container_runtimes,omitempty"`
}

func (s *Server) handleAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	var hb agentHeartbeatPayload
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if hb.NodeName == "" {
		http.Error(w, "node_name requis", http.StatusBadRequest)
		return
	}
	s.nodeStore.Upsert(coreagent.NodeInfo{
		NodeName:          hb.NodeName,
		Role:              hb.Role,
		Version:           hb.Version,
		Endpoint:          hb.Endpoint,
		CPUPCT:            hb.CPUPCT,
		MemPCT:            hb.MemPCT,
		ContainerRuntimes: hb.ContainerRuntimes,
	})
	w.WriteHeader(http.StatusNoContent)
}

type agentContainerPayload struct {
	ID           string   `json:"id"`
	Host         string   `json:"host"`
	RouteType    string   `json:"route_type"`
	Backends     []string `json:"backends"`
	TLSEnabled   bool     `json:"tls_enabled"`
	Passthrough  bool     `json:"passthrough"`
	Source       string   `json:"source"`
	ContainerID  string   `json:"container_id"`
	AgentName    string   `json:"agent_name"`
	Role         string   `json:"role"`          // normal | canary | shadow
	CanaryWeight int      `json:"canary_weight"` // % trafic canary (défaut 10)

	// Sécurité (labels) — RawMessage pour accepter string legacy ou objet structuré.
	RateLimit      json.RawMessage `json:"rate_limit"`
	IPFilter       json.RawMessage `json:"ip_filter"`
	CORS           json.RawMessage `json:"cors"`
	GeoIP          json.RawMessage `json:"geo_ip"`
	SnippetIDs     []string        `json:"snippet_ids"`
	AuthProviderID string          `json:"auth_provider_id"`
	WAF            json.RawMessage `json:"waf"`
	Bot            json.RawMessage `json:"bot"`
}

func (s *Server) handleAgentContainerStart(w http.ResponseWriter, r *http.Request) {
	var p agentContainerPayload
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if p.Host == "" || len(p.Backends) == 0 {
		http.Error(w, "host et backends requis", http.StatusBadRequest)
		return
	}
	role := strings.ToLower(strings.TrimSpace(p.Role))
	if role == "" {
		role = "normal"
	}
	weight := p.CanaryWeight
	if weight <= 0 {
		weight = 10
	}
	if weight > 100 {
		weight = 100
	}
	backendURL := p.Backends[0]
	routeID := dockerHostRouteID(p.Host)

	var existing *router.Route
	if rt, ok := s.table.ByHost(p.Host); ok && isDockerDiscoveryRoute(rt) {
		existing = rt
	}

	applyMeta := func(rt *router.Route) {
		if rt.LB == "" || rt.LB == router.LBRoundRobin {
			rt.LB = router.LBAdaptive
		}
		if p.AgentName != "" {
			rt.AgentName = p.AgentName
		}
		if p.TLSEnabled {
			rt.TLSEnabled = true
		}
		if p.Passthrough {
			rt.TLSPassthrough = true
		}
		geoDB := ""
		if s.cfg != nil {
			geoDB = s.cfg.GeoIP.DBPath
		}
		applyDiscoverySecurity(rt, &p, geoDB)
		if rt.ID != routeID {
			if existing != nil && existing.ID != routeID {
				s.table.Delete(existing.ID)
			}
			rt.ID = routeID
		}
	}

	switch role {
	case "canary":
		rt := existing
		if rt == nil {
			rt = &router.Route{ID: routeID, Host: p.Host, LB: router.LBAdaptive}
		}
		// Hors pool LB : retirer ce conteneur s'il y était en normal
		rt.Backends = removeBackendByContainer(rt.Backends, p.ContainerID)
		rt.Canary = &router.CanaryConfig{
			Backend:     backendURL,
			Weight:      weight,
			ContainerID: p.ContainerID,
		}
		// Si ce conteneur était shadow, clear
		if rt.Shadow != nil && containerIDMatch(rt.Shadow.ContainerID, p.ContainerID) {
			rt.Shadow = nil
		}
		applyMeta(rt)
		s.table.Upsert(rt)
		metrics.Core.RouteCount.Set(float64(s.table.Len()))
		s.log.Info("agent: canary activé", "host", p.Host, "container", p.ContainerID, "weight", weight, "agent", p.AgentName)
		w.WriteHeader(http.StatusNoContent)
		return

	case "shadow":
		rt := existing
		if rt == nil {
			rt = &router.Route{ID: routeID, Host: p.Host, LB: router.LBAdaptive}
		}
		rt.Backends = removeBackendByContainer(rt.Backends, p.ContainerID)
		rt.Shadow = &router.ShadowConfig{
			Backend:     backendURL,
			ContainerID: p.ContainerID,
		}
		if rt.Canary != nil && containerIDMatch(rt.Canary.ContainerID, p.ContainerID) {
			rt.Canary = nil
		}
		applyMeta(rt)
		s.table.Upsert(rt)
		metrics.Core.RouteCount.Set(float64(s.table.Len()))
		s.log.Info("agent: shadow activé", "host", p.Host, "container", p.ContainerID, "agent", p.AgentName)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	// role normal (défaut) : pool backends
	backends := make([]router.Backend, 0, len(p.Backends))
	for _, u := range p.Backends {
		backends = append(backends, router.Backend{
			URL:         u,
			ContainerID: p.ContainerID,
			AgentName:   p.AgentName,
		})
	}
	if existing != nil {
		merged := mergeDiscoveryBackends(existing.Backends, backends)
		existing.Backends = merged
		// Re-label : ce conteneur n'est plus canary/shadow
		if existing.Canary != nil && containerIDMatch(existing.Canary.ContainerID, p.ContainerID) {
			existing.Canary = nil
		}
		if existing.Shadow != nil && containerIDMatch(existing.Shadow.ContainerID, p.ContainerID) {
			existing.Shadow = nil
		}
		applyMeta(existing)
		s.table.Upsert(existing)
		metrics.Core.RouteCount.Set(float64(s.table.Len()))
		s.log.Info("agent: backend ajouté au pool", "host", p.Host, "container", p.ContainerID, "backends", len(merged), "agent", p.AgentName)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	route := &router.Route{
		ID:             routeID,
		Host:           p.Host,
		Backends:       backends,
		TLSEnabled:     p.TLSEnabled,
		TLSPassthrough: p.Passthrough,
		AgentName:      p.AgentName,
		LB:             router.LBAdaptive,
	}
	applyMeta(route)
	s.table.Upsert(route)
	metrics.Core.RouteCount.Set(float64(s.table.Len()))
	s.log.Info("agent: route label ajoutée", "host", p.Host, "container", p.ContainerID, "agent", p.AgentName)
	w.WriteHeader(http.StatusNoContent)
}

func dockerHostRouteID(host string) string {
	return "docker-host:" + host
}

func isDockerDiscoveryRoute(r *router.Route) bool {
	if r == nil {
		return false
	}
	return strings.HasPrefix(r.ID, "docker:") || strings.HasPrefix(r.ID, "docker-host:")
}

func containerIDMatch(stored, incoming string) bool {
	if stored == "" || incoming == "" {
		return false
	}
	if stored == incoming {
		return true
	}
	short := incoming
	if len(short) > 12 {
		short = short[:12]
	}
	return strings.HasPrefix(stored, short) || strings.HasPrefix(incoming, stored)
}

func removeBackendByContainer(backends []router.Backend, containerID string) []router.Backend {
	if containerID == "" {
		return backends
	}
	out := make([]router.Backend, 0, len(backends))
	for _, b := range backends {
		if b.ContainerID != "" && containerIDMatch(b.ContainerID, containerID) {
			continue
		}
		out = append(out, b)
	}
	return out
}

func mergeDiscoveryBackends(existing, incoming []router.Backend) []router.Backend {
	out := append([]router.Backend(nil), existing...)
	for _, in := range incoming {
		replaced := false
		for i := range out {
			if in.ContainerID != "" && out[i].ContainerID == in.ContainerID {
				out[i] = in
				replaced = true
				break
			}
			if in.URL != "" && out[i].URL == in.URL {
				out[i] = in
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, in)
		}
	}
	return out
}

func (s *Server) handleAgentContainerStop(w http.ResponseWriter, r *http.Request) {
	var p struct {
		ContainerID string `json:"container_id"`
		Name        string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	shortID := p.ContainerID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	changed := false
	for _, rt := range s.table.All() {
		if !isDockerDiscoveryRoute(rt) {
			continue
		}
		// Ancien schéma : une route par conteneur
		prefix := "docker:" + shortID
		if rt.ID == prefix || strings.HasPrefix(rt.ID, prefix+":") {
			if s.table.Delete(rt.ID) {
				changed = true
			}
			continue
		}
		// Pool par host : retirer backend et/ou clear canary/shadow
		if !strings.HasPrefix(rt.ID, "docker-host:") {
			continue
		}
		kept := make([]router.Backend, 0, len(rt.Backends))
		removedBackend := false
		for _, b := range rt.Backends {
			if b.ContainerID != "" && (b.ContainerID == p.ContainerID || strings.HasPrefix(b.ContainerID, shortID)) {
				removedBackend = true
				continue
			}
			kept = append(kept, b)
		}
		clearedCanary := false
		if rt.Canary != nil && containerIDMatch(rt.Canary.ContainerID, p.ContainerID) {
			rt.Canary = nil
			clearedCanary = true
		}
		clearedShadow := false
		if rt.Shadow != nil && containerIDMatch(rt.Shadow.ContainerID, p.ContainerID) {
			rt.Shadow = nil
			clearedShadow = true
		}
		if !removedBackend && !clearedCanary && !clearedShadow {
			continue
		}
		rt.Backends = kept
		if len(kept) == 0 && rt.Canary == nil && rt.Shadow == nil {
			if s.table.Delete(rt.ID) {
				changed = true
			}
			continue
		}
		s.table.Upsert(rt)
		changed = true
	}
	if changed {
		metrics.Core.RouteCount.Set(float64(s.table.Len()))
		s.log.Info("agent: routes/backends label retirés", "container", p.Name)
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleListAgentContainers retourne les routes injectées par les Agents (préfixe docker: ou k8s:).
func (s *Server) handleListAgentContainers(w http.ResponseWriter, r *http.Request) {
	type containerRoute struct {
		ID           string         `json:"id"`
		Host         string         `json:"host"`
		Aliases      []string       `json:"aliases,omitempty"`
		Backends     []string       `json:"backends"`
		ContainerIDs []string       `json:"container_ids,omitempty"`
		TLS          bool           `json:"tls"`
		Source       string         `json:"source"`
		AgentName    string         `json:"agent_name,omitempty"`
		Config       map[string]any `json:"config,omitempty"`
	}
	filterAgent := r.URL.Query().Get("agent")
	all := s.table.All()
	result := make([]containerRoute, 0)
	for _, rt := range all {
		src := ""
		if strings.HasPrefix(rt.ID, "docker:") || strings.HasPrefix(rt.ID, "docker-host:") {
			src = "docker"
		} else if strings.HasPrefix(rt.ID, "k8s:") {
			src = "k8s"
		} else {
			continue
		}
		if filterAgent != "" && rt.AgentName != filterAgent {
			continue
		}
		backends := make([]string, 0, len(rt.Backends))
		containerIDs := make([]string, 0, len(rt.Backends))
		seenCID := map[string]struct{}{}
		for _, b := range rt.Backends {
			backends = append(backends, b.URL)
			if b.ContainerID == "" {
				continue
			}
			if _, ok := seenCID[b.ContainerID]; ok {
				continue
			}
			seenCID[b.ContainerID] = struct{}{}
			containerIDs = append(containerIDs, b.ContainerID)
		}
		if rt.Canary != nil && rt.Canary.ContainerID != "" {
			if _, ok := seenCID[rt.Canary.ContainerID]; !ok {
				containerIDs = append(containerIDs, rt.Canary.ContainerID)
			}
		}
		if rt.Shadow != nil && rt.Shadow.ContainerID != "" {
			if _, ok := seenCID[rt.Shadow.ContainerID]; !ok {
				containerIDs = append(containerIDs, rt.Shadow.ContainerID)
			}
		}
		result = append(result, containerRoute{
			ID:           rt.ID,
			Host:         rt.Host,
			Aliases:      append([]string(nil), rt.Aliases...),
			Backends:     backends,
			ContainerIDs: containerIDs,
			TLS:          rt.TLSEnabled || rt.TLSPassthrough,
			Source:       src,
			AgentName:    rt.AgentName,
			Config:       discoveryRouteConfig(rt),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result) //nolint:errcheck
}

// discoveryRouteConfig expose les champs utiles aux badges UI Trafic (même forme que config proxy).
// Le badge LB Adaptatif n'est exposé que lorsqu'il y a réellement un pool multi-backends.
func discoveryRouteConfig(rt *router.Route) map[string]any {
	if rt == nil {
		return nil
	}
	cfg := map[string]any{
		"tls_enabled":     rt.TLSEnabled,
		"tls_passthrough": rt.TLSPassthrough,
	}
	if len(rt.Backends) >= 2 {
		lb := rt.LB
		if lb == "" || lb == router.LBRoundRobin {
			lb = router.LBAdaptive
		}
		cfg["lb"] = lb
	}
	if rt.RateLimit != nil {
		cfg["rate_limit"] = rt.RateLimit
	}
	if rt.IPFilter != nil {
		cfg["ip_filter"] = rt.IPFilter
	}
	if rt.GeoIP != nil {
		cfg["geo_ip"] = rt.GeoIP
	}
	if rt.CORS != nil {
		cfg["cors"] = rt.CORS
	}
	if rt.WAF != nil {
		cfg["waf"] = rt.WAF
	}
	if rt.Bot != nil {
		cfg["bot"] = rt.Bot
	}
	if rt.JWT != nil {
		cfg["jwt"] = rt.JWT
	}
	if rt.MTLS != nil {
		cfg["mtls"] = rt.MTLS
	}
	if rt.SSO != nil {
		cfg["sso"] = rt.SSO
	}
	if rt.AuthProviderID != "" {
		cfg["auth_provider_id"] = rt.AuthProviderID
	}
	if len(rt.SnippetIDs) > 0 {
		cfg["snippet_ids"] = rt.SnippetIDs
	}
	if rt.CircuitBreaker != nil {
		cfg["circuit_breaker"] = rt.CircuitBreaker
	}
	if rt.Retry != nil {
		cfg["retry"] = rt.Retry
	}
	if rt.StickyCookie != "" {
		cfg["sticky_cookie"] = rt.StickyCookie
	}
	if rt.Canary != nil {
		cfg["canary"] = rt.Canary
	}
	if rt.Shadow != nil {
		cfg["shadow"] = rt.Shadow
	}
	if len(rt.Locations) > 0 {
		cfg["locations"] = rt.Locations
	}
	if rt.Logging != nil {
		cfg["logging"] = rt.Logging
	}
	return cfg
}

func (s *Server) handleAgentEvent(w http.ResponseWriter, r *http.Request) {
	var e struct {
		NodeName    string `json:"node_name"`
		ContainerID string `json:"container_id"`
		EventType   string `json:"event_type"`
		Detail      string `json:"detail"`
	}
	if err := json.NewDecoder(r.Body).Decode(&e); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ev := s.nodeStore.RecordEvent(coreagent.NodeEvent{
		NodeName:    e.NodeName,
		ContainerID: e.ContainerID,
		EventType:   e.EventType,
		Detail:      e.Detail,
	})
	// Relayer vers Admin pour persistance SQLite (historique UI)
	if payload, err := json.Marshal(ev); err == nil {
		s.wsHub.BroadcastToAdmins(corews.Message{Type: corews.TypeAgentEvent, Payload: payload})
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleAgentLogs(w http.ResponseWriter, r *http.Request) {
	// Relais transparent vers Admin (Prism / Logs) — pas de stockage local.
	var batch struct {
		ContainerID   string `json:"container_id"`
		ContainerName string `json:"container_name"`
		Entries       []struct {
			T    time.Time `json:"t"`
			Line string    `json:"line"`
		} `json:"entries"`
	}
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		http.Error(w, "JSON invalide", http.StatusBadRequest)
		return
	}
	if len(batch.Entries) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	payload := make([]corews.LogEntryPayload, 0, len(batch.Entries))
	for _, e := range batch.Entries {
		ts := e.T
		if ts.IsZero() {
			ts = time.Now().UTC()
		}
		payload = append(payload, corews.LogEntryPayload{
			Ts:        ts.Format(time.RFC3339Nano),
			Level:     "info",
			Component: "agent",
			NodeName:  s.cfg.Identity.NodeName,
			Domain:    batch.ContainerName,
			Message:   e.Line,
		})
	}
	msg, err := corews.NewMessage(0, corews.TypeAgentLog, payload)
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	s.wsHub.BroadcastToAdmins(msg)
	w.WriteHeader(http.StatusNoContent)
}

// handleCorePair émet un token Agent local sans passer par l'Admin.
// Protégé uniquement par GPX_PAIRING_SECRET (identique à Admin).
// Permet aux Agents sur des hôtes distants de s'appairer avec leur Core local.
func (s *Server) handleCorePair(w http.ResponseWriter, r *http.Request) {
	configuredSecret := os.Getenv("GPX_PAIRING_SECRET")
	var req struct {
		Secret   string `json:"secret"`
		NodeName string `json:"node_name"`
		Role     string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if configuredSecret == "" {
		http.Error(w, "pairing non configuré", http.StatusServiceUnavailable)
		return
	}
	if len(configuredSecret) != len(req.Secret) ||
		subtle.ConstantTimeCompare([]byte(configuredSecret), []byte(req.Secret)) != 1 {
		http.Error(w, "secret invalide", http.StatusForbidden)
		return
	}
	nodeName := req.NodeName
	if nodeName == "" {
		nodeName = "agent"
	}
	token, _, err := s.tokenStore.Create(nodeName, coretokens.RoleAgent, 0)
	if err != nil {
		s.log.Error("core: création token appairage agent", "err", err)
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	s.log.Info("core: appairage agent accepté", "node", nodeName)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"token": token}) //nolint:errcheck
}

// --- Endpoints lecture nœuds (Admin → Core) ------------------------------

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.nodeStore.All()) //nolint:errcheck
}

func (s *Server) handleListNodeEvents(w http.ResponseWriter, r *http.Request) {
	limit := 200
	nodeFilter := r.URL.Query().Get("node")
	w.Header().Set("Content-Type", "application/json")
	evs := s.nodeStore.Events(limit)
	if nodeFilter != "" {
		filtered := make([]coreagent.NodeEvent, 0, len(evs))
		for _, e := range evs {
			if e.NodeName == nodeFilter {
				filtered = append(filtered, e)
			}
		}
		evs = filtered
	}
	json.NewEncoder(w).Encode(evs) //nolint:errcheck
}

// agentOfflineLoop marque les Agents inactifs depuis plus de 90 s comme "offline".
// handleAgentRescanRelay relaie une commande rescan d'Admin vers l'Agent.
// Admin → Core (ce handler) → Agent (internal API).
// Le relay via Core est nécessaire car Admin est cross-machine et ne peut
// pas résoudre les endpoints Docker internes des agents.
func (s *Server) handleAgentRescanRelay(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	if s.wsHub.IsAgentConnected(name) {
		body, _ := json.Marshal(map[string]string{"action": "rescan"})
		msg, err := corews.NewMessage(0, corews.TypeRescan, json.RawMessage(body))
		if err != nil {
			http.Error(w, "erreur interne", http.StatusInternalServerError)
			return
		}
		if err := s.wsHub.SendToAgentByName(name, msg); err != nil {
			s.log.Warn("rescan relay: WS échoué", "agent", name, "err", err)
			http.Error(w, "agent injoignable", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	all := s.nodeStore.All()
	s.log.Info("rescan relay: recherche agent", "name", name, "nodestore_count", len(all))
	var agentEndpoint string
	for _, n := range all {
		s.log.Info("rescan relay: nœud connu", "node_name", n.NodeName, "endpoint", n.Endpoint, "status", n.Status)
		if n.NodeName == name && n.Endpoint != "" {
			agentEndpoint = n.Endpoint
			break
		}
	}
	if agentEndpoint == "" {
		s.log.Warn("rescan relay: agent introuvable dans nodestore", "name", name)
		http.Error(w, "agent introuvable ou endpoint inconnu", http.StatusNotFound)
		return
	}
	s.log.Info("rescan relay: forward vers agent", "name", name, "endpoint", agentEndpoint)

	body, _ := json.Marshal(map[string]string{"action": "rescan"})
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		agentEndpoint+"/internal/v1/command", bytes.NewReader(body))
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	setAgentInternalAuth(req)

	resp, err := agentRelayHTTP.Do(req)
	if err != nil {
		s.log.Warn("rescan relay: agent injoignable", "agent", name, "endpoint", agentEndpoint, "err", err)
		http.Error(w, "agent injoignable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
}

// handleAgentCommandRelay relaie une commande JSON arbitraire vers l'Agent.
func (s *Server) handleAgentCommandRelay(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "erreur lecture body", http.StatusBadRequest)
		return
	}

	// Priorité WS : l'agent connecté n'a pas besoin d'endpoint HTTP exposé.
	if s.wsHub.IsAgentConnected(name) {
		msgType := corews.TypeCommand
		var cmd map[string]string
		if json.Unmarshal(body, &cmd) == nil && cmd["action"] == "rescan" {
			msgType = corews.TypeRescan
		}
		msg, err := corews.NewMessage(0, msgType, json.RawMessage(body))
		if err != nil {
			http.Error(w, "erreur interne", http.StatusInternalServerError)
			return
		}
		if err := s.wsHub.SendToAgentByName(name, msg); err != nil {
			s.log.Warn("command relay: WS échoué", "agent", name, "err", err)
			http.Error(w, "agent injoignable", http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusAccepted)
		return
	}

	n, ok := s.nodeStore.Get(name)
	if !ok || n.Endpoint == "" {
		http.Error(w, "agent introuvable ou endpoint inconnu", http.StatusNotFound)
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		n.Endpoint+"/internal/v1/command", bytes.NewReader(body))
	if err != nil {
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	setAgentInternalAuth(req)
	resp, err := agentRelayHTTP.Do(req)
	if err != nil {
		s.log.Warn("command relay: agent injoignable", "agent", name, "endpoint", n.Endpoint, "err", err)
		http.Error(w, "agent injoignable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.WriteHeader(resp.StatusCode)
}

// setAgentInternalAuth pose le Bearer partagé (GPX_PAIRING_SECRET) pour l'API Agent :8001.
func setAgentInternalAuth(req *http.Request) {
	if secret := os.Getenv("GPX_PAIRING_SECRET"); secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
}

func (s *Server) agentOfflineLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.nodeStore.MarkOffline(90 * time.Second)
		}
	}
}

// --- Handlers WebSocket plan de contrôle ------------------------------------

// handleWSAdminMessage traite les messages reçus d'un Admin via WS.
// Les types de messages correspondent aux mêmes payloads que les endpoints HTTP.
func (s *Server) handleWSAdminMessage(connID string, msg corews.Message) error {
	switch msg.Type {
	case corews.TypePushRoutes:
		var routes []*router.Route
		if err := json.Unmarshal(msg.Payload, &routes); err != nil {
			return err
		}
		for _, rt := range s.table.All() {
			if isAgentRoute(rt.ID) {
				routes = append(routes, rt)
			}
		}
		if err := s.table.Replace(routes); err != nil {
			return err
		}
		s.ensurePortalPublicRoute()
		purged := s.purgeRoutesShadowedByPassthrough()
		metrics.Core.RouteCount.Set(float64(s.table.Len()))
		s.saveCache()
		s.log.Info("ws/admin: routes mises à jour", "count", len(routes), "purged_conflicts", purged)

	case corews.TypeDeleteRoute:
		var p struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return err
		}
		s.table.Delete(p.ID)
		s.saveCache()
		s.log.Info("ws/admin: route supprimée", "id", p.ID)

	case corews.TypePushCert:
		var cert struct {
			Name    string `json:"name"`
			CertPEM []byte `json:"cert_pem"`
			KeyPEM  []byte `json:"key_pem"`
		}
		if err := json.Unmarshal(msg.Payload, &cert); err != nil {
			return err
		}
		if err := s.certStore.StorePEM(cert.Name, cert.CertPEM, cert.KeyPEM); err != nil {
			return err
		}
		s.saveCache()
		s.log.Info("ws/admin: certificat poussé", "name", cert.Name)

	case corews.TypePushDelegations:
		var routes []*router.Route
		if err := json.Unmarshal(msg.Payload, &routes); err != nil {
			return err
		}
		s.applyDelegationRoutes(routes)

	case corews.TypePushSnippets:
		var snippets []*router.Snippet
		if err := json.Unmarshal(msg.Payload, &snippets); err != nil {
			return err
		}
		s.snippetStore.Replace(snippets)
		s.saveCache()

	case corews.TypePushAuthProviders:
		var providers []*router.AuthProvider
		if err := json.Unmarshal(msg.Payload, &providers); err != nil {
			return err
		}
		s.providerStore.Replace(providers)
		s.saveCache()

	case corews.TypePushIPProfiles:
		var profiles []*router.IPProfile
		if err := json.Unmarshal(msg.Payload, &profiles); err != nil {
			return err
		}
		s.applyIPProfiles(profiles)

	case corews.TypePushBans:
		var list []*router.RuntimeBan
		if err := json.Unmarshal(msg.Payload, &list); err != nil {
			return err
		}
		s.applyBans(list)
		s.log.Info("ws/admin: bans mis à jour", "count", len(list))

	case corews.TypePushSettings:
		var payload pushedSettings
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			return err
		}
		s.applyPushedSettings(payload)

	case corews.TypePushPortal:
		var payload portalPushPayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			return err
		}
		s.applyPortalPush(payload)

	case corews.TypePushErrorPages:
		var tpls []errorpages.Template
		if err := json.Unmarshal(msg.Payload, &tpls); err != nil {
			return err
		}
		if err := errorpages.DefaultStore().ReplaceAll(tpls); err != nil {
			s.log.Warn("ws/admin: error pages", "err", err)
			return err
		}
		s.log.Info("ws/admin: pages d'erreur mises à jour", "count", len(tpls))

	case corews.TypePushPortalTemplates:
		var tpls []portal.PageTemplate
		if err := json.Unmarshal(msg.Payload, &tpls); err != nil {
			return err
		}
		s.portal.ReplacePageTemplates(tpls)
		s.log.Info("ws/admin: templates Access mis à jour", "count", len(tpls))

	case corews.TypeFullSync:
		// full_sync contient routes + certs + snippets + providers dans un seul payload
		var fsync struct {
			Routes    []*router.Route        `json:"routes"`
			Snippets  []*router.Snippet      `json:"snippets"`
			Providers []*router.AuthProvider `json:"providers"`
			Profiles  []*router.IPProfile    `json:"ip_profiles"`
			Bans      []*router.RuntimeBan   `json:"bans"`
		}
		if err := json.Unmarshal(msg.Payload, &fsync); err != nil {
			return err
		}
		if fsync.Routes != nil {
			routes := fsync.Routes
			for _, rt := range s.table.All() {
				if isAgentRoute(rt.ID) {
					routes = append(routes, rt)
				}
			}
			_ = s.table.Replace(routes)
			s.ensurePortalPublicRoute()
			purged := s.purgeRoutesShadowedByPassthrough()
			metrics.Core.RouteCount.Set(float64(s.table.Len()))
			s.log.Info("ws/admin: full_sync routes", "count", len(routes), "purged_conflicts", purged)
		}
		if fsync.Snippets != nil {
			s.snippetStore.Replace(fsync.Snippets)
		}
		if fsync.Providers != nil {
			s.providerStore.Replace(fsync.Providers)
		}
		if fsync.Profiles != nil {
			s.applyIPProfiles(fsync.Profiles)
		}
		if fsync.Bans != nil {
			s.applyBans(fsync.Bans)
		}
		s.saveCache()
		s.log.Info("ws/admin: full_sync appliqué",
			"routes", len(fsync.Routes),
			"snippets", len(fsync.Snippets),
			"providers", len(fsync.Providers),
			"ip_profiles", len(fsync.Profiles),
			"bans", len(fsync.Bans),
		)

	case corews.TypeApproveAgent:
		var p corews.ApproveAgentPayload
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return err
		}
		return s.wsHub.ApproveAgent(p.AgentID)

	case corews.TypeRevokeAgent:
		var p corews.RevokeAgentPayload
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return err
		}
		return s.wsHub.RevokeAgent(p.AgentID)

	case corews.TypeAdminToken:
		var p corews.AdminTokenPayload
		if err := json.Unmarshal(msg.Payload, &p); err != nil {
			return err
		}
		if p.Token != "" {
			if err := s.tokenStore.EnsureToken("admin-ws", p.Token, coretokens.RoleAdmin); err != nil {
				s.log.Warn("ws/admin: enregistrement token Admin échoué", "err", err)
			} else {
				s.log.Debug("ws/admin: token Admin enregistré dans le store")
			}
		}

	case corews.TypePushGatewayPeers:
		return s.applyGatewayPeersWS(msg.Payload)

	default:
		s.log.Debug("ws/admin: message inconnu ignoré", "type", msg.Type)
	}
	return nil
}

// handleWSAgentMessage traite les messages reçus d'un Agent via WS.
func (s *Server) handleWSAgentMessage(connID string, msg corews.Message) error {
	switch msg.Type {
	case corews.TypeAgentHeartbeat:
		var hb agentHeartbeatPayload
		if err := json.Unmarshal(msg.Payload, &hb); err != nil {
			return err
		}
		if hb.NodeName == "" {
			hb.NodeName = connID
		}
		s.nodeStore.Upsert(coreagent.NodeInfo{
			NodeName:          hb.NodeName,
			Role:              "agent",
			Version:           hb.Version,
			Endpoint:          hb.Endpoint,
			CPUPCT:            hb.CPUPCT,
			MemPCT:            hb.MemPCT,
			ContainerRuntimes: hb.ContainerRuntimes,
		})
		if s.metrics != nil {
			s.metrics.UpdateHost(hb.Endpoint, hb.CPUPCT, hb.MemPCT)
		}

	case corews.TypeAgentContainers:
		// Même traitement que POST /internal/v1/agent/containers
		s.log.Debug("ws/agent: containers reçus", "agent", connID)

	case corews.TypeAgentMetrics:
		var mp corews.AgentMetricsPayload
		if err := json.Unmarshal(msg.Payload, &mp); err != nil {
			return err
		}
		if s.metrics != nil {
			s.metrics.UpdateFromMetrics(mp)
		}
		s.log.Debug("ws/agent: métriques reçues", "agent", connID, "containers", len(mp.Containers))

	case corews.TypeAgentEvent:
		var ev coreagent.NodeEvent
		if err := json.Unmarshal(msg.Payload, &ev); err == nil {
			if ev.NodeName == "" {
				ev.NodeName = connID
			}
			recorded := s.nodeStore.RecordEvent(ev)
			if payload, err := json.Marshal(recorded); err == nil {
				s.wsHub.BroadcastToAdmins(corews.Message{Type: corews.TypeAgentEvent, Payload: payload})
			}
		}

	case corews.TypeAgentLog:
		// Relayer les logs vers l'Admin via WS
		relayMsg := corews.Message{Type: corews.TypeAgentLog, Payload: msg.Payload}
		s.wsHub.BroadcastToAdmins(relayMsg)

	case corews.TypeShellData, corews.TypeShellReady, corews.TypeShellClose, corews.TypeShellError:
		if s.portal != nil {
			if b := s.portal.ShellBroker(); b != nil {
				b.HandleAgentMessage(msg.Type, msg.Payload)
			}
		}

	default:
		s.log.Debug("ws/agent: message inconnu ignoré", "type", msg.Type)
	}
	return nil
}
