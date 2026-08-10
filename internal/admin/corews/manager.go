// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package corews

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/delegation"
	"github.com/vincamok/goproxify/internal/admin/mailer"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/core/errorpages"
	"github.com/vincamok/goproxify/internal/core/router"
	coretls "github.com/vincamok/goproxify/internal/core/tls"
	coreWS "github.com/vincamok/goproxify/internal/core/ws"
)

// Settings regroupe les paramètres runtime poussés aux Cores.
type Settings struct {
	TracingEndpoint string `json:"tracing_endpoint,omitempty"`
	LogLevel        string `json:"log_level,omitempty"`
	LogFormat       string `json:"log_format,omitempty"`
	AccessLogPath   string `json:"access_log_path,omitempty"`
	// AdminPublicURL : origine publique de l'UI Admin (liens pages d'erreur → Logs).
	AdminPublicURL string `json:"admin_public_url,omitempty"`
}

// coreEntry associe un coreID (token UUID) à son client WS et ses métadonnées.
type coreEntry struct {
	id       string // UUID dans la table tokens
	nodeName string
	rbacRole string
	client   *Client
}

// Manager gère un client WS persistant par Core enregistré.
// Il remplace corepush.Pusher comme mécanisme de synchronisation Admin→Core.
type Manager struct {
	mu         sync.RWMutex
	cores      map[string]*coreEntry // key = coreID (UUID)
	hmacSecret string
	db         *sql.DB
	log        *slog.Logger

	settingsMu     sync.RWMutex
	settings       Settings // derniers paramètres poussés (utilisés au full_sync)
	onAgentPending func(id, name, version string)
	onLogBatch     func(entries []coreWS.LogEntryPayload)
}

// NewManager crée un Manager WS Admin→Core.
func NewManager(hmacSecret string, db *sql.DB, log *slog.Logger) *Manager {
	return &Manager{
		cores:      make(map[string]*coreEntry),
		hmacSecret: hmacSecret,
		db:         db,
		log:        log,
	}
}

// LoadFromDB charge les Cores existants depuis la table tokens et crée un client WS pour chacun.
// Ignore les nœuds déjà connectés (même id ou même node_name) pour cohabiter avec ConnectFromEnv.
func (m *Manager) LoadFromDB(ctx context.Context) error {
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, node_name, node_endpoint, COALESCE(rbac_role, 'admin')
		 FROM tokens
		 WHERE role='core' AND revoked=0 AND node_endpoint != ''
		   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`)
	if err != nil {
		return err
	}
	defer rows.Close()

	n := 0
	for rows.Next() {
		var id, nodeName, endpoint, rbacRole string
		if err := rows.Scan(&id, &nodeName, &endpoint, &rbacRole); err != nil {
			continue
		}
		if m.hasCore(id, nodeName) {
			continue
		}
		m.Register(id, nodeName, endpoint, rbacRole)
		n++
	}
	if n > 0 {
		m.log.Info("corews: Cores supplémentaires chargés depuis DB", "count", n)
	}
	return nil
}

func (m *Manager) hasCore(coreID, nodeName string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.cores[coreID]; ok {
		return true
	}
	for _, e := range m.cores {
		if e.nodeName == nodeName {
			return true
		}
	}
	return false
}

// Register crée ou met à jour un client WS pour un Core.
// Un seul client par node_name : les doublons (autre UUID) sont fermés.
func (m *Manager) Register(coreID, nodeName, endpoint, rbacRole string) {
	if endpoint == "" {
		m.log.Warn("corews: Register ignoré — endpoint vide", "core", nodeName, "id", coreID)
		return
	}
	if coreID == "" {
		m.log.Warn("corews: Register ignoré — id vide", "core", nodeName)
		return
	}
	// Interdit d'utiliser node_name comme id (scopes liés à l'UUID token).
	if nodeName != "" && coreID == nodeName {
		m.log.Error("corews: Register refusé — id=node_name (scopes introuvables)", "core", nodeName)
		return
	}

	m.mu.Lock()
	var stale []*coreEntry
	for id, e := range m.cores {
		if id != coreID && e.nodeName != "" && e.nodeName == nodeName {
			stale = append(stale, e)
			delete(m.cores, id)
		}
	}
	existing, ok := m.cores[coreID]
	if ok {
		existing.nodeName = nodeName
		existing.rbacRole = rbacRole
		m.mu.Unlock()
		for _, s := range stale {
			s.client.Close()
			m.log.Info("corews: doublon retiré", "core", nodeName, "id", s.id)
		}
		existing.client.Close()
		entry := &coreEntry{
			id:       coreID,
			nodeName: nodeName,
			rbacRole: rbacRole,
		}
		entry.client = m.newClient(coreID, endpoint, entry)
		m.mu.Lock()
		m.cores[coreID] = entry
		m.mu.Unlock()
		m.log.Info("corews: client mis à jour", "core", nodeName, "id", coreID, "endpoint", endpoint)
		return
	}
	entry := &coreEntry{
		id:       coreID,
		nodeName: nodeName,
		rbacRole: rbacRole,
	}
	entry.client = m.newClient(coreID, endpoint, entry)
	m.cores[coreID] = entry
	m.mu.Unlock()
	for _, s := range stale {
		s.client.Close()
		m.log.Info("corews: doublon retiré", "core", nodeName, "id", s.id)
	}
	m.log.Info("corews: client enregistré", "core", nodeName, "id", coreID, "endpoint", endpoint)
}

// Unregister ferme le client WS d'un Core et le supprime du Manager.
func (m *Manager) Unregister(coreID string) {
	m.mu.Lock()
	entry, ok := m.cores[coreID]
	if ok {
		delete(m.cores, coreID)
	}
	m.mu.Unlock()
	if ok {
		entry.client.Close()
		m.log.Info("corews: client retiré", "id", coreID)
	}
}

// Close ferme tous les clients WS.
func (m *Manager) Close() {
	m.mu.Lock()
	entries := make([]*coreEntry, 0, len(m.cores))
	for _, e := range m.cores {
		entries = append(entries, e)
	}
	m.cores = make(map[string]*coreEntry)
	m.mu.Unlock()
	for _, e := range entries {
		e.client.Close()
	}
}

// ConnectFromEnv connecte Admin → Core principal via GPX_IDENTITY_CORE_NODE_NAME,
// puis charge tous les autres Cores déclarés (tokens avec node_endpoint) pour le multi-Core.
func (m *Manager) ConnectFromEnv(ctx context.Context) {
	coreName := os.Getenv("GPX_IDENTITY_CORE_NODE_NAME")
	if coreName == "" {
		m.log.Info("corews: GPX_IDENTITY_CORE_NODE_NAME non défini — connexion via tokens DB uniquement")
	} else {
		endpoint := "http://" + coreName + ":8000"
		id, role, err := m.ensureCoreToken(ctx, coreName, endpoint)
		if err != nil {
			m.log.Error("corews: impossible de préparer le token Core — pas de connexion env",
				"core", coreName, "err", err)
		} else {
			m.Register(id, coreName, endpoint, role)
			m.log.Info("corews: connexion Core depuis env", "core", coreName, "id", id, "endpoint", endpoint)
		}
	}
	if err := m.LoadFromDB(ctx); err != nil {
		m.log.Warn("corews: chargement Cores depuis DB", "err", err)
	}
}

// ensureCoreToken vérifie qu'un token valide existe dans la table tokens pour ce Core.
// Préfère un token qui a déjà des périmètres. Crée un nouveau token sinon.
// Retourne l'ID et le rbac_role du token.
func (m *Manager) ensureCoreToken(ctx context.Context, nodeName, endpoint string) (id, rbacRole string, err error) {
	acc := rbac.ResolveCoreAccess(ctx, m.db, nodeName)
	if acc.TokenID != "" {
		_, _ = m.db.ExecContext(ctx,
			`UPDATE tokens SET node_endpoint=? WHERE id=?`, endpoint, acc.TokenID)
		return acc.TokenID, acc.Role, nil
	}
	id = uuid.New().String()
	tok := auth.GenerateToken("core", nodeName)
	stored, hash := auth.PrepareNodeTokenForStore(tok)
	_, err = m.db.ExecContext(ctx,
		`INSERT INTO tokens (id, token, token_hash, role, rbac_role, node_name, node_endpoint)
		 VALUES (?, ?, ?, 'core', 'admin', ?, ?)`,
		id, stored, hash, nodeName, endpoint)
	return id, "admin", err
}

// SetAgentPendingHandler enregistre un callback appelé quand Core signale un Agent en attente.
func (m *Manager) SetAgentPendingHandler(fn func(id, name, version string)) {
	m.onAgentPending = fn
}

// SetLogBatchHandler enregistre le callback d'ingestion des logs Core/Agent (Prism / Logs).
func (m *Manager) SetLogBatchHandler(fn func(entries []coreWS.LogEntryPayload)) {
	m.onLogBatch = fn
}

// HandleCoreMessage dispatche les messages reçus du Core.
func (m *Manager) HandleCoreMessage(msg coreWS.Message) {
	switch msg.Type {
	case coreWS.TypeCoreHeartbeat:
		m.handleCoreHeartbeat(msg)
	case coreWS.TypeAgentPending:
		var p coreWS.AgentPendingPayload
		if err := json.Unmarshal(msg.Payload, &p); err == nil && m.onAgentPending != nil {
			m.onAgentPending(p.AgentID, p.AgentName, p.Version)
		}
	case coreWS.TypeAccessLog, coreWS.TypeAgentLog:
		m.handleLogBatch(msg.Payload)
	case coreWS.TypeAgentEvent:
		m.handleAgentEvent(msg.Payload)
	case coreWS.TypePortalInviteCompleted:
		var p struct {
			UserID string `json:"user_id"`
		}
		if err := json.Unmarshal(msg.Payload, &p); err == nil {
			api.MarkPortalInviteCompleted(m.db, p.UserID)
		}
	case coreWS.TypePortalSendEmailOTP:
		m.handlePortalSendEmailOTP(msg.Payload)
	case coreWS.TypePortalAudit:
		m.handlePortalAudit(msg.Payload)
	}
}

func (m *Manager) handlePortalAudit(raw json.RawMessage) {
	if m.db == nil || len(raw) == 0 {
		return
	}
	var p struct {
		Ts       string `json:"ts"`
		Actor    string `json:"actor"`
		TargetID string `json:"target_id"`
		Facade   string `json:"facade"`
		Success  bool   `json:"success"`
		Detail   string `json:"detail"`
		NodeName string `json:"node_name"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		return
	}
	api.InsertPortalAudit(m.db, p.NodeName, p.Ts, p.Actor, p.TargetID, p.Facade, p.Success, p.Detail)
}

func (m *Manager) handlePortalSendEmailOTP(raw json.RawMessage) {
	if m.db == nil || len(raw) == 0 {
		return
	}
	var p struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := json.Unmarshal(raw, &p); err != nil || p.Email == "" || p.Code == "" {
		return
	}
	subj := "Code GoProxify Access"
	body := "Votre code de vérification Access : " + p.Code + "\n\nValable 10 minutes.\n"
	if err := mailer.Send(m.db, p.Email, subj, body); err != nil {
		m.log.Warn("corews: portal email OTP", "email", p.Email, "err", err)
	}
}

func (m *Manager) handleAgentEvent(raw json.RawMessage) {
	if len(raw) == 0 || m.db == nil {
		return
	}
	var e struct {
		NodeName    string `json:"node_name"`
		ContainerID string `json:"container_id"`
		EventType   string `json:"event_type"`
		Detail      string `json:"detail"`
	}
	if err := json.Unmarshal(raw, &e); err != nil || e.EventType == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := m.db.ExecContext(ctx,
		`INSERT INTO node_events (node_name, container_id, event_type, detail) VALUES (?, ?, ?, ?)`,
		e.NodeName, e.ContainerID, e.EventType, e.Detail,
	); err != nil {
		m.log.Debug("corews: insert node_event", "err", err)
	}
}

func (m *Manager) handleLogBatch(raw json.RawMessage) {
	if m.onLogBatch == nil || len(raw) == 0 {
		return
	}
	var entries []coreWS.LogEntryPayload
	if err := json.Unmarshal(raw, &entries); err != nil {
		m.log.Debug("corews: batch logs non reconnu", "err", err)
		return
	}
	if len(entries) == 0 {
		return
	}
	m.onLogBatch(entries)
}

func (m *Manager) handleCoreHeartbeat(msg coreWS.Message) {
	var hb coreWS.CoreHeartbeatPayload
	if err := json.Unmarshal(msg.Payload, &hb); err != nil {
		m.log.Warn("corews: heartbeat Core invalide", "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := m.db.ExecContext(ctx, `
		INSERT INTO nodes (id, node_name, role, status, version, endpoint, cpu_pct, mem_pct, last_seen_at)
		VALUES (?, ?, 'core', 'online', ?, '', ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			status='online', version=excluded.version,
			cpu_pct=excluded.cpu_pct, mem_pct=excluded.mem_pct,
			last_seen_at=excluded.last_seen_at`,
		hb.NodeName, hb.NodeName, hb.Version, hb.CPUPct, hb.MemPct)
	if err != nil {
		m.log.Warn("corews: upsert heartbeat Core", "err", err)
	}
}

// newClient crée un Client WS pour un Core donné.
func (m *Manager) newClient(coreID, endpoint string, entry *coreEntry) *Client {
	return NewClient(coreID, endpoint, m.hmacSecret, func(ctx context.Context) error {
		m.settingsMu.RLock()
		s := m.settings
		m.settingsMu.RUnlock()
		m.pushAllToEntry(ctx, entry, s)
		m.pushAdminToken(ctx, entry)
		return nil
	}, func(msg coreWS.Message) {
		if msg.Type == coreWS.TypeAccessLog || msg.Type == coreWS.TypeAgentLog {
			msg.Payload = stampLogBatchNodeName(msg.Payload, entry.nodeName)
		}
		m.HandleCoreMessage(msg)
	}, m.log)
}

// stampLogBatchNodeName injecte node_name sur chaque entrée si absent (filtre Logs par Core).
func stampLogBatchNodeName(raw json.RawMessage, nodeName string) json.RawMessage {
	if nodeName == "" || len(raw) == 0 {
		return raw
	}
	var entries []coreWS.LogEntryPayload
	if err := json.Unmarshal(raw, &entries); err != nil || len(entries) == 0 {
		return raw
	}
	changed := false
	for i := range entries {
		if entries[i].NodeName == "" {
			entries[i].NodeName = nodeName
			changed = true
		}
	}
	if !changed {
		return raw
	}
	b, err := json.Marshal(entries)
	if err != nil {
		return raw
	}
	return b
}

// pushAdminToken envoie à Core le token HTTP qu'Admin utilisera pour ses appels REST internes.
// Core l'enregistre dans son tokenStore (RoleAdmin) afin de valider les requêtes Admin→Core.
func (m *Manager) pushAdminToken(ctx context.Context, entry *coreEntry) {
	var tok string
	if err := m.db.QueryRowContext(ctx,
		`SELECT token FROM tokens WHERE id=? AND revoked=0`, entry.id).Scan(&tok); err != nil || tok == "" {
		// Fallback node_name si l'entrée pointe encore vers un id obsolète.
		_ = m.db.QueryRowContext(ctx,
			`SELECT token FROM tokens
			 WHERE role='core' AND node_name=? AND revoked=0 AND node_endpoint != ''
			   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
			 ORDER BY created_at DESC
			 LIMIT 1`, entry.nodeName).Scan(&tok)
	}
	if tok == "" {
		return
	}
	tok = auth.PlainNodeToken(tok)
	msg, err := coreWS.NewMessage(0, coreWS.TypeAdminToken, coreWS.AdminTokenPayload{Token: tok})
	if err != nil {
		return
	}
	entry.client.Send(msg)
}

// allEntries retourne une copie sûre des entrées courantes.
func (m *Manager) allEntries() []*coreEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entries := make([]*coreEntry, 0, len(m.cores))
	for _, e := range m.cores {
		entries = append(entries, e)
	}
	return entries
}

// --- Interfaces compatibles corepush.Pusher ---

// PushRoutes envoie les routes filtrées par RBAC à tous les Cores.
// Bloque jusqu'à la fin des envois.
func (m *Manager) PushRoutes(ctx context.Context) {
	allRoutes, err := m.loadRoutes(ctx)
	if err != nil {
		m.log.Error("corews/manager: lecture routes", "err", err)
		return
	}
	bindings := m.loadDelegationBindings(ctx)
	entries := m.allEntries()
	var wg sync.WaitGroup
	for _, e := range entries {
		e := e
		wg.Add(1)
		go func() {
			defer wg.Done()
			acc := rbac.LoadCoreAccess(ctx, m.db, e.id, e.nodeName)
			filtered := rbac.FilterRoutesByScopes(acc.Role, acc.Scopes, allRoutes)
			before := len(filtered)
			filtered = delegation.FilterRoutesForCore(e.id, e.nodeName, filtered, bindings)
			if err := e.client.PushJSON(coreWS.TypePushRoutes, filtered); err != nil {
				m.log.Warn("corews/manager: push routes", "core", e.nodeName, "err", err)
				return
			}
			m.log.Info("corews/manager: routes poussées", "core", e.nodeName, "count", len(filtered),
				"filtered_out", before-len(filtered), "scopes", len(acc.Scopes), "token", acc.TokenID)
		}()
	}
	wg.Wait()
	go m.PushGatewayPeers(ctx)
}

// DeleteRoute supprime immédiatement une route sur tous les Cores.
func (m *Manager) DeleteRoute(ctx context.Context, id string) {
	payload := map[string]string{"id": id}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(coreWS.TypeDeleteRoute, payload); err != nil {
				m.log.Warn("corews/manager: delete route", "core", e.nodeName, "err", err)
			}
		}()
	}
}

// PushCert envoie un certificat déchiffré aux Cores dont le périmètre le couvre.
// Admin sans scope → tous les Cores (comportement par défaut).
func (m *Manager) PushCert(ctx context.Context, name string, certPEM, keyPEM []byte) {
	payload := map[string]any{
		"name":     name,
		"cert_pem": certPEM,
		"key_pem":  keyPEM,
	}
	for _, e := range m.allEntries() {
		e := e
		acc := rbac.LoadCoreAccess(ctx, m.db, e.id, e.nodeName)
		if !rbac.ShouldReceiveCert(acc.Role, acc.Scopes, name) {
			continue
		}
		go func() {
			if err := e.client.PushJSON(coreWS.TypePushCert, payload); err != nil {
				m.log.Warn("corews/manager: push cert", "core", e.nodeName, "name", name, "err", err)
				return
			}
			m.log.Info("corews/manager: cert poussé", "core", e.nodeName, "name", name)
		}()
	}
}

// PushCerts renvoie tous les certificats stockés en DB à tous les Cores.
func (m *Manager) PushCerts(ctx context.Context) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT domain, cert_pem, key_pem FROM certs WHERE cert_pem != '' AND key_pem != ''`)
	if err != nil {
		m.log.Error("corews/manager: lecture certs", "err", err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var domain, certPEM, keyPEM string
		if err := rows.Scan(&domain, &certPEM, &keyPEM); err != nil {
			continue
		}
		pemBytes := []byte(certPEM)
		keyBytes := []byte(keyPEM)
		for _, name := range coretls.PushNames(domain, pemBytes) {
			go m.PushCert(ctx, name, pemBytes, keyBytes)
		}
	}
}

// PushSnippets envoie tous les snippets actifs à tous les Cores.
func (m *Manager) PushSnippets(ctx context.Context) {
	snippets, err := m.loadSnippets(ctx)
	if err != nil {
		m.log.Error("corews/manager: lecture snippets", "err", err)
		return
	}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(coreWS.TypePushSnippets, snippets); err != nil {
				m.log.Warn("corews/manager: push snippets", "core", e.nodeName, "err", err)
			}
		}()
	}
}

// PushErrorPages envoie la bibliothèque de pages d'erreur (scope admin) à tous les Cores.
// Bloque jusqu'à la fin des envois (évite la course avec PushRoutes).
func (m *Manager) PushErrorPages(ctx context.Context) {
	tpls, err := m.loadErrorPages(ctx)
	if err != nil {
		m.log.Error("corews/manager: lecture error pages", "err", err)
		return
	}
	entries := m.allEntries()
	var wg sync.WaitGroup
	for _, e := range entries {
		e := e
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.client.PushJSON(coreWS.TypePushErrorPages, tpls); err != nil {
				m.log.Warn("corews/manager: push error pages", "core", e.nodeName, "err", err)
			}
		}()
	}
	wg.Wait()
}

// PushPortalTemplates envoie les templates HTML Access à tous les Cores.
func (m *Manager) PushPortalTemplates(ctx context.Context) {
	tpls := api.LoadPortalPageTemplatesForPush(m.db)
	entries := m.allEntries()
	var wg sync.WaitGroup
	for _, e := range entries {
		e := e
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.client.PushJSON(coreWS.TypePushPortalTemplates, tpls); err != nil {
				m.log.Warn("corews/manager: push portal templates", "core", e.nodeName, "err", err)
			}
		}()
	}
	wg.Wait()
}

// PushAuthProviders envoie tous les fournisseurs auth à tous les Cores.
func (m *Manager) PushAuthProviders(ctx context.Context) {
	providers, err := m.loadAuthProviders(ctx)
	if err != nil {
		m.log.Error("corews/manager: lecture providers", "err", err)
		return
	}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(coreWS.TypePushAuthProviders, providers); err != nil {
				m.log.Warn("corews/manager: push providers", "core", e.nodeName, "err", err)
			}
		}()
	}
}

// PushIPProfiles envoie les profils IP actifs à tous les Cores.
func (m *Manager) PushIPProfiles(ctx context.Context) {
	profiles, err := m.loadIPProfiles(ctx)
	if err != nil {
		m.log.Error("corews/manager: lecture ip-profiles", "err", err)
		return
	}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(coreWS.TypePushIPProfiles, profiles); err != nil {
				m.log.Warn("corews/manager: push ip-profiles", "core", e.nodeName, "err", err)
			}
		}()
	}
}

// PushBans envoie les bans IP actifs (Fail2Ban, CrowdSec, natif) à tous les Cores.
func (m *Manager) PushBans(ctx context.Context) {
	list, err := m.loadActiveBans(ctx)
	if err != nil {
		m.log.Error("corews/manager: lecture bans", "err", err)
		return
	}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(coreWS.TypePushBans, list); err != nil {
				m.log.Warn("corews/manager: push bans", "core", e.nodeName, "err", err)
			}
		}()
	}
}

// PushPortal envoie la config portail d'accès au Core nommé (node_name).
func (m *Manager) PushPortal(ctx context.Context, coreName string, payload any) {
	coreName = strings.TrimSpace(coreName)
	if coreName == "" {
		return
	}
	for _, e := range m.allEntries() {
		if e.nodeName != coreName {
			continue
		}
		e := e
		go func() {
			if err := e.client.PushJSON(coreWS.TypePushPortal, payload); err != nil {
				m.log.Warn("corews/manager: push portal", "core", e.nodeName, "err", err)
			}
		}()
		return
	}
	m.log.Warn("corews/manager: push portal — Core introuvable", "core", coreName)
}

// PushSettings envoie les paramètres runtime à tous les Cores.
func (m *Manager) PushSettings(ctx context.Context, s Settings) {
	m.settingsMu.Lock()
	m.settings = s
	m.settingsMu.Unlock()
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(coreWS.TypePushSettings, s); err != nil {
				m.log.Warn("corews/manager: push settings", "core", e.nodeName, "err", err)
			}
		}()
	}
}

// PushClusterPeers envoie la topologie Raft à chaque Core.
func (m *Manager) PushClusterPeers(ctx context.Context) {
	// Construire la map peers depuis les Cores enregistrés (besoin du raft_endpoint)
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, node_name, COALESCE(raft_endpoint,'')
		 FROM tokens WHERE role='core' AND revoked=0 AND node_endpoint != ''
		   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`)
	if err != nil {
		m.log.Error("corews/manager: lecture raft peers", "err", err)
		return
	}
	defer rows.Close()

	peers := make(map[string]string)
	for rows.Next() {
		var id, name, raft string
		if err := rows.Scan(&id, &name, &raft); err != nil {
			continue
		}
		if raft != "" {
			peers[name] = raft
		}
	}
	if len(peers) == 0 {
		return
	}

	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(coreWS.TypePushClusterPeers, peers); err != nil {
				m.log.Warn("corews/manager: push cluster peers", "core", e.nodeName, "err", err)
			}
		}()
	}
}

// PushGatewayPeers envoie à chaque Core la liste des autres Cores (endpoint + token)
// pour le LB adaptive cross-Core via stream gateway.
func (m *Manager) PushGatewayPeers(ctx context.Context) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT node_name, node_endpoint, token FROM tokens
		 WHERE role='core' AND revoked=0 AND node_endpoint != '' AND token != ''
		   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`)
	if err != nil {
		m.log.Error("corews/manager: lecture gateway peers", "err", err)
		return
	}
	defer rows.Close()

	type peer struct {
		Name     string `json:"name"`
		Endpoint string `json:"endpoint"`
		Token    string `json:"token"`
	}
	var all []peer
	for rows.Next() {
		var p peer
		if err := rows.Scan(&p.Name, &p.Endpoint, &p.Token); err != nil {
			continue
		}
		p.Token = auth.PlainNodeToken(p.Token)
		all = append(all, p)
	}
	if len(all) < 2 {
		return // rien à synchroniser entre Cores
	}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(coreWS.TypePushGatewayPeers, all); err != nil {
				m.log.Warn("corews/manager: push gateway peers", "core", e.nodeName, "err", err)
				return
			}
			m.log.Debug("corews/manager: gateway peers poussés", "core", e.nodeName, "count", len(all))
		}()
	}
}

// resolveTokenCoreID convertit un core_id (UUID token ou node_name) vers l'UUID token.
func (m *Manager) resolveTokenCoreID(ctx context.Context, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	var id string
	err := m.db.QueryRowContext(ctx, `
		SELECT id FROM tokens
		WHERE role='core' AND revoked=0
		  AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
		  AND (id=? OR node_name=?)
		ORDER BY CASE WHEN id=? THEN 0 ELSE 1 END, created_at DESC
		LIMIT 1`, ref, ref, ref).Scan(&id)
	if err != nil {
		return ref
	}
	return id
}

// PushDelegations envoie les routes de délégation à chaque Core concerné.
// Envoie aussi une liste vide aux autres Cores pour purger d'éventuelles routes deleg-* obsolètes.
func (m *Manager) PushDelegations(ctx context.Context) {
	type delegation struct {
		ID                string
		Domain            string
		CoreID            string
		DelegatedEndpoint string
		DelegationMode    string
	}

	rows, err := m.db.QueryContext(ctx, `
		SELECT id, domain, core_id, delegated_endpoint, delegation_mode
		FROM domains
		WHERE delegated_to_core_id != '' AND delegated_endpoint != ''`)
	if err != nil {
		m.log.Error("corews/manager: lecture délégations", "err", err)
		return
	}
	defer rows.Close()

	byCoreID := map[string][]delegation{}
	for rows.Next() {
		var d delegation
		if err := rows.Scan(&d.ID, &d.Domain, &d.CoreID, &d.DelegatedEndpoint, &d.DelegationMode); err != nil {
			continue
		}
		resolved := m.resolveTokenCoreID(ctx, d.CoreID)
		if resolved != "" && resolved != d.CoreID {
			if _, err := m.db.ExecContext(ctx,
				`UPDATE domains SET core_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
				resolved, d.ID); err != nil {
				m.log.Warn("corews/manager: normalisation core_id", "domain", d.Domain, "err", err)
			} else {
				m.log.Info("corews/manager: core_id normalisé", "domain", d.Domain, "from", d.CoreID, "to", resolved)
			}
			d.CoreID = resolved
		}
		// Normalise aussi delegated_to_core_id (informatif UI / cohérence DB).
		var delegatedRef string
		_ = m.db.QueryRowContext(ctx,
			`SELECT delegated_to_core_id FROM domains WHERE id=?`, d.ID).Scan(&delegatedRef)
		if resolvedDeleg := m.resolveTokenCoreID(ctx, delegatedRef); resolvedDeleg != "" && resolvedDeleg != delegatedRef {
			_, _ = m.db.ExecContext(ctx,
				`UPDATE domains SET delegated_to_core_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
				resolvedDeleg, d.ID)
		}
		byCoreID[d.CoreID] = append(byCoreID[d.CoreID], d)
	}

	for _, e := range m.allEntries() {
		e := e
		delegs := byCoreID[e.id]
		if len(delegs) == 0 {
			delegs = byCoreID[e.nodeName]
		}
		go func() {
			routes := make([]router.Route, 0, len(delegs))
			for _, d := range delegs {
				r := router.Route{
					ID:   "deleg-" + d.ID,
					Host: d.Domain,
					Type: router.RouteHTTP,
				}
				if d.DelegationMode == "terminate" {
					r.TLSEnabled = true
					r.TLSPassthrough = false
					ph := true
					r.PreserveHost = &ph // Core B doit recevoir le Host original
					backendURL := d.DelegatedEndpoint
					if len(backendURL) > 0 && backendURL[0] != 'h' {
						backendURL = "https://" + backendURL
					}
					r.Backends = []router.Backend{{URL: backendURL}}
					// Explicite côté Admin (pas forcé par Core) — labs / Core B auto-signé.
					r.TLSSkipVerify = true
				} else {
					r.TLSEnabled = true
					r.TLSPassthrough = true
					// Le passthrough TLS ouvre un dial TCP brut côté Core :
					// il attend impérativement un endpoint au format host:port.
					r.Backends = []router.Backend{{URL: d.DelegatedEndpoint}}
				}
				routes = append(routes, r)
			}
			if err := e.client.PushJSON(coreWS.TypePushDelegations, routes); err != nil {
				m.log.Warn("corews/manager: push délégations", "core", e.nodeName, "err", err)
				return
			}
			m.log.Info("corews/manager: délégations poussées", "core", e.nodeName, "count", len(routes))
		}()
	}
}

// SetSettings stocke les paramètres runtime à utiliser lors des prochains full_sync.
func (m *Manager) SetSettings(s Settings) {
	m.settingsMu.Lock()
	m.settings = s
	m.settingsMu.Unlock()
}

// BroadcastApproveAgent envoie un message approve_agent à tous les Cores connectés.
// Le Core qui a l'Agent en attente traitera le message ; les autres l'ignoreront.
func (m *Manager) BroadcastApproveAgent(agentID string) {
	payload := coreWS.ApproveAgentPayload{AgentID: agentID}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(coreWS.TypeApproveAgent, payload); err != nil {
				m.log.Warn("corews/manager: broadcast approve_agent", "core", e.nodeName, "err", err)
			}
		}()
	}
}

// BroadcastRevokeAgent envoie revoke_agent à tous les Cores : fermeture WS + invalidation HMAC.
func (m *Manager) BroadcastRevokeAgent(agentID string) {
	payload := coreWS.RevokeAgentPayload{AgentID: agentID}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(coreWS.TypeRevokeAgent, payload); err != nil {
				m.log.Warn("corews/manager: broadcast revoke_agent", "core", e.nodeName, "err", err)
			}
		}()
	}
}

// PushAll envoie la configuration complète à tous les Cores.
// Appelé lors de l'enregistrement d'un Core et à chaque reconnexion WS.
func (m *Manager) PushAll(ctx context.Context, settings Settings) {
	m.settingsMu.Lock()
	m.settings = settings
	m.settingsMu.Unlock()
	for _, e := range m.allEntries() {
		e := e
		go m.pushAllToEntry(ctx, e, settings)
	}
}

// pushAllToEntry envoie la config complète à un Core spécifique.
func (m *Manager) pushAllToEntry(ctx context.Context, e *coreEntry, s Settings) {
	allRoutes, _ := m.loadRoutes(ctx)
	acc := rbac.LoadCoreAccess(ctx, m.db, e.id, e.nodeName)
	filteredRoutes := rbac.FilterRoutesByScopes(acc.Role, acc.Scopes, allRoutes)
	filteredRoutes = delegation.FilterRoutesForCore(e.id, e.nodeName, filteredRoutes, m.loadDelegationBindings(ctx))
	if filteredRoutes == nil {
		filteredRoutes = []router.Route{}
	}

	snippets, _ := m.loadSnippets(ctx)
	providers, _ := m.loadAuthProviders(ctx)
	profiles, _ := m.loadIPProfiles(ctx)
	banList, _ := m.loadActiveBans(ctx)

	fsync := map[string]any{
		"routes":      filteredRoutes,
		"snippets":    snippets,
		"providers":   providers,
		"ip_profiles": profiles,
		"bans":        banList,
	}
	// Pages d'erreur avant full_sync : les routes peuvent référencer des template_id.
	if tpls, err := m.loadErrorPages(ctx); err != nil {
		m.log.Warn("corews/manager: lecture error pages", "core", e.nodeName, "err", err)
	} else if err := e.client.PushJSON(coreWS.TypePushErrorPages, tpls); err != nil {
		m.log.Warn("corews/manager: push error pages", "core", e.nodeName, "err", err)
	}
	if err := e.client.PushJSON(coreWS.TypeFullSync, fsync); err != nil {
		m.log.Warn("corews/manager: full_sync", "core", e.nodeName, "err", err)
		return
	}

	// Certs en parallèle (binaires, séparés du full_sync JSON)
	go m.PushCerts(ctx)

	// Settings runtime
	if s != (Settings{}) {
		go func() {
			if err := e.client.PushJSON(coreWS.TypePushSettings, s); err != nil {
				m.log.Warn("corews/manager: push settings", "core", e.nodeName, "err", err)
			}
		}()
	}

	// Peers Raft
	go m.PushClusterPeers(ctx)
	// Peers gateway LB cross-Core
	go m.PushGatewayPeers(ctx)
	// Délégations
	go m.PushDelegations(ctx)

	// Portail d'accès (config par Core)
	go func() {
		cfg := api.LoadPortalConfigForCore(m.db, e.nodeName)
		if err := e.client.PushJSON(coreWS.TypePushPortal, cfg); err != nil {
			m.log.Warn("corews/manager: push portal", "core", e.nodeName, "err", err)
		}
	}()
	go func() {
		tpls := api.LoadPortalPageTemplatesForPush(m.db)
		if err := e.client.PushJSON(coreWS.TypePushPortalTemplates, tpls); err != nil {
			m.log.Warn("corews/manager: push portal templates", "core", e.nodeName, "err", err)
		}
	}()

	m.log.Info("corews/manager: full_sync envoyé", "core", e.nodeName,
		"routes", len(filteredRoutes), "scopes", len(acc.Scopes), "token", acc.TokenID)
}

// --- Chargement des données depuis la DB ---

// loadDelegationBindings charge les délégations actives (IDs normalisés vers UUID token).
func (m *Manager) loadDelegationBindings(ctx context.Context) []delegation.Binding {
	rows, err := m.db.QueryContext(ctx, `
		SELECT domain, core_id, delegated_to_core_id
		FROM domains
		WHERE delegated_to_core_id != '' AND delegated_endpoint != ''`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []delegation.Binding
	for rows.Next() {
		var b delegation.Binding
		if err := rows.Scan(&b.Domain, &b.ResponsibleCoreID, &b.TargetCoreID); err != nil {
			continue
		}
		if id := m.resolveTokenCoreID(ctx, b.ResponsibleCoreID); id != "" {
			b.ResponsibleCoreID = id
		}
		if id := m.resolveTokenCoreID(ctx, b.TargetCoreID); id != "" {
			b.TargetCoreID = id
		}
		out = append(out, b)
	}
	return out
}

// FilterRoutesForCore applique RBAC + exclusion des hosts délégués (pour GET /internal/v1/routes).
func (m *Manager) FilterRoutesForCore(ctx context.Context, coreID, nodeName, rbacRole string, scopes []rbac.Scope, routes []router.Route) []router.Route {
	filtered := rbac.FilterRoutesByScopes(rbacRole, scopes, routes)
	return delegation.FilterRoutesForCore(coreID, nodeName, filtered, m.loadDelegationBindings(ctx))
}

func (m *Manager) loadRoutes(ctx context.Context) ([]router.Route, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT config FROM proxies WHERE enabled=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var routes []router.Route
	for rows.Next() {
		var cfg string
		if err := rows.Scan(&cfg); err != nil {
			continue
		}
		var r router.Route
		if err := json.Unmarshal([]byte(cfg), &r); err == nil {
			routes = append(routes, r)
		}
	}
	if routes == nil {
		routes = []router.Route{}
	}
	return routes, nil
}

func (m *Manager) loadSnippets(ctx context.Context) ([]json.RawMessage, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT id, name, type, config FROM snippets`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type snippet struct {
		ID     string          `json:"id"`
		Name   string          `json:"name"`
		Type   string          `json:"type"`
		Config json.RawMessage `json:"config"`
	}
	var list []json.RawMessage
	for rows.Next() {
		var s snippet
		var cfg string
		if err := rows.Scan(&s.ID, &s.Name, &s.Type, &cfg); err != nil {
			continue
		}
		s.Config = json.RawMessage(cfg)
		b, _ := json.Marshal(s)
		list = append(list, b)
	}
	if list == nil {
		list = []json.RawMessage{}
	}
	return list, nil
}

func (m *Manager) loadErrorPages(ctx context.Context) ([]errorpages.Template, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, name, description, body, scope_type, scope_id
		 FROM error_page_templates WHERE scope_type='admin'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []errorpages.Template
	for rows.Next() {
		var t errorpages.Template
		if err := rows.Scan(&t.ID, &t.Name, &t.Description, &t.Body, &t.ScopeType, &t.ScopeID); err != nil {
			continue
		}
		aRows, err := m.db.QueryContext(ctx,
			`SELECT filename, content_type, content FROM error_page_assets WHERE template_id=?`, t.ID)
		if err == nil {
			for aRows.Next() {
				var a errorpages.Asset
				if err := aRows.Scan(&a.Filename, &a.ContentType, &a.Content); err != nil {
					continue
				}
				t.Assets = append(t.Assets, a)
			}
			aRows.Close()
		}
		list = append(list, t)
	}
	if list == nil {
		list = []errorpages.Template{}
	}
	return list, nil
}

func (m *Manager) loadAuthProviders(ctx context.Context) ([]json.RawMessage, error) {
	rows, err := m.db.QueryContext(ctx, `SELECT id, name, provider, config FROM auth_providers WHERE enabled=1`)
	if err != nil {
		return []json.RawMessage{}, nil
	}
	defer rows.Close()
	type provider struct {
		ID       string          `json:"id"`
		Name     string          `json:"name"`
		Provider string          `json:"provider"`
		Config   json.RawMessage `json:"config"`
	}
	var list []json.RawMessage
	for rows.Next() {
		var pr provider
		var cfg string
		if err := rows.Scan(&pr.ID, &pr.Name, &pr.Provider, &cfg); err != nil {
			continue
		}
		pr.Config = json.RawMessage(cfg)
		b, _ := json.Marshal(pr)
		list = append(list, b)
	}
	if list == nil {
		list = []json.RawMessage{}
	}
	return list, nil
}

func (m *Manager) loadIPProfiles(ctx context.Context) ([]json.RawMessage, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, name, mode, cidrs FROM ip_profiles WHERE enabled=1`)
	if err != nil {
		return []json.RawMessage{}, nil
	}
	defer rows.Close()
	type profile struct {
		ID    string          `json:"id"`
		Name  string          `json:"name"`
		Mode  string          `json:"mode"`
		CIDRs json.RawMessage `json:"cidrs"`
	}
	var list []json.RawMessage
	for rows.Next() {
		var pr profile
		var cidrs string
		if err := rows.Scan(&pr.ID, &pr.Name, &pr.Mode, &cidrs); err != nil {
			continue
		}
		pr.CIDRs = json.RawMessage(cidrs)
		b, _ := json.Marshal(pr)
		list = append(list, b)
	}
	if list == nil {
		list = []json.RawMessage{}
	}
	return list, nil
}

func (m *Manager) loadActiveBans(ctx context.Context) ([]router.RuntimeBan, error) {
	rows, err := m.db.QueryContext(ctx, `
		SELECT id, ip, reason, source, expires_at
		FROM security_bans
		WHERE expires_at IS NULL OR expires_at = '' OR expires_at > CURRENT_TIMESTAMP`)
	if err != nil {
		return []router.RuntimeBan{}, nil
	}
	defer rows.Close()
	var list []router.RuntimeBan
	for rows.Next() {
		var b router.RuntimeBan
		var expires sql.NullString
		if err := rows.Scan(&b.ID, &b.IP, &b.Reason, &b.Source, &expires); err != nil {
			continue
		}
		if expires.Valid && expires.String != "" {
			if t, err := time.Parse(time.RFC3339, expires.String); err == nil {
				b.ExpiresAt = &t
			} else if t, err := time.Parse("2006-01-02 15:04:05", expires.String); err == nil {
				b.ExpiresAt = &t
			}
		}
		list = append(list, b)
	}
	if list == nil {
		list = []router.RuntimeBan{}
	}
	return list, nil
}
