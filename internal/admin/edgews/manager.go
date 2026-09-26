// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/alerting"
	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/archstore"
	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/delegation"
	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/admin/mailer"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/edge/errorpages"
	"github.com/vincamok/goproxify/internal/edge/router"
	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

// Settings regroupe les paramètres runtime poussés aux passerelles.
type Settings struct {
	TracingEndpoint string `json:"tracing_endpoint,omitempty"`
	LogLevel        string `json:"log_level,omitempty"`
	LogFormat       string `json:"log_format,omitempty"`
	AccessLogPath   string `json:"access_log_path,omitempty"`
	// AdminPublicURL : origine publique de l'UI Admin (liens pages d'erreur → Logs).
	AdminPublicURL string `json:"admin_public_url,omitempty"`
	// IPAnonymize : quand true, la passerelle tronque les IPs dans les access logs (RGPD).
	IPAnonymize *bool `json:"ip_anonymize,omitempty"`
	// IPPseudonymize : quand true, la passerelle tronque l'IP dans son fichier log mais envoie l'IP réelle à l'Admin pour chiffrement AES-GCM.
	IPPseudonymize *bool `json:"ip_pseudonymize,omitempty"`
}

// edgeEntry associe un edgeID (token UUID) à son client WS et ses métadonnées.
type edgeEntry struct {
	id       string // UUID dans la table tokens
	nodeName string
	rbacRole string
	client   *Client
}

// Manager gère un client WS persistant par passerelle enregistrée.
// Il remplace edgepush.Pusher comme mécanisme de synchronisation Admin→Passerelle.
type Manager struct {
	mu         sync.RWMutex
	edges      map[string]*edgeEntry // key = edgeID (UUID)
	hmacSecret string
	db         *sql.DB
	log        *slog.Logger
	dataDir    string           // basePath Admin pour fallback disque snippets/providers
	archStore  *archstore.Store // référentiel architecture disque

	settingsMu     sync.RWMutex
	settings       Settings // derniers paramètres poussés (utilisés au full_sync)
	onAgentPending func(id, name, version string)
	onLogBatch     func(entries []edgeWS.LogEntryPayload)
	onWAFReloaded  func(nodeName string)
	alertEngine    *alerting.Engine
}

// NewManager crée un Manager WS Admin→Passerelle.
func NewManager(hmacSecret string, db *sql.DB, log *slog.Logger) *Manager {
	return &Manager{
		edges:      make(map[string]*edgeEntry),
		hmacSecret: hmacSecret,
		db:         db,
		log:        log,
	}
}

// SetDataDir configure le répertoire de persistance disque pour snippets et auth providers.
func (m *Manager) SetDataDir(dir string) {
	m.dataDir = dir
}

// SetArchStore injecte le référentiel architecture.
func (m *Manager) SetArchStore(s *archstore.Store) {
	m.archStore = s
}

type edgeTokenDisk struct {
	ID           string `json:"id"`
	Role         string `json:"role"`  // "edge" | "agent" ; vide = "edge" (compat ancien format)
	Token        string `json:"token"` // sealed
	TokenHash    string `json:"token_hash"`
	RBACRole     string `json:"rbac_role"`
	NodeName     string `json:"node_name"`
	NodeEndpoint string `json:"node_endpoint"`
}

// LoadFromDB charge les passerelles existantes depuis la table tokens et crée un client WS pour chacun.
// Ignore les nœuds déjà connectés (même id ou même node_name) pour cohabiter avec ConnectFromEnv.
// Si la table est vide, tente une restauration depuis node_tokens.json (disque).
func (m *Manager) LoadFromDB(ctx context.Context) error {
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, node_name, node_endpoint, COALESCE(rbac_role, 'admin')
		 FROM tokens
		 WHERE role='edge' AND revoked=0 AND node_endpoint != ''
		   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`)
	if err != nil {
		// DB error → try disk
		m.restoreEdgeTokensFromDisk(ctx)
		return err
	}
	defer rows.Close()

	type entry struct{ id, name, ep, role string }
	var entries []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.id, &e.name, &e.ep, &e.role); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	rows.Close()

	// architecture.json fait foi : reconnecter ses passerelles, puis aligner la base dessus.
	m.registerArchitectureEdges(ctx)
	m.applyArchitecture(ctx)

	if len(entries) == 0 {
		m.restoreEdgeTokensFromDisk(ctx)
		// reload after restore
		rows2, err2 := m.db.QueryContext(ctx,
			`SELECT id, node_name, node_endpoint, COALESCE(rbac_role, 'admin')
			 FROM tokens
			 WHERE role='edge' AND revoked=0 AND node_endpoint != ''
			   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`)
		if err2 == nil {
			for rows2.Next() {
				var e entry
				if err2 := rows2.Scan(&e.id, &e.name, &e.ep, &e.role); err2 == nil {
					entries = append(entries, e)
				}
			}
			rows2.Close()
		}
	} else {
		// Persist current tokens to disk
		m.saveEdgeTokensToDisk(ctx)
	}
	m.seedArchitecture(ctx)

	n := 0
	for _, e := range entries {
		if m.hasEdge(e.id, e.name) {
			continue
		}
		m.Register(e.id, e.name, e.ep, e.role)
		n++
	}
	if n > 0 {
		m.log.Info("edgews: Passerelles supplémentaires chargés depuis DB", "count", n)
	}
	return nil
}

// saveEdgeTokensToDisk persiste les tokens passerelle et Agent actifs dans node_tokens.json.
func (m *Manager) saveEdgeTokensToDisk(ctx context.Context) {
	if m.dataDir == "" {
		return
	}
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, role, token, token_hash, COALESCE(rbac_role,'admin'),
		        COALESCE(node_name,''), COALESCE(node_endpoint,'')
		 FROM tokens
		 WHERE revoked=0 AND role IN ('edge','agent')
		   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`)
	if err != nil {
		return
	}
	defer rows.Close()
	var list []edgeTokenDisk
	for rows.Next() {
		var t edgeTokenDisk
		if err := rows.Scan(&t.ID, &t.Role, &t.Token, &t.TokenHash, &t.RBACRole, &t.NodeName, &t.NodeEndpoint); err != nil {
			continue
		}
		list = append(list, t)
	}
	if len(list) > 0 {
		m.writeJSONFile("node_tokens.json", list)
	}
}

// restoreEdgeTokensFromDisk ré-insère les tokens passerelle depuis node_tokens.json si la table est vide.
func (m *Manager) restoreEdgeTokensFromDisk(ctx context.Context) {
	if m.dataDir == "" {
		return
	}
	b, err := os.ReadFile(filepath.Join(m.dataDir, "node_tokens.json"))
	if err != nil {
		return
	}
	var list []edgeTokenDisk
	if err := json.Unmarshal(b, &list); err != nil || len(list) == 0 {
		return
	}
	n := 0
	for _, t := range list {
		if t.ID == "" || t.NodeName == "" {
			continue
		}
		role := t.Role
		if role == "" {
			role = "edge" // compat ancien format
		}
		if role == "core" {
			role = "edge"
		}
		if role == "edge" && t.NodeEndpoint == "" {
			continue // Passerelle sans endpoint n'est pas connecté
		}
		_, err := m.db.ExecContext(ctx,
			`INSERT OR IGNORE INTO tokens (id, token, token_hash, role, rbac_role, node_name, node_endpoint)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			t.ID, t.Token, t.TokenHash, role, t.RBACRole, t.NodeName, t.NodeEndpoint)
		if err == nil {
			n++
		}
	}
	if n > 0 {
		m.log.Info("edgews: tokens nœuds restaurés depuis disque", "count", n)
	}
}

func (m *Manager) hasEdge(edgeID, nodeName string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if _, ok := m.edges[edgeID]; ok {
		return true
	}
	for _, e := range m.edges {
		if e.nodeName == nodeName {
			return true
		}
	}
	return false
}

// Register crée ou met à jour un client WS pour une passerelle.
// Un seul client par node_name : les doublons (autre UUID) sont fermés.
func (m *Manager) Register(edgeID, nodeName, endpoint, rbacRole string) {
	if endpoint == "" {
		m.log.Warn("edgews: Register ignoré — endpoint vide", "edge", nodeName, "id", edgeID)
		return
	}
	if edgeID == "" {
		m.log.Warn("edgews: Register ignoré — id vide", "edge", nodeName)
		return
	}
	// Interdit d'utiliser node_name comme id (scopes liés à l'UUID token).
	if nodeName != "" && edgeID == nodeName {
		m.log.Error("edgews: Register refusé — id=node_name (scopes introuvables)", "edge", nodeName)
		return
	}

	m.mu.Lock()
	var stale []*edgeEntry
	for id, e := range m.edges {
		if id != edgeID && e.nodeName != "" && e.nodeName == nodeName {
			stale = append(stale, e)
			delete(m.edges, id)
		}
	}
	existing, ok := m.edges[edgeID]
	if ok {
		existing.nodeName = nodeName
		existing.rbacRole = rbacRole
		m.mu.Unlock()
		for _, s := range stale {
			s.client.Close()
			m.log.Info("edgews: doublon retiré", "edge", nodeName, "id", s.id)
		}
		existing.client.Close()
		entry := &edgeEntry{
			id:       edgeID,
			nodeName: nodeName,
			rbacRole: rbacRole,
		}
		entry.client = m.newClient(edgeID, endpoint, entry)
		m.mu.Lock()
		m.edges[edgeID] = entry
		m.mu.Unlock()
		m.log.Info("edgews: client mis à jour", "edge", nodeName, "id", edgeID, "endpoint", endpoint)
		return
	}
	entry := &edgeEntry{
		id:       edgeID,
		nodeName: nodeName,
		rbacRole: rbacRole,
	}
	entry.client = m.newClient(edgeID, endpoint, entry)
	m.edges[edgeID] = entry
	m.mu.Unlock()
	for _, s := range stale {
		s.client.Close()
		m.log.Info("edgews: doublon retiré", "edge", nodeName, "id", s.id)
	}
	m.log.Info("edgews: client enregistré", "edge", nodeName, "id", edgeID, "endpoint", endpoint)
	go m.saveEdgeTokensToDisk(context.Background())
}

// Unregister ferme le client WS d'une passerelle et le supprime du Manager.
func (m *Manager) Unregister(edgeID string) {
	m.mu.Lock()
	entry, ok := m.edges[edgeID]
	if ok {
		delete(m.edges, edgeID)
	}
	m.mu.Unlock()
	if ok {
		entry.client.Close()
		m.log.Info("edgews: client retiré", "id", edgeID)
	}
}

// Close ferme tous les clients WS.
func (m *Manager) Close() {
	m.mu.Lock()
	entries := make([]*edgeEntry, 0, len(m.edges))
	for _, e := range m.edges {
		entries = append(entries, e)
	}
	m.edges = make(map[string]*edgeEntry)
	m.mu.Unlock()
	for _, e := range entries {
		e.client.Close()
	}
}

// ConnectFromEnv connecte Admin → passerelle principale via GPX_IDENTITY_EDGE_NODE_NAME,
// les passerelles supplémentaires via GPX_EDGE_EXTRA_ENDPOINTS (format CSV "name=http://host:port"),
// puis charge tous les autres passerelles déclarées (tokens avec node_endpoint) pour le multi-passerelle.
func (m *Manager) ConnectFromEnv(ctx context.Context) {
	edgeName := os.Getenv("GPX_IDENTITY_EDGE_NODE_NAME")
	if edgeName == "" {
		m.log.Info("edgews: GPX_IDENTITY_EDGE_NODE_NAME non défini — connexion via tokens DB uniquement")
	} else {
		endpoint := "http://" + edgeName + ":8000"
		id, role, err := m.ensureEdgeToken(ctx, edgeName, endpoint)
		if err != nil {
			m.log.Error("edgews: impossible de préparer le token passerelle — pas de connexion env",
				"edge", edgeName, "err", err)
		} else {
			m.Register(id, edgeName, endpoint, role)
			m.log.Info("edgews: connexion passerelle depuis env", "edge", edgeName, "id", id, "endpoint", endpoint)
		}
	}

	// GPX_EDGE_EXTRA_ENDPOINTS : Passerelles supplémentaires (HA, multi-passerelle).
	// Format CSV : "name=http://host:port,name2=http://edge.example.com:port"
	if extras := os.Getenv("GPX_EDGE_EXTRA_ENDPOINTS"); extras != "" {
		for _, entry := range strings.Split(extras, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}
			name, ep, ok := strings.Cut(entry, "=")
			if !ok || name == "" || ep == "" {
				m.log.Warn("edgews: GPX_EDGE_EXTRA_ENDPOINTS — entrée ignorée (format attendu name=http://host:port)", "entry", entry)
				continue
			}
			name = strings.TrimSpace(name)
			ep = strings.TrimSpace(ep)
			id, role, err := m.ensureEdgeToken(ctx, name, ep)
			if err != nil {
				m.log.Error("edgews: impossible de préparer le token passerelle extra — pas de connexion",
					"edge", name, "err", err)
				continue
			}
			m.Register(id, name, ep, role)
			m.log.Info("edgews: connexion passerelle extra depuis env", "edge", name, "id", id, "endpoint", ep)
		}
	}

	if err := m.LoadFromDB(ctx); err != nil {
		m.log.Warn("edgews: chargement passerelles depuis DB", "err", err)
	}
}

// ensureEdgeToken vérifie qu'un token valide existe dans la table tokens pour cette passerelle.
// Préfère un token qui a déjà des périmètres. Crée un nouveau token sinon.
// Retourne l'ID et le rbac_role du token.
func (m *Manager) ensureEdgeToken(ctx context.Context, nodeName, endpoint string) (id, rbacRole string, err error) {
	return m.ensureEdgeTokenWithID(ctx, nodeName, endpoint, "")
}

// ensureEdgeTokenWithID comme ensureEdgeToken, mais crée le token sous wantID (si non vide) :
// les périmètres RBAC sont liés à l'ID du nœud, qui doit rester celui d'architecture.json.
func (m *Manager) ensureEdgeTokenWithID(ctx context.Context, nodeName, endpoint, wantID string) (id, rbacRole string, err error) {
	acc := rbac.ResolveEdgeAccess(ctx, m.db, nodeName)
	if acc.TokenID != "" {
		_, _ = m.db.ExecContext(ctx,
			`UPDATE tokens SET node_endpoint=? WHERE id=?`, endpoint, acc.TokenID)
		if m.archStore != nil {
			_ = m.archStore.EnsureEdge(acc.TokenID, nodeName, endpoint, acc.Role)
		}
		return acc.TokenID, acc.Role, nil
	}
	id = wantID
	if id == "" && m.archStore != nil {
		if nodes, lerr := m.archStore.List(); lerr == nil {
			for _, n := range nodes {
				if n.Role == "edge" && n.Name == nodeName {
					id = n.ID
					break
				}
			}
		}
	}
	if id == "" {
		id = uuid.New().String()
	}
	tok := auth.GenerateToken("edge", nodeName)
	stored, hash := auth.PrepareNodeTokenForStore(tok)
	_, err = m.db.ExecContext(ctx,
		`INSERT INTO tokens (id, token, token_hash, role, rbac_role, node_name, node_endpoint)
		 VALUES (?, ?, ?, 'edge', 'admin', ?, ?)`,
		id, stored, hash, nodeName, endpoint)
	if err == nil {
		m.saveEdgeTokensToDisk(ctx)
		if m.archStore != nil {
			_ = m.archStore.EnsureEdge(id, nodeName, endpoint, "admin")
		}
	}
	return id, "admin", err
}

// SetAgentPendingHandler enregistre un callback appelé quand la passerelle signale un Agent en attente.
func (m *Manager) SetAgentPendingHandler(fn func(id, name, version string)) {
	m.onAgentPending = fn
}

// SetLogBatchHandler enregistre le callback d'ingestion des logs passerelle/Agent (Prism / Logs).
func (m *Manager) SetLogBatchHandler(fn func(entries []edgeWS.LogEntryPayload)) {
	m.onLogBatch = fn
}

// SetWAFReloadedHandler enregistre un callback appelé quand la passerelle confirme l'application des snippets WAF.
func (m *Manager) SetWAFReloadedHandler(fn func(nodeName string)) {
	m.onWAFReloaded = fn
}

// SetAlertEngine injecte l'engine d'alertes pour émettre des événements depuis les messages passerelle.
func (m *Manager) SetAlertEngine(e *alerting.Engine) {
	m.alertEngine = e
}

// HandleEdgeMessage dispatche les messages reçus de la passerelle.
func (m *Manager) HandleEdgeMessage(msg edgeWS.Message) {
	switch msg.Type {
	case edgeWS.TypeEdgeHeartbeat:
		m.handleEdgeHeartbeat(msg)
	case edgeWS.TypeAgentPending:
		var p edgeWS.AgentPendingPayload
		if err := json.Unmarshal(msg.Payload, &p); err == nil && m.onAgentPending != nil {
			m.onAgentPending(p.AgentID, p.AgentName, p.Version)
		}
	case edgeWS.TypeAccessLog, edgeWS.TypeAgentLog:
		m.handleLogBatch(msg.Payload)
	case edgeWS.TypeAgentEvent:
		m.handleAgentEvent(msg.Payload)
	case edgeWS.TypePortalInviteCompleted:
		var p struct {
			UserID string `json:"user_id"`
		}
		if err := json.Unmarshal(msg.Payload, &p); err == nil {
			api.MarkPortalInviteCompleted(m.db, p.UserID)
		}
	case edgeWS.TypePortalSendEmailOTP:
		m.handlePortalSendEmailOTP(msg.Payload)
	case edgeWS.TypePortalAudit:
		m.handlePortalAudit(msg.Payload)
	case edgeWS.TypeThreatBan:
		m.handleThreatBan(msg.Payload)
	case edgeWS.TypeF2BBan:
		m.handleF2BBan(msg.Payload)
	case edgeWS.TypeCrowdSecDecisions:
		m.handleCrowdSecDecisions(msg.Payload)
	case edgeWS.TypeRuleFired:
		m.handleRuleFired(msg.Payload)
	case edgeWS.TypeBackendDown:
		m.handleBackendDown(msg.Payload)
	case edgeWS.TypeWAFReloaded:
		m.handleWAFReloaded(msg.Payload)
	}
}

func (m *Manager) handleWAFReloaded(raw json.RawMessage) {
	var p struct {
		NodeName string `json:"node_name"`
		Status   string `json:"status"`
	}
	if err := json.Unmarshal(raw, &p); err != nil || p.NodeName == "" {
		return
	}
	if m.db != nil {
		key := "waf_reloaded_at:" + p.NodeName
		m.db.Exec(`INSERT INTO settings (key, value) VALUES (?, CURRENT_TIMESTAMP)
			ON CONFLICT(key) DO UPDATE SET value=CURRENT_TIMESTAMP`, key) //nolint:errcheck
	}
	if m.onWAFReloaded != nil {
		m.onWAFReloaded(p.NodeName)
	}
}

func (m *Manager) handleThreatBan(raw json.RawMessage) {
	if m.db == nil || len(raw) == 0 {
		return
	}
	var p edgeWS.ThreatBanPayload
	if err := json.Unmarshal(raw, &p); err != nil || p.IP == "" {
		return
	}
	var expiresAt any
	if p.ExpiresAt != "" {
		expiresAt = p.ExpiresAt
	}
	banID := "threat-" + p.IP
	m.db.Exec( //nolint:errcheck
		`INSERT INTO security_bans (id, ip, domain, reason, source, expires_at)
		 VALUES (?, ?, '', ?, 'threat', ?)
		 ON CONFLICT(id) DO UPDATE SET reason=excluded.reason, expires_at=excluded.expires_at`,
		banID, p.IP, p.Reason, expiresAt,
	)
	m.db.Exec( //nolint:errcheck
		`INSERT INTO security_ban_history (ip, domain, action, reason, source, ban_id) VALUES (?,?,'banned',?,?,?)`,
		p.IP, "", p.Reason, "threat", banID)
	if m.alertEngine != nil {
		m.alertEngine.Emit(alerting.Event{
			Trigger:  alerting.TriggerSentinelBan,
			Severity: alerting.SevWarning,
			NodeName: p.NodeName,
			Detail:   map[string]any{"ip": p.IP, "reason": p.Reason},
		})
	}
}

func (m *Manager) handleF2BBan(raw json.RawMessage) {
	if m.db == nil || len(raw) == 0 {
		return
	}
	var p edgeWS.F2BBanPayload
	if err := json.Unmarshal(raw, &p); err != nil || p.IP == "" {
		return
	}
	var expiresAt any
	if p.ExpiresAt != "" {
		expiresAt = p.ExpiresAt
	}
	m.db.Exec( //nolint:errcheck
		`INSERT INTO security_bans (id, ip, domain, reason, source, expires_at)
		 VALUES (?, ?, '', ?, 'fail2ban', ?)
		 ON CONFLICT(id) DO NOTHING`,
		p.ID, p.IP, p.Reason, expiresAt,
	)
	m.db.Exec( //nolint:errcheck
		`INSERT INTO security_ban_history (ip, domain, action, reason, source, ban_id) VALUES (?,?,'banned',?,?,?)`,
		p.IP, "", p.Reason, "fail2ban", p.ID)
	if m.alertEngine != nil {
		m.alertEngine.Emit(alerting.Event{
			Trigger:  alerting.TriggerFail2BanBan,
			Severity: alerting.SevWarning,
			NodeName: p.NodeName,
			Detail:   map[string]any{"ip": p.IP, "reason": p.Reason},
		})
	}
}

func (m *Manager) handleBackendDown(raw json.RawMessage) {
	if len(raw) == 0 {
		return
	}
	var p edgeWS.BackendDownPayload
	if err := json.Unmarshal(raw, &p); err != nil || p.URL == "" {
		return
	}
	if m.alertEngine != nil {
		m.alertEngine.Emit(alerting.Event{
			Trigger:  alerting.TriggerBackendDown,
			Severity: alerting.SevCritical,
			NodeName: p.NodeName,
			Detail:   map[string]any{"url": p.URL},
		})
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
		m.log.Warn("edgews: portal email OTP", "email", p.Email, "err", err)
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
		m.log.Debug("edgews: insert node_event", "err", err)
	}
}

func (m *Manager) handleLogBatch(raw json.RawMessage) {
	if m.onLogBatch == nil || len(raw) == 0 {
		return
	}
	var entries []edgeWS.LogEntryPayload
	if err := json.Unmarshal(raw, &entries); err != nil {
		m.log.Debug("edgews: batch logs non reconnu", "err", err)
		return
	}
	if len(entries) == 0 {
		return
	}
	m.onLogBatch(entries)
}

func (m *Manager) handleEdgeHeartbeat(msg edgeWS.Message) {
	var hb edgeWS.EdgeHeartbeatPayload
	if err := json.Unmarshal(msg.Payload, &hb); err != nil {
		m.log.Warn("edgews: heartbeat passerelle invalide", "err", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := m.db.ExecContext(ctx, `
		INSERT INTO nodes (id, node_name, role, status, version, endpoint, cpu_pct, mem_pct, last_seen_at)
		VALUES (?, ?, 'edge', 'online', ?, '', ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(id) DO UPDATE SET
			status='online', version=excluded.version,
			cpu_pct=excluded.cpu_pct, mem_pct=excluded.mem_pct,
			last_seen_at=excluded.last_seen_at`,
		hb.NodeName, hb.NodeName, hb.Version, hb.CPUPct, hb.MemPct)
	if err != nil {
		m.log.Warn("edgews: upsert heartbeat passerelle", "err", err)
	}
	m.discoverClusterPeers(ctx, hb)
}

// newClient crée un Client WS pour une passerelle donné.
func (m *Manager) newClient(edgeID, endpoint string, entry *edgeEntry) *Client {
	return NewClient(edgeID, endpoint, m.hmacSecret, func(ctx context.Context) error {
		m.settingsMu.RLock()
		s := m.settings
		m.settingsMu.RUnlock()
		m.pushAllToEntry(ctx, entry, s)
		m.pushAdminToken(ctx, entry)
		return nil
	}, func(msg edgeWS.Message) {
		if msg.Type == edgeWS.TypeAccessLog || msg.Type == edgeWS.TypeAgentLog {
			msg.Payload = stampLogBatchNode(msg.Payload, edgeID, entry.nodeName)
		}
		m.HandleEdgeMessage(msg)
	}, m.log)
}

// stampLogBatchNode injecte node_name (si absent) et écrase toujours node_id
// avec l'ID stable de la connexion WS authentifiée (edgeID/token), quel que
// soit ce que la passerelle a pu envoyer — l'identité du nœud doit être autoritaire
// côté Admin, jamais déclarée par le client. Un renommage du nœud (qui change
// node_name, ex. après un re-bootstrap de edge.json) ne casse ainsi plus le
// filtrage/historique des logs : node_id reste stable tant que le token du
// Passerelle ne change pas.
func stampLogBatchNode(raw json.RawMessage, nodeID, nodeName string) json.RawMessage {
	if len(raw) == 0 || (nodeID == "" && nodeName == "") {
		return raw
	}
	var entries []edgeWS.LogEntryPayload
	if err := json.Unmarshal(raw, &entries); err != nil || len(entries) == 0 {
		return raw
	}
	changed := false
	for i := range entries {
		if entries[i].NodeName == "" && nodeName != "" {
			entries[i].NodeName = nodeName
			changed = true
		}
		if entries[i].NodeID != nodeID {
			entries[i].NodeID = nodeID
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

// pushAdminToken envoie à passerelle le token HTTP qu'Admin utilisera pour ses appels REST internes.
// Passerelle l'enregistre dans son tokenStore (RoleAdmin) afin de valider les requêtes Admin→Passerelle.
func (m *Manager) pushAdminToken(ctx context.Context, entry *edgeEntry) {
	var tok string
	if err := m.db.QueryRowContext(ctx,
		`SELECT token FROM tokens WHERE id=? AND revoked=0`, entry.id).Scan(&tok); err != nil || tok == "" {
		// Fallback node_name si l'entrée pointe encore vers un id obsolète.
		_ = m.db.QueryRowContext(ctx,
			`SELECT token FROM tokens
			 WHERE role='edge' AND node_name=? AND revoked=0 AND node_endpoint != ''
			   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
			 ORDER BY created_at DESC
			 LIMIT 1`, entry.nodeName).Scan(&tok)
	}
	if tok == "" {
		return
	}
	tok = auth.PlainNodeToken(tok)
	msg, err := edgeWS.NewMessage(0, edgeWS.TypeAdminToken, edgeWS.AdminTokenPayload{Token: tok})
	if err != nil {
		return
	}
	entry.client.Send(msg)
}

// allEntries retourne une copie sûre des entrées courantes.
func (m *Manager) allEntries() []*edgeEntry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entries := make([]*edgeEntry, 0, len(m.edges))
	for _, e := range m.edges {
		entries = append(entries, e)
	}
	return entries
}

// --- Interfaces compatibles edgepush.Pusher ---

// PushRoutes envoie les routes filtrées par RBAC à toutes les passerelles.
// Les proxies fichiers YAML sont la source de vérité côté passerelle — on ne pousse pas les routes ici.
func (m *Manager) PushRoutes(ctx context.Context) {
	go m.PushGatewayPeers(ctx)
}

func (m *Manager) pushRoutesSQLite(ctx context.Context) {
	allRoutes, err := m.loadRoutes(ctx)
	if err != nil {
		m.log.Error("edgews/manager: lecture routes", "err", err)
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
			acc := rbac.LoadEdgeAccess(ctx, m.db, e.id, e.nodeName)
			filtered := rbac.FilterRoutesByScopes(acc.Role, acc.Scopes, allRoutes)
			before := len(filtered)
			filtered = delegation.FilterRoutesForEdge(e.id, e.nodeName, filtered, bindings)
			if err := e.client.PushJSON(edgeWS.TypePushRoutes, filtered); err != nil {
				m.log.Warn("edgews/manager: push routes", "edge", e.nodeName, "err", err)
				return
			}
			m.log.Info("edgews/manager: routes poussées", "edge", e.nodeName, "count", len(filtered),
				"filtered_out", before-len(filtered), "scopes", len(acc.Scopes), "token", acc.TokenID)
		}()
	}
	wg.Wait()
	go m.PushGatewayPeers(ctx)
}

// DeleteRoute supprime immédiatement une route sur toutes les passerelles.
func (m *Manager) DeleteRoute(ctx context.Context, id string) {
	payload := map[string]string{"id": id}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(edgeWS.TypeDeleteRoute, payload); err != nil {
				m.log.Warn("edgews/manager: delete route", "edge", e.nodeName, "err", err)
			}
		}()
	}
}

// PushCert envoie un certificat déchiffré aux passerelles dont le périmètre le couvre.
// Admin sans scope → toutes les passerelles (comportement par défaut).
func (m *Manager) PushCert(ctx context.Context, name string, certPEM, keyPEM []byte) {
	payload := map[string]any{
		"name":     name,
		"cert_pem": certPEM,
		"key_pem":  keyPEM,
	}
	for _, e := range m.allEntries() {
		e := e
		acc := rbac.LoadEdgeAccess(ctx, m.db, e.id, e.nodeName)
		if !rbac.ShouldReceiveCert(acc.Role, acc.Scopes, name) {
			continue
		}
		go func() {
			if err := e.client.PushJSON(edgeWS.TypePushCert, payload); err != nil {
				m.log.Warn("edgews/manager: push cert", "edge", e.nodeName, "name", name, "err", err)
				return
			}
			m.log.Info("edgews/manager: cert poussé", "edge", e.nodeName, "name", name)
		}()
	}
}

// PushCerts renvoie tous les certificats stockés en DB à toutes les passerelles.
func (m *Manager) PushCerts(ctx context.Context) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT domain, cert_pem, key_pem FROM certs WHERE cert_pem != '' AND key_pem != ''`)
	if err != nil {
		m.log.Error("edgews/manager: lecture certs", "err", err)
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
		for _, name := range edgetls.PushNames(domain, pemBytes) {
			go m.PushCert(ctx, name, pemBytes, keyBytes)
		}
	}
}

// PushSnippets envoie tous les snippets actifs à toutes les passerelles.
func (m *Manager) PushSnippets(ctx context.Context) {
	snippets, err := m.loadSnippets(ctx)
	if err != nil {
		m.log.Error("edgews/manager: lecture snippets", "err", err)
		return
	}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(edgeWS.TypePushSnippets, snippets); err != nil {
				m.log.Warn("edgews/manager: push snippets", "edge", e.nodeName, "err", err)
			}
		}()
	}
}

// PushErrorPages envoie la bibliothèque de pages d'erreur (scope admin) à toutes les passerelles.
// Bloque jusqu'à la fin des envois (évite la course avec PushRoutes).
func (m *Manager) PushErrorPages(ctx context.Context) {
	tpls, err := m.loadErrorPages(ctx)
	if err != nil {
		m.log.Error("edgews/manager: lecture error pages", "err", err)
		return
	}
	entries := m.allEntries()
	var wg sync.WaitGroup
	for _, e := range entries {
		e := e
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.client.PushJSON(edgeWS.TypePushErrorPages, tpls); err != nil {
				m.log.Warn("edgews/manager: push error pages", "edge", e.nodeName, "err", err)
			}
		}()
	}
	wg.Wait()
}

// PushPortalTemplates envoie les templates HTML Access à toutes les passerelles.
func (m *Manager) PushPortalTemplates(ctx context.Context) {
	tpls := api.LoadPortalPageTemplatesForPush(m.db)
	entries := m.allEntries()
	var wg sync.WaitGroup
	for _, e := range entries {
		e := e
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := e.client.PushJSON(edgeWS.TypePushPortalTemplates, tpls); err != nil {
				m.log.Warn("edgews/manager: push portal templates", "edge", e.nodeName, "err", err)
			}
		}()
	}
	wg.Wait()
}

// PushAuthProviders envoie tous les fournisseurs auth à toutes les passerelles.
func (m *Manager) PushAuthProviders(ctx context.Context) {
	providers, err := m.loadAuthProviders(ctx)
	if err != nil {
		m.log.Error("edgews/manager: lecture providers", "err", err)
		return
	}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(edgeWS.TypePushAuthProviders, providers); err != nil {
				m.log.Warn("edgews/manager: push providers", "edge", e.nodeName, "err", err)
			}
		}()
	}
}

// PushIPProfiles envoie les profils IP actifs à toutes les passerelles.
func (m *Manager) PushIPProfiles(ctx context.Context) {
	profiles, err := m.loadIPProfiles(ctx)
	if err != nil {
		m.log.Error("edgews/manager: lecture ip-profiles", "err", err)
		return
	}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(edgeWS.TypePushIPProfiles, profiles); err != nil {
				m.log.Warn("edgews/manager: push ip-profiles", "edge", e.nodeName, "err", err)
			}
		}()
	}
}

// PushBans envoie les bans IP actifs (Fail2Ban, CrowdSec, natif) à toutes les passerelles.
func (m *Manager) PushBans(ctx context.Context) {
	list, err := m.loadActiveBans(ctx)
	if err != nil {
		m.log.Error("edgews/manager: lecture bans", "err", err)
		return
	}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(edgeWS.TypePushBans, list); err != nil {
				m.log.Warn("edgews/manager: push bans", "edge", e.nodeName, "err", err)
			}
		}()
	}
}

// PushPortal envoie la config portail d'accès à la passerelle nommé (node_name).
func (m *Manager) PushPortal(ctx context.Context, edgeName string, payload any) {
	edgeName = strings.TrimSpace(edgeName)
	if edgeName == "" {
		return
	}
	for _, e := range m.allEntries() {
		if e.nodeName != edgeName {
			continue
		}
		e := e
		go func() {
			if err := e.client.PushJSON(edgeWS.TypePushPortal, payload); err != nil {
				m.log.Warn("edgews/manager: push portal", "edge", e.nodeName, "err", err)
			}
		}()
		return
	}
	m.log.Warn("edgews/manager: push portal — passerelle introuvable", "edge", edgeName)
}

// PushSettings envoie les paramètres runtime à toutes les passerelles.
func (m *Manager) PushSettings(ctx context.Context, s Settings) {
	m.settingsMu.Lock()
	m.settings = s
	m.settingsMu.Unlock()
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(edgeWS.TypePushSettings, s); err != nil {
				m.log.Warn("edgews/manager: push settings", "edge", e.nodeName, "err", err)
			}
		}()
	}
}

// PushIPAnonymize pousse uniquement le toggle d'anonymisation IP vers toutes les passerelles.
// Implémente api.LogsSettingsPusher.
func (m *Manager) PushIPAnonymize(ctx context.Context, enabled bool) {
	partial := Settings{IPAnonymize: &enabled}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(edgeWS.TypePushSettings, partial); err != nil {
				m.log.Warn("edgews/manager: push ip_anonymize", "edge", e.nodeName, "err", err)
			}
		}()
	}
}

// PushIPPseudonymize pousse le toggle de pseudonymisation IP vers toutes les passerelles.
// Implémente api.LogsSettingsPusher.
func (m *Manager) PushIPPseudonymize(ctx context.Context, enabled bool) {
	partial := Settings{IPPseudonymize: &enabled}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(edgeWS.TypePushSettings, partial); err != nil {
				m.log.Warn("edgews/manager: push ip_pseudonymize", "edge", e.nodeName, "err", err)
			}
		}()
	}
}

// PushClusterPeers envoie la topologie Raft à chaque passerelle.
func (m *Manager) PushClusterPeers(ctx context.Context) {
	// Construire la map peers depuis les passerelles enregistrées (besoin du raft_endpoint)
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, node_name, COALESCE(raft_endpoint,'')
		 FROM tokens WHERE role='edge' AND revoked=0 AND node_endpoint != ''
		   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`)
	if err != nil {
		m.log.Error("edgews/manager: lecture raft peers", "err", err)
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
			if err := e.client.PushJSON(edgeWS.TypePushClusterPeers, peers); err != nil {
				m.log.Warn("edgews/manager: push cluster peers", "edge", e.nodeName, "err", err)
			}
		}()
	}
}

// PushGatewayPeers envoie à chaque passerelle la liste des autres passerelles (endpoint + token)
// pour le LB adaptive cross-passerelle via stream gateway.
func (m *Manager) PushGatewayPeers(ctx context.Context) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT node_name, node_endpoint, token FROM tokens
		 WHERE role='edge' AND revoked=0 AND node_endpoint != '' AND token != ''
		   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`)
	if err != nil {
		m.log.Error("edgews/manager: lecture gateway peers", "err", err)
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
		return // rien à synchroniser entre passerelles
	}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(edgeWS.TypePushGatewayPeers, all); err != nil {
				m.log.Warn("edgews/manager: push gateway peers", "edge", e.nodeName, "err", err)
				return
			}
			m.log.Debug("edgews/manager: gateway peers poussés", "edge", e.nodeName, "count", len(all))
		}()
	}
}

// resolveTokenEdgeID convertit un edge_id (UUID token ou node_name) vers l'UUID token.
func (m *Manager) resolveTokenEdgeID(ctx context.Context, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ""
	}
	var id string
	err := m.db.QueryRowContext(ctx, `
		SELECT id FROM tokens
		WHERE role='edge' AND revoked=0
		  AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
		  AND (id=? OR node_name=?)
		ORDER BY CASE WHEN id=? THEN 0 ELSE 1 END, created_at DESC
		LIMIT 1`, ref, ref, ref).Scan(&id)
	if err != nil {
		return ref
	}
	return id
}

// PushDelegations envoie les routes de délégation à chaque passerelle concernée.
// Envoie aussi une liste vide aux autres passerelles pour purger d'éventuelles routes deleg-* obsolètes.
func (m *Manager) PushDelegations(ctx context.Context) {
	type delegation struct {
		ID                string
		Domain            string
		EdgeID            string
		DelegatedToEdge   string
		DelegatedEndpoint string
		DelegationMode    string
	}

	rows, err := m.db.QueryContext(ctx, `
		SELECT id, domain, edge_id, delegated_to_edge_id, delegated_endpoint, delegation_mode
		FROM domains
		WHERE delegated_to_edge_id != '' AND delegated_endpoint != ''`)
	if err != nil {
		m.log.Error("edgews/manager: lecture délégations", "err", err)
		return
	}
	defer rows.Close()

	byEdgeID := map[string][]delegation{}
	var totalRows int
	for rows.Next() {
		totalRows++
		var d delegation
		if err := rows.Scan(&d.ID, &d.Domain, &d.EdgeID, &d.DelegatedToEdge, &d.DelegatedEndpoint, &d.DelegationMode); err != nil {
			continue
		}
		m.log.Info("edgews/manager: délégation DB", "domain", d.Domain, "edge_id", d.EdgeID, "endpoint", d.DelegatedEndpoint, "mode", d.DelegationMode)
		resolved := m.resolveTokenEdgeID(ctx, d.EdgeID)
		if resolved != "" && resolved != d.EdgeID {
			if _, err := m.db.ExecContext(ctx,
				`UPDATE domains SET edge_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
				resolved, d.ID); err != nil {
				m.log.Warn("edgews/manager: normalisation edge_id", "domain", d.Domain, "err", err)
			} else {
				m.log.Info("edgews/manager: edge_id normalisé", "domain", d.Domain, "from", d.EdgeID, "to", resolved)
			}
			d.EdgeID = resolved
		}
		// Normalise aussi delegated_to_edge_id (informatif UI / cohérence DB).
		var delegatedRef string
		_ = m.db.QueryRowContext(ctx,
			`SELECT delegated_to_edge_id FROM domains WHERE id=?`, d.ID).Scan(&delegatedRef)
		if resolvedDeleg := m.resolveTokenEdgeID(ctx, delegatedRef); resolvedDeleg != "" && resolvedDeleg != delegatedRef {
			_, _ = m.db.ExecContext(ctx,
				`UPDATE domains SET delegated_to_edge_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
				resolvedDeleg, d.ID)
		}
		byEdgeID[d.EdgeID] = append(byEdgeID[d.EdgeID], d)
	}
	connectedEdges := m.allEntries()
	m.log.Info("edgews/manager: PushDelegations", "domaines_délégués", totalRows, "edges_connectés", len(connectedEdges))
	for _, e := range connectedEdges {
		m.log.Info("edgews/manager: edge connecté", "id", e.id, "node_name", e.nodeName, "delegs_trouvées", len(byEdgeID[e.id])+len(byEdgeID[e.nodeName]))
	}

	for _, e := range connectedEdges {
		e := e
		delegs := byEdgeID[e.id]
		if len(delegs) == 0 {
			delegs = byEdgeID[e.nodeName]
		}
		go func() {
			routes := make([]router.Route, 0, len(delegs))
			for _, d := range delegs {
				// Récupère l'endpoint interne de la passerelle déléguée pour le relay passerelle→Passerelle.
				var delegateAPIEndpoint string
				_ = m.db.QueryRowContext(ctx,
					`SELECT node_endpoint FROM tokens
					 WHERE role='edge' AND revoked=0 AND node_endpoint != ''
					   AND (id=? OR node_name=?)
					 LIMIT 1`, d.DelegatedToEdge, d.DelegatedToEdge).Scan(&delegateAPIEndpoint)

				r := router.Route{
					ID:                  "deleg-" + d.ID,
					Host:                d.Domain,
					Type:                router.RouteHTTP,
					DelegateAPIEndpoint: delegateAPIEndpoint,
				}
				if d.DelegationMode == "terminate" {
					r.TLSEnabled = true
					r.TLSPassthrough = false
					ph := true
					r.PreserveHost = &ph // Passerelle B doit recevoir le Host original
					backendURL := d.DelegatedEndpoint
					if len(backendURL) > 0 && backendURL[0] != 'h' {
						backendURL = "https://" + backendURL
					}
					r.Backends = []router.Backend{{URL: backendURL}}
					// Explicite côté Admin (pas forcé par passerelle) — labs / Passerelle B auto-signé.
					r.TLSSkipVerify = true
				} else {
					r.TLSEnabled = true
					r.TLSPassthrough = true
					// Le passthrough TLS ouvre un dial TCP brut côté passerelle :
					// il attend impérativement un endpoint au format host:port.
					r.Backends = []router.Backend{{URL: d.DelegatedEndpoint}}
				}
				routes = append(routes, r)
			}
			if err := e.client.PushJSON(edgeWS.TypePushDelegations, routes); err != nil {
				m.log.Warn("edgews/manager: push délégations", "edge", e.nodeName, "err", err)
				return
			}
			m.log.Info("edgews/manager: délégations poussées", "edge", e.nodeName, "count", len(routes))
		}()
	}
}

// SetSettings stocke les paramètres runtime à utiliser lors des prochains full_sync.
func (m *Manager) SetSettings(s Settings) {
	m.settingsMu.Lock()
	m.settings = s
	m.settingsMu.Unlock()
}

// BroadcastApproveAgent envoie un message approve_agent à toutes les passerelles connectées.
// La passerelle qui a l'Agent en attente traitera le message ; les autres l'ignoreront.
func (m *Manager) BroadcastApproveAgent(agentID string) {
	payload := edgeWS.ApproveAgentPayload{AgentID: agentID}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(edgeWS.TypeApproveAgent, payload); err != nil {
				m.log.Warn("edgews/manager: broadcast approve_agent", "edge", e.nodeName, "err", err)
			}
		}()
	}
}

// BroadcastRevokeAgent envoie revoke_agent à toutes les passerelles : fermeture WS + invalidation HMAC.
func (m *Manager) BroadcastRevokeAgent(agentID string) {
	payload := edgeWS.RevokeAgentPayload{AgentID: agentID}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(edgeWS.TypeRevokeAgent, payload); err != nil {
				m.log.Warn("edgews/manager: broadcast revoke_agent", "edge", e.nodeName, "err", err)
			}
		}()
	}
}

// PushAll envoie la configuration complète à toutes les passerelles.
// Appelé lors de l'enregistrement d'une passerelle et à chaque reconnexion WS.
func (m *Manager) PushAll(ctx context.Context, settings Settings) {
	m.settingsMu.Lock()
	m.settings = settings
	m.settingsMu.Unlock()
	for _, e := range m.allEntries() {
		e := e
		go m.pushAllToEntry(ctx, e, settings)
	}
}

// syncProxiesFromPeers rattrape sur e les proxies de production manquants.
func (m *Manager) syncProxiesFromPeers(ctx context.Context, e *edgeEntry) {
	targets, err := edgeproxy.ListTargets(ctx, m.db)
	if err != nil {
		m.log.Warn("edgews/manager: sync proxies — targets", "edge", e.nodeName, "err", err)
		return
	}
	var self *edgeproxy.Target
	for i := range targets {
		if targets[i].ID == e.id || targets[i].NodeName == e.nodeName {
			self = &targets[i]
			break
		}
	}
	if self == nil || len(targets) < 2 {
		return
	}
	// Au démarrage de l'Admin, les passerelles répondent 401 tant que leur token n'est pas pris en compte.
	total := 0
	for attempt := 1; attempt <= 4; attempt++ {
		n, err := edgeproxy.NewClient().SyncMissing(ctx, *self, targets)
		total += n
		if err == nil {
			break
		}
		m.log.Warn("edgews/manager: sync proxies", "edge", e.nodeName, "attempt", attempt, "synced", n, "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
	if total > 0 {
		m.log.Info("edgews/manager: proxies rattrapés depuis les pairs", "edge", e.nodeName, "count", total)
	}
}

// pushAllToEntry envoie la config complète à une passerelle spécifique.
func (m *Manager) pushAllToEntry(ctx context.Context, e *edgeEntry, s Settings) {
	snippets, _ := m.loadSnippets(ctx)
	providers, _ := m.loadAuthProviders(ctx)
	profiles, _ := m.loadIPProfiles(ctx)
	banList, _ := m.loadActiveBans(ctx)

	// Routes non envoyées : les fichiers YAML passerelle sont la source de vérité.
	fsync := map[string]any{
		"snippets":    snippets,
		"providers":   providers,
		"ip_profiles": profiles,
		"bans":        banList,
	}
	// Pages d'erreur avant full_sync : les routes peuvent référencer des template_id.
	if tpls, err := m.loadErrorPages(ctx); err != nil {
		m.log.Warn("edgews/manager: lecture error pages", "edge", e.nodeName, "err", err)
	} else if err := e.client.PushJSON(edgeWS.TypePushErrorPages, tpls); err != nil {
		m.log.Warn("edgews/manager: push error pages", "edge", e.nodeName, "err", err)
	}
	if err := e.client.PushJSON(edgeWS.TypeFullSync, fsync); err != nil {
		m.log.Warn("edgews/manager: full_sync", "edge", e.nodeName, "err", err)
		return
	}

	// Les proxies vivent en YAML côté passerelle : une passerelle resté hors ligne pendant une
	// publication doit les récupérer auprès de ses pairs.
	go m.syncProxiesFromPeers(ctx, e)

	// Certs en parallèle (binaires, séparés du full_sync JSON)
	go m.PushCerts(ctx)

	// Settings runtime
	if s != (Settings{}) {
		go func() {
			if err := e.client.PushJSON(edgeWS.TypePushSettings, s); err != nil {
				m.log.Warn("edgews/manager: push settings", "edge", e.nodeName, "err", err)
			}
		}()
	}

	// Peers Raft
	go m.PushClusterPeers(ctx)
	// Peers gateway LB cross-passerelle
	go m.PushGatewayPeers(ctx)
	// Délégations
	go m.PushDelegations(ctx)

	// Portail d'accès (config par passerelle)
	go func() {
		cfg := api.LoadPortalConfigForEdge(m.db, e.nodeName)
		if err := e.client.PushJSON(edgeWS.TypePushPortal, cfg); err != nil {
			m.log.Warn("edgews/manager: push portal", "edge", e.nodeName, "err", err)
		}
	}()
	go func() {
		tpls := api.LoadPortalPageTemplatesForPush(m.db)
		if err := e.client.PushJSON(edgeWS.TypePushPortalTemplates, tpls); err != nil {
			m.log.Warn("edgews/manager: push portal templates", "edge", e.nodeName, "err", err)
		}
	}()

	// Config Sentinel (threat engine) — poussée après le full_sync
	go func() {
		if cfg := m.loadThreatConfig(ctx, e.id); cfg != nil {
			if err := e.client.PushJSON(edgeWS.TypePushThreatConfig, cfg); err != nil {
				m.log.Warn("edgews/manager: push threat config", "edge", e.nodeName, "err", err)
			}
		}
	}()

	// Règles automatiques — poussées après le full_sync
	go m.PushAutoRules(ctx)

	// Config tunnel peers — poussée si présente
	go func() {
		var nodeUUID string
		if err := m.db.QueryRowContext(ctx,
			`SELECT id FROM nodes WHERE node_name=?`, e.nodeName).Scan(&nodeUUID); err == nil {
			m.PushTunnelConfig(ctx, nodeUUID)
		}
	}()

	m.log.Info("edgews/manager: full_sync envoyé", "edge", e.nodeName)
}

// --- Chargement des données depuis la DB ---

// loadDelegationBindings charge les délégations actives (IDs normalisés vers UUID token).
func (m *Manager) loadDelegationBindings(ctx context.Context) []delegation.Binding {
	rows, err := m.db.QueryContext(ctx, `
		SELECT domain, edge_id, delegated_to_edge_id
		FROM domains
		WHERE delegated_to_edge_id != '' AND delegated_endpoint != ''`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []delegation.Binding
	for rows.Next() {
		var b delegation.Binding
		if err := rows.Scan(&b.Domain, &b.ResponsibleEdgeID, &b.TargetEdgeID); err != nil {
			continue
		}
		if id := m.resolveTokenEdgeID(ctx, b.ResponsibleEdgeID); id != "" {
			b.ResponsibleEdgeID = id
		}
		if id := m.resolveTokenEdgeID(ctx, b.TargetEdgeID); id != "" {
			b.TargetEdgeID = id
		}
		out = append(out, b)
	}
	return out
}

// FilterRoutesForEdge applique RBAC + exclusion des hosts délégués (pour GET /internal/v1/routes).
func (m *Manager) FilterRoutesForEdge(ctx context.Context, edgeID, nodeName, rbacRole string, scopes []rbac.Scope, routes []router.Route) []router.Route {
	filtered := rbac.FilterRoutesByScopes(rbacRole, scopes, routes)
	return delegation.FilterRoutesForEdge(edgeID, nodeName, filtered, m.loadDelegationBindings(ctx))
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
		return m.loadSnippetsFromDisk(), nil
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
	if len(list) == 0 {
		if disk := m.loadSnippetsFromDisk(); len(disk) > 0 {
			return disk, nil
		}
		return []json.RawMessage{}, nil
	}
	m.writeJSONFile("snippets.json", list)
	return list, nil
}

func (m *Manager) loadSnippetsFromDisk() []json.RawMessage {
	return m.readJSONArrayFile("snippets.json")
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
		return m.loadAuthProvidersFromDisk(), nil
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
	if len(list) == 0 {
		if disk := m.loadAuthProvidersFromDisk(); len(disk) > 0 {
			return disk, nil
		}
		return []json.RawMessage{}, nil
	}
	m.writeJSONFile("auth_providers.json", list)
	return list, nil
}

func (m *Manager) loadAuthProvidersFromDisk() []json.RawMessage {
	return m.readJSONArrayFile("auth_providers.json")
}

// writeJSONFile persiste une slice JSON dans dataDir/<filename>.
func (m *Manager) writeJSONFile(filename string, v any) {
	if m.dataDir == "" {
		return
	}
	if err := os.MkdirAll(m.dataDir, 0o700); err != nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	_ = os.WriteFile(filepath.Join(m.dataDir, filename), b, 0o600)
}

// readJSONArrayFile lit un fichier JSON de dataDir et retourne le tableau.
func (m *Manager) readJSONArrayFile(filename string) []json.RawMessage {
	if m.dataDir == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(m.dataDir, filename))
	if err != nil {
		return nil
	}
	var list []json.RawMessage
	if err := json.Unmarshal(b, &list); err != nil {
		return nil
	}
	return list
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

// loadThreatConfig charge la config du Sentinel depuis la DB pour une passerelle donné.
func (m *Manager) loadThreatConfig(ctx context.Context, edgeID string) json.RawMessage {
	key := "threat_engine_config"
	if edgeID != "" {
		key = "threat_engine_config:" + edgeID
	}
	var val string
	_ = m.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&val)
	if val == "" {
		return nil
	}
	return json.RawMessage(val)
}

// PushServerConfig envoie les timeouts HTTP/QUIC à toutes les passerelles via WS.
func (m *Manager) PushServerConfig(ctx context.Context, cfg any) {
	body, err := json.Marshal(cfg)
	if err != nil {
		return
	}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(edgeWS.TypePushServerConfig, json.RawMessage(body)); err != nil {
				m.log.Warn("edgews: push server config", "edge", e.nodeName, "err", err)
			}
		}()
	}
}

// PushF2BConfig envoie la config Fail2Ban à une passerelle spécifique (ou tous si edgeRef vide).
func (m *Manager) PushF2BConfig(ctx context.Context, edgeRef string, cfg any) {
	body, err := json.Marshal(cfg)
	if err != nil {
		return
	}
	entries := m.allEntries()
	for _, e := range entries {
		if edgeRef != "" && e.nodeName != edgeRef && e.id != edgeRef {
			continue
		}
		e := e
		go func() {
			if err := e.client.PushJSON(edgeWS.TypePushF2BConfig, json.RawMessage(body)); err != nil {
				m.log.Warn("edgews: push f2b config", "edge", e.nodeName, "err", err)
			}
		}()
	}
}

// handleCrowdSecDecisions reçoit les nouvelles décisions CrowdSec de passerelle et les persiste en DB.
func (m *Manager) handleCrowdSecDecisions(raw json.RawMessage) {
	if m.db == nil || len(raw) == 0 {
		return
	}
	var p edgeWS.CrowdSecDecisionsPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return
	}
	for _, d := range p.Added {
		if d.Value == "" {
			continue
		}
		banID := "crowdsec:" + d.Value
		m.db.Exec( //nolint:errcheck
			`INSERT INTO security_bans (id, ip, domain, reason, source, expires_at)
			 VALUES (?, ?, '', ?, 'crowdsec', NULL)
			 ON CONFLICT(id) DO NOTHING`,
			banID, d.Value, d.Scenario,
		)
		m.db.Exec( //nolint:errcheck
			`INSERT OR IGNORE INTO security_threats (ip, scenario, origin, type, scope, node_name)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			d.Value, d.Scenario, d.Origin, d.Type, d.Scope, p.NodeName,
		)
	}
	for _, d := range p.Deleted {
		if d.Value == "" {
			continue
		}
		banID := "crowdsec:" + d.Value
		m.db.Exec(`DELETE FROM security_bans WHERE id=?`, banID)            //nolint:errcheck
		m.db.Exec(`DELETE FROM security_threats WHERE ip=? AND scenario=?`, //nolint:errcheck
			d.Value, d.Scenario)
	}
}

// PushCrowdSecConfig envoie la config CrowdSec à une passerelle spécifique (ou tous si edgeRef vide).
func (m *Manager) PushCrowdSecConfig(ctx context.Context, edgeRef string, cfg any) {
	body, err := json.Marshal(cfg)
	if err != nil {
		return
	}
	for _, e := range m.allEntries() {
		if edgeRef != "" && e.nodeName != edgeRef && e.id != edgeRef {
			continue
		}
		e := e
		go func() {
			if err := e.client.PushJSON(edgeWS.TypePushCrowdSecConfig, json.RawMessage(body)); err != nil {
				m.log.Warn("edgews: push crowdsec config", "edge", e.nodeName, "err", err)
			}
		}()
	}
}

// handleRuleFired reçoit un ExecLog de règle automatique depuis passerelle et le persiste en DB.
func (m *Manager) handleRuleFired(raw json.RawMessage) {
	if m.db == nil || len(raw) == 0 {
		return
	}
	var p edgeWS.RuleFiredPayload
	if err := json.Unmarshal(raw, &p); err != nil || p.RuleID == "" {
		return
	}
	detail, _ := json.Marshal(p.Detail)
	matched, taken := 0, 0
	if p.CondResult {
		matched = 1
	}
	if p.ActionTaken {
		taken = 1
	}
	m.db.Exec( //nolint:errcheck
		`INSERT INTO rules_engine_history (rule_id, cond_result, action_taken, detail, error)
		 VALUES (?, ?, ?, ?, ?)`,
		p.RuleID, matched, taken, string(detail), p.Error,
	)
	if p.CondResult && p.ActionTaken {
		m.db.Exec( //nolint:errcheck
			`UPDATE rules_engine_rules SET last_fired_at=CURRENT_TIMESTAMP,
			 fire_count=fire_count+1 WHERE id=?`, p.RuleID,
		)
		// Si l'action est un ban IP, persister dans security_bans pour agrégation.
		if p.ActionType == "ban_ip" && p.Detail != nil {
			if ip, _ := p.Detail["ip"].(string); ip != "" {
				reason, _ := p.Detail["ban_reason"].(string)
				expiresAt, _ := p.Detail["ban_expires_at"].(string)
				node := p.NodeName
				if node == "" {
					node = "edge"
				}
				source := "rules_engine:" + node
				banID := "re:" + node + ":" + ip
				if expiresAt != "" {
					m.db.Exec( //nolint:errcheck
						`INSERT OR REPLACE INTO security_bans (id, ip, domain, reason, source, expires_at)
						 VALUES (?, ?, '', ?, ?, ?)`,
						banID, ip, reason, source, expiresAt,
					)
				} else {
					m.db.Exec( //nolint:errcheck
						`INSERT OR REPLACE INTO security_bans (id, ip, domain, reason, source)
						 VALUES (?, ?, '', ?, ?)`,
						banID, ip, reason, source,
					)
				}
				m.db.Exec( //nolint:errcheck
					`INSERT INTO security_ban_history (ip, domain, action, reason, source, ban_id)
					 VALUES (?, '', 'banned', ?, ?, ?)`,
					ip, reason, source, banID,
				)
			}
		}
	}
}

// PushAutoRules envoie toutes les règles automatiques actives à toutes les passerelles.
func (m *Manager) PushAutoRules(ctx context.Context) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT id, name, description, enabled, condition_json, action_json, cooldown_sec
		 FROM rules_engine_rules ORDER BY created_at`)
	if err != nil {
		m.log.Error("edgews/manager: lecture règles automatiques", "err", err)
		return
	}
	defer rows.Close()

	type ruleRow struct {
		ID          string          `json:"id"`
		Name        string          `json:"name"`
		Description string          `json:"description,omitempty"`
		Enabled     bool            `json:"enabled"`
		Condition   json.RawMessage `json:"condition"`
		Action      json.RawMessage `json:"action"`
		CooldownSec int             `json:"cooldown_sec"`
	}
	var rules []ruleRow
	for rows.Next() {
		var r ruleRow
		var condJSON, actionJSON string
		var enabled int
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &enabled, &condJSON, &actionJSON, &r.CooldownSec); err != nil {
			continue
		}
		r.Enabled = enabled == 1
		r.Condition = json.RawMessage(condJSON)
		r.Action = json.RawMessage(actionJSON)
		rules = append(rules, r)
	}
	if rules == nil {
		rules = []ruleRow{}
	}
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(edgeWS.TypePushAutoRules, rules); err != nil {
				m.log.Warn("edgews/manager: push auto_rules", "edge", e.nodeName, "err", err)
			}
		}()
	}
}

// PushTunnelConfig envoie la config peers tunnel mTLS à la passerelle identifié par son node UUID (table nodes).
func (m *Manager) PushTunnelConfig(ctx context.Context, nodeID string) {
	// Résoudre le node_name depuis l'UUID de la table nodes
	var nodeName string
	if err := m.db.QueryRowContext(ctx,
		`SELECT node_name FROM nodes WHERE id=?`, nodeID).Scan(&nodeName); err != nil {
		return
	}
	// Lire la config tunnel
	var raw string
	if err := m.db.QueryRowContext(ctx,
		`SELECT config FROM node_tunnel_configs WHERE node_id=?`, nodeID).Scan(&raw); err != nil {
		return // pas de config → rien à pousser
	}
	type tunnelPeer struct {
		Name string `json:"name"`
		Addr string `json:"addr"`
	}
	type tunnelCfg struct {
		Peers []tunnelPeer `json:"peers"`
	}
	var cfg tunnelCfg
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return
	}
	// Trouver l'entrée WS par node_name
	m.mu.RLock()
	var target *edgeEntry
	for _, e := range m.edges {
		if e.nodeName == nodeName {
			target = e
			break
		}
	}
	m.mu.RUnlock()
	if target == nil || target.client == nil {
		return
	}
	if err := target.client.PushJSON(edgeWS.TypePushTunnelConfig, cfg); err != nil {
		m.log.Warn("edgews/manager: push tunnel_config", "edge", target.nodeName, "err", err)
	}
}

// PushThreatConfig envoie la config du Sentinel à la passerelle edgeRef (nom ou id), ou à tous si vide.
func (m *Manager) PushThreatConfig(ctx context.Context, edgeRef string, cfg any) {
	body, err := json.Marshal(cfg)
	if err != nil {
		return
	}
	for _, e := range m.allEntries() {
		if edgeRef != "" && e.nodeName != edgeRef && e.id != edgeRef {
			continue
		}
		e := e
		go func() {
			if err := e.client.PushJSON(edgeWS.TypePushThreatConfig, json.RawMessage(body)); err != nil {
				m.log.Warn("edgews: push threat config", "edge", e.nodeName, "err", err)
			}
		}()
	}
}
