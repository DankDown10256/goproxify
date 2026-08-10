// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package ws implémente le hub WebSocket du plan de contrôle Goproxify.
// Admin et Agent initialisent des connexions WS persistantes vers Core :8000.
// Core ne contacte jamais Admin ni Agent de manière sortante.
package ws

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"

	"github.com/vincamok/goproxify/internal/core/metrics"
)

const (
	pingInterval    = 30 * time.Second
	pingTimeout     = 10 * time.Second
	agentOfflineGrace = 90 * time.Second
	hmacRotateInterval = 1 * time.Hour
)

// MessageHandler est une fonction appelée à la réception d'un message WS.
type MessageHandler func(connID string, msg Message) error

// Hub gère toutes les connexions WebSocket actives du plan de contrôle.
type Hub struct {
	mu sync.RWMutex

	adminConns map[string]*adminConn // key = nodeID (ou adresse)
	agentConns map[string]*agentConn // key = agentName

	adminSecret string // clé HMAC Admin→Core (vide = authentification désactivée)

	onAdminMsg MessageHandler // appelé pour chaque message Admin reçu
	onAgentMsg MessageHandler // appelé pour chaque message Agent reçu

	log *slog.Logger

	// Pending agents awaiting approval (agentID → agentConn)
	pendingMu     sync.RWMutex
	pendingAgents map[string]*agentConn

	// Pré-approbations Admin (agent id ou name) avant que l'Agent se connecte
	preApprovedMu sync.Mutex
	preApproved   map[string]struct{}

	// Persistance des HMACs approuvés (survit aux redémarrages du Core)
	hmacStore *AgentHMACStore

	// JOIN_TOKEN usage unique
	joinStore *JoinTokenStore

	// Callbacks pour notifier le reste du Core
	onAgentPending  func(agentID, agentName, version string) // Agent en attente d'approbation
	onJoinTokenUsed func(joinToken string)                   // optionnel : révoquer dans tokenStore Core
}

// adminConn représente une connexion WS Admin active.
type adminConn struct {
	id   string
	conn *websocket.Conn
	seq  atomic.Int64
	mu   sync.Mutex
}

// agentConn représente une connexion WS Agent active.
type agentConn struct {
	id       string // agentID interne
	name     string
	version  string
	conn     *websocket.Conn
	seq      atomic.Int64
	mu       sync.Mutex
	hmac     string // secret HMAC courant
	approved bool
	lastSeen time.Time
}

// NewHub crée un nouveau Hub WebSocket.
func NewHub(adminHMACSecret string, log *slog.Logger) *Hub {
	return &Hub{
		adminConns:    make(map[string]*adminConn),
		agentConns:    make(map[string]*agentConn),
		pendingAgents: make(map[string]*agentConn),
		preApproved:   make(map[string]struct{}),
		adminSecret:   adminHMACSecret,
		hmacStore:     NewAgentHMACStore("/etc/goproxify/agent-hmacs.json"),
		joinStore:     NewJoinTokenStore("/etc/goproxify/join-tokens-used.json"),
		log:           log,
	}
}

// SetJoinTokenStore remplace le store JOIN_TOKEN (tests / chemins custom).
func (h *Hub) SetJoinTokenStore(s *JoinTokenStore) { h.joinStore = s }

// SetHMACStore remplace le store HMAC (tests / chemins custom).
func (h *Hub) SetHMACStore(s *AgentHMACStore) { h.hmacStore = s }

// SetJoinTokenUsedCallback est appelé après consommation réussie d'un JOIN_TOKEN
// (ex: révoquer le token dans le tokenStore local du Core).
func (h *Hub) SetJoinTokenUsedCallback(fn func(joinToken string)) {
	h.onJoinTokenUsed = fn
}

// SetAdminMessageHandler configure le handler pour les messages Admin→Core.
func (h *Hub) SetAdminMessageHandler(fn MessageHandler) { h.onAdminMsg = fn }

// SetAgentMessageHandler configure le handler pour les messages Agent→Core.
func (h *Hub) SetAgentMessageHandler(fn MessageHandler) { h.onAgentMsg = fn }

// SetAgentPendingCallback configure le callback appelé quand un Agent attend l'approbation.
func (h *Hub) SetAgentPendingCallback(fn func(agentID, agentName, version string)) {
	h.onAgentPending = fn
}

// ServeAdmin gère une connexion WS entrante d'un Admin.
func (h *Hub) ServeAdmin(w http.ResponseWriter, r *http.Request) {
	if err := ValidateAdminHMAC(r, h.adminSecret); err != nil {
		h.log.Warn("ws/admin: authentification refusée", "err", err, "remote", r.RemoteAddr)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := websocket.Accept(w, r, AcceptOpts())
	if err != nil {
		h.log.Warn("ws/admin: upgrade WS échoué", "err", err)
		return
	}
	conn.SetReadLimit(4 * 1024 * 1024) // 4 MiB — full_sync et batch de routes peuvent être volumineux

	nodeID := r.Header.Get("X-Node-ID")
	if nodeID == "" {
		nodeID = r.RemoteAddr
	}

	ac := &adminConn{id: nodeID, conn: conn}
	h.mu.Lock()
	h.adminConns[nodeID] = ac
	h.mu.Unlock()
	metrics.WSConnectionsActive.WithLabelValues("admin").Inc()

	h.log.Info("ws/admin: connexion établie", "node", nodeID)
	defer func() {
		h.mu.Lock()
		delete(h.adminConns, nodeID)
		h.mu.Unlock()
		metrics.WSConnectionsActive.WithLabelValues("admin").Dec()
		conn.Close(websocket.StatusNormalClosure, "")
		h.log.Info("ws/admin: connexion fermée", "node", nodeID)
	}()

	h.readLoop(r.Context(), ac)
}

// ServeAgent gère une connexion WS entrante d'un Agent.
func (h *Hub) ServeAgent(w http.ResponseWriter, r *http.Request) {
	joinToken := ExtractJoinToken(r)
	agentHMAC := ExtractAgentHMAC(r)

	conn, err := websocket.Accept(w, r, AcceptOpts())
	if err != nil {
		h.log.Warn("ws/agent: upgrade WS échoué", "err", err)
		return
	}
	conn.SetReadLimit(4 * 1024 * 1024) // 4 MiB

	// Lire le premier message "register" pour obtenir les infos de l'Agent
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	var regMsg Message
	if err := wsjson.Read(ctx, conn, &regMsg); err != nil {
		cancel()
		conn.Close(websocket.StatusPolicyViolation, "message register attendu")
		return
	}
	cancel()

	if regMsg.Type != TypeAgentRegister {
		conn.Close(websocket.StatusPolicyViolation, "premier message doit être 'register'")
		return
	}

	var regPayload struct {
		AgentID  string `json:"agent_id"`
		Name     string `json:"name"`
		Version  string `json:"version"`
	}
	if err := json.Unmarshal(regMsg.Payload, &regPayload); err != nil {
		conn.Close(websocket.StatusPolicyViolation, "payload register invalide")
		return
	}

	agentID := regPayload.AgentID
	if agentID == "" {
		agentID = regPayload.Name
	}

	ac := &agentConn{
		id:       agentID,
		name:     regPayload.Name,
		version:  regPayload.Version,
		conn:     conn,
		lastSeen: time.Now(),
	}

	// Vérifier si l'Agent est déjà approuvé (connexion de régime via HMAC)
	if agentHMAC != "" {
		// Cherche d'abord dans les connexions actives, puis dans le store persistant
		var storedHMAC string
		h.mu.RLock()
		if existing, ok := h.agentConns[agentID]; ok {
			existing.mu.Lock()
			storedHMAC = existing.hmac
			existing.mu.Unlock()
		}
		h.mu.RUnlock()
		if storedHMAC == "" {
			storedHMAC, _ = h.hmacStore.Get(agentID)
		}
		if storedHMAC != "" && ValidateAgentHMAC(agentHMAC, storedHMAC) {
			ac.hmac = storedHMAC
			ac.approved = true
		} else {
			conn.Close(websocket.StatusPolicyViolation, "agent_hmac invalide")
			h.log.Warn("ws/agent: HMAC invalide", "agent", agentID)
			return
		}
	} else if joinToken != "" {
		// Premier démarrage : JOIN_TOKEN usage unique → état pending
		if err := h.joinStore.Consume(joinToken); err != nil {
			conn.Close(websocket.StatusPolicyViolation, "join token invalide ou déjà utilisé")
			h.log.Warn("ws/agent: JOIN_TOKEN refusé", "agent", agentID, "err", err)
			return
		}
		if h.onJoinTokenUsed != nil {
			h.onJoinTokenUsed(joinToken)
		}
		h.pendingMu.Lock()
		h.pendingAgents[agentID] = ac
		h.pendingMu.Unlock()

		if h.onAgentPending != nil {
			h.onAgentPending(agentID, regPayload.Name, regPayload.Version)
		}
		h.log.Info("ws/agent: Agent en attente d'approbation", "agent", agentID, "version", regPayload.Version)

		ac.mu.Lock()
		already := ac.approved
		ac.mu.Unlock()
		if !already && h.consumePreApproval(agentID, regPayload.Name) {
			if err := h.ApproveAgent(agentID); err != nil {
				h.log.Warn("ws/agent: auto-approbation échouée", "agent", agentID, "err", err)
			}
		}
	} else {
		conn.Close(websocket.StatusPolicyViolation, "X-Join-Token ou X-Agent-HMAC requis")
		return
	}

	h.mu.Lock()
	h.agentConns[agentID] = ac
	h.mu.Unlock()
	metrics.WSConnectionsActive.WithLabelValues("agent").Inc()

	h.log.Info("ws/agent: connexion établie", "agent", agentID, "approved", ac.approved)
	defer func() {
		h.unregisterAgent(agentID, ac)
		metrics.WSConnectionsActive.WithLabelValues("agent").Dec()
		conn.Close(websocket.StatusNormalClosure, "")
		h.log.Info("ws/agent: connexion fermée", "agent", agentID)
	}()

	// Démarrer la rotation HMAC si approuvé
	if ac.approved {
		go h.hmacRotateLoop(r.Context(), ac)
	}

	h.readAgentLoop(r.Context(), ac)
}

// unregisterAgent retire ac des maps uniquement s'il est encore l'entrée courante
// (évite qu'un defer de reconnect efface le successeur — revue P1 #10).
func (h *Hub) unregisterAgent(agentID string, ac *agentConn) {
	h.mu.Lock()
	if cur, ok := h.agentConns[agentID]; ok && cur == ac {
		delete(h.agentConns, agentID)
	}
	h.mu.Unlock()
	h.pendingMu.Lock()
	if cur, ok := h.pendingAgents[agentID]; ok && cur == ac {
		delete(h.pendingAgents, agentID)
	}
	h.pendingMu.Unlock()
}

// ApproveAgent approuve un Agent en attente et lui envoie le premier agent_hmac.
// Si l'Agent n'est pas encore connecté, enregistre une pré-approbation (id ou name).
func (h *Hub) ApproveAgent(agentID string) error {
	if agentID == "" {
		return fmt.Errorf("agent_id vide")
	}

	// Déjà approuvé (ex. callback Admin + pré-approbation) → no-op.
	h.mu.RLock()
	if existing, ok := h.agentConns[agentID]; ok {
		existing.mu.Lock()
		done := existing.approved
		existing.mu.Unlock()
		if done {
			h.mu.RUnlock()
			h.clearPreApproval(agentID)
			return nil
		}
	} else {
		for _, existing := range h.agentConns {
			if existing.name == agentID || existing.id == agentID {
				existing.mu.Lock()
				done := existing.approved
				existing.mu.Unlock()
				if done {
					h.mu.RUnlock()
					h.clearPreApproval(agentID, existing.name, existing.id)
					return nil
				}
			}
		}
	}
	h.mu.RUnlock()

	h.pendingMu.Lock()
	ac, key, ok := h.findPendingLocked(agentID)
	h.pendingMu.Unlock()
	if !ok {
		h.preApprovedMu.Lock()
		if h.preApproved == nil {
			h.preApproved = make(map[string]struct{})
		}
		h.preApproved[agentID] = struct{}{}
		h.preApprovedMu.Unlock()
		h.log.Info("ws/agent: pré-approbation enregistrée (Agent non connecté)", "agent", agentID)
		return nil
	}

	newHMAC, err := GenerateAgentHMAC()
	if err != nil {
		return err
	}

	ac.mu.Lock()
	if ac.approved {
		ac.mu.Unlock()
		h.clearPreApproval(agentID, ac.name, ac.id)
		return nil
	}
	ac.hmac = newHMAC
	ac.approved = true
	ac.mu.Unlock()

	h.pendingMu.Lock()
	delete(h.pendingAgents, key)
	h.pendingMu.Unlock()
	h.clearPreApproval(agentID, ac.name, ac.id)

	payload, _ := NewMessage(ac.seq.Add(1), TypeApprove, ApprovePayload{
		AgentID:   agentID,
		AgentHMAC: newHMAC,
	})
	if err := h.sendToAgent(ac, payload); err != nil {
		return err
	}

	// Persister le HMAC pour que l'Agent puisse se reconnecter après un redémarrage du Core.
	if err := h.hmacStore.Set(key, newHMAC); err != nil {
		h.log.Error("ws/agent: persistance HMAC échouée", "agent", agentID, "err", err)
		return fmt.Errorf("persistance HMAC: %w", err)
	}
	if ac.name != "" && ac.name != key {
		_ = h.hmacStore.Set(ac.name, newHMAC)
	}

	go h.hmacRotateLoop(context.Background(), ac)
	h.log.Info("ws/agent: Agent approuvé", "agent", agentID)
	return nil
}

func (h *Hub) findPendingLocked(agentID string) (*agentConn, string, bool) {
	if ac, ok := h.pendingAgents[agentID]; ok {
		return ac, agentID, true
	}
	for id, p := range h.pendingAgents {
		if p.name == agentID || p.id == agentID {
			return p, id, true
		}
	}
	return nil, "", false
}

func (h *Hub) consumePreApproval(ids ...string) bool {
	h.preApprovedMu.Lock()
	defer h.preApprovedMu.Unlock()
	if h.preApproved == nil {
		return false
	}
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, ok := h.preApproved[id]; ok {
			delete(h.preApproved, id)
			return true
		}
	}
	return false
}

func (h *Hub) clearPreApproval(ids ...string) {
	h.preApprovedMu.Lock()
	defer h.preApprovedMu.Unlock()
	for _, id := range ids {
		if id != "" {
			delete(h.preApproved, id)
		}
	}
}

// RevokeAgent ferme la connexion WS d'un Agent, retire le pending et invalide son HMAC.
// agentID peut être l'id interne ou le name.
func (h *Hub) RevokeAgent(agentID string) error {
	if agentID == "" {
		return fmt.Errorf("agent_id vide")
	}

	h.clearPreApproval(agentID)

	h.mu.Lock()
	ac, key := h.findAgentLocked(agentID)
	if ac != nil {
		delete(h.agentConns, key)
	}
	h.mu.Unlock()

	h.pendingMu.Lock()
	if p, ok := h.pendingAgents[agentID]; ok {
		delete(h.pendingAgents, agentID)
		if ac == nil {
			ac = p
			key = agentID
		}
	} else {
		for id, p := range h.pendingAgents {
			if p.name == agentID || p.id == agentID {
				delete(h.pendingAgents, id)
				if ac == nil {
					ac = p
					key = id
				}
				break
			}
		}
	}
	h.pendingMu.Unlock()

	if err := h.hmacStore.Delete(agentID); err != nil {
		h.log.Warn("ws/agent: suppression HMAC échouée", "agent", agentID, "err", err)
	}
	if key != "" && key != agentID {
		if err := h.hmacStore.Delete(key); err != nil {
			h.log.Warn("ws/agent: suppression HMAC échouée", "agent", key, "err", err)
		}
	}
	if ac != nil && ac.name != "" {
		if err := h.hmacStore.Delete(ac.name); err != nil {
			h.log.Warn("ws/agent: suppression HMAC échouée", "agent", ac.name, "err", err)
		}
	}

	if ac != nil {
		ac.mu.Lock()
		conn := ac.conn
		ac.mu.Unlock()
		if conn != nil {
			_ = conn.Close(websocket.StatusPolicyViolation, "agent révoqué")
		}
		h.log.Info("ws/agent: Agent révoqué — connexion fermée", "agent", agentID, "key", key)
	} else {
		h.log.Info("ws/agent: révocation enregistrée (Agent non connecté)", "agent", agentID)
	}
	return nil
}

// findAgentLocked cherche un Agent par id ou name. Appeler sous h.mu.
func (h *Hub) findAgentLocked(agentID string) (*agentConn, string) {
	if ac, ok := h.agentConns[agentID]; ok {
		return ac, agentID
	}
	for id, ac := range h.agentConns {
		if ac.name == agentID || ac.id == agentID {
			return ac, id
		}
	}
	return nil, ""
}

// IsAgentConnected indique si un Agent est connecté via WS.
func (h *Hub) IsAgentConnected(name string) bool {
	h.mu.RLock()
	_, ok := h.agentConns[name]
	h.mu.RUnlock()
	return ok
}

// SendToAgentByName envoie un message à un Agent identifié par son nom.
func (h *Hub) SendToAgentByName(name string, msg Message) error {
	h.mu.RLock()
	ac, ok := h.agentConns[name]
	h.mu.RUnlock()
	if !ok {
		return fmt.Errorf("agent %q non connecté via WS", name)
	}
	return h.sendToAgent(ac, msg)
}

// BroadcastToAdmins envoie un message à tous les Admins connectés.
func (h *Hub) BroadcastToAdmins(msg Message) {
	h.mu.RLock()
	conns := make([]*adminConn, 0, len(h.adminConns))
	for _, ac := range h.adminConns {
		conns = append(conns, ac)
	}
	h.mu.RUnlock()

	for _, ac := range conns {
		if err := h.sendToAdmin(ac, msg); err != nil {
			h.log.Warn("ws/admin: erreur envoi broadcast", "node", ac.id, "err", err)
		}
	}
}

// ConnectedAdmins retourne le nombre d'Admins connectés.
func (h *Hub) ConnectedAdmins() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.adminConns)
}

// ConnectedAgents retourne le nombre d'Agents connectés.
func (h *Hub) ConnectedAgents() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.agentConns)
}

func (h *Hub) sendToAdmin(ac *adminConn, msg Message) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := wsjson.Write(ctx, ac.conn, msg)
	if err == nil {
		metrics.WSMessagesSentTotal.WithLabelValues("admin", msg.Type).Inc()
	}
	return err
}

func (h *Hub) sendToAgent(ac *agentConn, msg Message) error {
	ac.mu.Lock()
	defer ac.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err := wsjson.Write(ctx, ac.conn, msg)
	if err == nil {
		metrics.WSMessagesSentTotal.WithLabelValues("agent", msg.Type).Inc()
	}
	return err
}

// readLoop lit les messages d'une connexion Admin en boucle.
func (h *Hub) readLoop(ctx context.Context, ac *adminConn) {
	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()

	msgCh := make(chan Message, 16)
	errCh := make(chan error, 1)
	go func() {
		for {
			var msg Message
			if err := wsjson.Read(ctx, ac.conn, &msg); err != nil {
				errCh <- err
				return
			}
			msgCh <- msg
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-errCh:
			h.log.Debug("ws/admin: connexion terminée", "node", ac.id, "err", err)
			return
		case msg := <-msgCh:
			if h.onAdminMsg != nil {
				if err := h.onAdminMsg(ac.id, msg); err != nil {
					h.log.Warn("ws/admin: erreur traitement message", "type", msg.Type, "err", err)
				}
			}
		case <-pingTicker.C:
			pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
			err := ac.conn.Ping(pingCtx)
			cancel()
			if err != nil {
				h.log.Warn("ws/admin: ping timeout", "node", ac.id)
				return
			}
		}
	}
}

// readAgentLoop lit les messages d'une connexion Agent en boucle.
func (h *Hub) readAgentLoop(ctx context.Context, ac *agentConn) {
	pingTicker := time.NewTicker(pingInterval)
	defer pingTicker.Stop()

	msgCh := make(chan Message, 32)
	errCh := make(chan error, 1)
	go func() {
		for {
			var msg Message
			if err := wsjson.Read(ctx, ac.conn, &msg); err != nil {
				errCh <- err
				return
			}
			msgCh <- msg
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-errCh:
			h.log.Debug("ws/agent: connexion terminée", "agent", ac.id, "err", err)
			return
		case msg := <-msgCh:
			ac.lastSeen = time.Now()
			if msg.Type == TypePong {
				continue
			}
			if h.onAgentMsg != nil {
				if err := h.onAgentMsg(ac.id, msg); err != nil {
					h.log.Warn("ws/agent: erreur traitement message", "type", msg.Type, "err", err)
				}
			}
		case <-pingTicker.C:
			pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
			err := ac.conn.Ping(pingCtx)
			cancel()
			if err != nil {
				h.log.Warn("ws/agent: ping timeout", "agent", ac.id)
				return
			}
		}
	}
}

// hmacRotateLoop émet un nouveau agent_hmac toutes les heures.
func (h *Hub) hmacRotateLoop(ctx context.Context, ac *agentConn) {
	ticker := time.NewTicker(hmacRotateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			newHMAC, err := GenerateAgentHMAC()
			if err != nil {
				h.log.Error("ws/agent: rotation HMAC échouée", "agent", ac.id, "err", err)
				continue
			}
			ac.mu.Lock()
			ac.hmac = newHMAC
			ac.mu.Unlock()

			// Persister le nouveau HMAC avant envoi (l'Agent peut redémarrer entre les deux).
			if err := h.hmacStore.Set(ac.id, newHMAC); err != nil {
				h.log.Error("ws/agent: persistance rotate HMAC échouée", "agent", ac.id, "err", err)
				continue
			}

			msg, _ := NewMessage(ac.seq.Add(1), TypeRotateHMAC, RotateHMACPayload{AgentHMAC: newHMAC})
			if err := h.sendToAgent(ac, msg); err != nil {
				h.log.Warn("ws/agent: envoi rotate_hmac échoué", "agent", ac.id, "err", err)
				return
			}
			h.log.Debug("ws/agent: HMAC rotatif envoyé", "agent", ac.id)
		}
	}
}
