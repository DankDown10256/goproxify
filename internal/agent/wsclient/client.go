// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package wsclient fournit le client WebSocket persistant Agent→Core.
// Il remplace progressivement la boucle HTTP heartbeat.
// Si la connexion WS est impossible, l'Agent retombe sur le heartbeat HTTP existant.
package wsclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	coreWS "github.com/vincamok/goproxify/internal/core/ws"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

const hmacPersistPath = "/etc/goproxify/agent.hmac"

// LoadPersistedHMAC charge le HMAC persisté depuis le run précédent, ou "".
func LoadPersistedHMAC() string {
	b, err := os.ReadFile(hmacPersistPath)
	if err != nil {
		return ""
	}
	return string(b)
}

func saveHMAC(hmac string) {
	_ = os.MkdirAll("/etc/goproxify", 0755)
	_ = os.WriteFile(hmacPersistPath, []byte(hmac), 0600)
}

const (
	reconnectBase = 1 * time.Second
	reconnectMax  = 60 * time.Second
	wsAgentPath   = "/ws/agent"
	heartbeatInterval = 30 * time.Second
	metricsInterval   = 10 * time.Second
)

// CommandHandler est appelé quand Core envoie une commande à l'Agent.
type CommandHandler func(action string, payload json.RawMessage)

// Client maintient la connexion WS persistante Agent→Core.
type Client struct {
	agentID   string
	agentName string
	version   string
	endpoint  string // URL du Core ex: http://goproxify-core:8000

	joinToken string // pour le bootstrap (premier démarrage)
	hmacSecret string // après approbation, stocké localement

	conn   *websocket.Conn
	connMu sync.Mutex
	seq    atomic.Int64

	onCommand CommandHandler // appelé pour les messages Core→Agent

	log *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	// Active indique si la connexion WS est établie.
	// Le heartbeat HTTP peut interroger ce flag pour savoir s'il doit prendre le relais.
	Active atomic.Bool
}

// NewClient crée un nouveau client WS Agent→Core.
// joinToken est utilisé au premier démarrage ; après approbation, hmacSecret est utilisé.
func NewClient(agentID, agentName, version, coreEndpoint, joinToken, hmacSecret string, onCommand CommandHandler, log *slog.Logger) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		agentID:    agentID,
		agentName:  agentName,
		version:    version,
		endpoint:   coreEndpoint,
		joinToken:  joinToken,
		hmacSecret: hmacSecret,
		onCommand:  onCommand,
		log:        log.With("agent", agentName),
		ctx:        ctx,
		cancel:     cancel,
	}
	go c.connectLoop()
	return c
}

// Close arrête le client WS.
func (c *Client) Close() {
	c.cancel()
	c.connMu.Lock()
	if c.conn != nil {
		c.conn.Close(websocket.StatusNormalClosure, "shutdown")
	}
	c.connMu.Unlock()
}

// IsActive retourne true si la connexion WS est actuellement établie.
func (c *Client) IsActive() bool { return c.Active.Load() }

// SendHeartbeat envoie un message heartbeat au Core.
func (c *Client) SendHeartbeat(cpuPct, memPct float64, runtimes []string, endpoint string) {
	c.sendJSON(coreWS.TypeAgentHeartbeat, map[string]any{
		"node_name":          c.agentName,
		"agent_name":         c.agentName,
		"endpoint":           endpoint,
		"cpu_pct":            cpuPct,
		"mem_pct":            memPct,
		"container_runtimes": runtimes,
	})
}

// SendContainers envoie la liste des conteneurs découverts.
func (c *Client) SendContainers(containers any) {
	c.sendJSON(coreWS.TypeAgentContainers, containers)
}

// SendMetrics envoie les métriques par conteneur pour le LB adaptatif.
func (c *Client) SendMetrics(metrics coreWS.AgentMetricsPayload) {
	c.sendJSON(coreWS.TypeAgentMetrics, metrics)
}

// SendEvent envoie un événement cycle de vie.
func (c *Client) SendEvent(event any) {
	c.sendJSON(coreWS.TypeAgentEvent, event)
}

// SendLog envoie un batch de logs.
func (c *Client) SendLog(logs any) {
	c.sendJSON(coreWS.TypeAgentLog, logs)
}

// SendShellData envoie un chunk stdout vers le Core.
func (c *Client) SendShellData(sessionID string, data []byte) {
	c.sendJSON(coreWS.TypeShellData, coreWS.ShellDataPayload{
		SessionID: sessionID,
		Data:      base64.StdEncoding.EncodeToString(data),
	})
}

// SendShellReady confirme que le docker exec est attaché.
func (c *Client) SendShellReady(sessionID string) {
	c.sendJSON(coreWS.TypeShellReady, coreWS.ShellReadyPayload{SessionID: sessionID})
}

// SendShellClose notifie la fin de session.
func (c *Client) SendShellClose(sessionID string) {
	c.sendJSON(coreWS.TypeShellClose, coreWS.ShellClosePayload{SessionID: sessionID})
}

// SendShellError signale une erreur d'ouverture exec.
func (c *Client) SendShellError(sessionID, errMsg string) {
	c.sendJSON(coreWS.TypeShellError, coreWS.ShellErrorPayload{SessionID: sessionID, Error: errMsg})
}

func (c *Client) sendJSON(msgType string, payload any) {
	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()
	if conn == nil {
		return
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return
	}
	msg := coreWS.Message{Seq: c.seq.Add(1), Type: msgType, Payload: b}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := wsjson.Write(ctx, conn, msg); err != nil {
		c.log.Warn("wsclient: erreur envoi", "type", msgType, "err", err)
		c.connMu.Lock()
		c.conn = nil
		c.connMu.Unlock()
		c.Active.Store(false)
	}
}

// connectLoop maintient la connexion WS avec backoff exponentiel + jitter.
func (c *Client) connectLoop() {
	backoff := reconnectBase
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		err := c.connect()
		c.Active.Store(false)
		if err != nil {
			c.log.Warn("wsclient: connexion échouée", "err", err, "retry", backoff)
		}

		select {
		case <-c.ctx.Done():
			return
		case <-time.After(backoff + coreWS.RandomJitter(backoff/5)):
		}
		backoff *= 2
		if backoff > reconnectMax {
			backoff = reconnectMax
		}
	}
}

// connect établit la connexion WS, envoie le message register, puis lit en boucle.
func (c *Client) connect() error {
	wsURL := "ws" + c.endpoint[4:] + wsAgentPath
	if len(c.endpoint) >= 5 && c.endpoint[:5] == "https" {
		wsURL = "wss" + c.endpoint[5:] + wsAgentPath
	}

	header := http.Header{}
	if c.hmacSecret != "" {
		header.Set("X-Agent-HMAC", c.hmacSecret)
	} else if c.joinToken != "" {
		header.Set("X-Join-Token", c.joinToken)
	} else {
		return nil // rien à présenter — ne pas tenter la connexion
	}

	dialCtx, cancel := context.WithTimeout(c.ctx, 15*time.Second)
	conn, _, err := websocket.Dial(dialCtx, wsURL, &websocket.DialOptions{
		HTTPHeader: header,
	})
	cancel()
	if err != nil {
		return err
	}

	// Envoyer le message register
	regMsg, _ := coreWS.NewMessage(c.seq.Add(1), coreWS.TypeAgentRegister, map[string]string{
		"agent_id": c.agentID,
		"name":     c.agentName,
		"version":  c.version,
	})
	ctx10s, cancel := context.WithTimeout(c.ctx, 10*time.Second)
	err = wsjson.Write(ctx10s, conn, regMsg)
	cancel()
	if err != nil {
		conn.Close(websocket.StatusInternalError, "register failed")
		return err
	}

	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()
	c.Active.Store(true)

	c.log.Info("wsclient: connexion WS établie", "url", wsURL)

	// Lecture des messages entrants (Core → Agent)
	for {
		var msg coreWS.Message
		if err := wsjson.Read(c.ctx, conn, &msg); err != nil {
			break
		}
		c.handleIncoming(msg)
	}

	c.connMu.Lock()
	c.conn = nil
	c.connMu.Unlock()
	c.Active.Store(false)
	c.log.Debug("wsclient: connexion WS perdue")
	return nil
}

// handleIncoming traite les messages Core → Agent.
func (c *Client) handleIncoming(msg coreWS.Message) {
	switch msg.Type {
	case coreWS.TypeApprove:
		var p coreWS.ApprovePayload
		if err := json.Unmarshal(msg.Payload, &p); err == nil {
			c.hmacSecret = p.AgentHMAC
			c.joinToken = "" // plus besoin du JOIN_TOKEN
			saveHMAC(p.AgentHMAC)
			c.log.Info("wsclient: Agent approuvé, HMAC reçu et persisté")
		}
	case coreWS.TypeRotateHMAC:
		var p coreWS.RotateHMACPayload
		if err := json.Unmarshal(msg.Payload, &p); err == nil {
			c.hmacSecret = p.AgentHMAC
			saveHMAC(p.AgentHMAC)
			c.log.Debug("wsclient: HMAC rotatif adopté et persisté")
		}
	case coreWS.TypePing:
		c.sendJSON(coreWS.TypePong, nil)
	case coreWS.TypeCommand, coreWS.TypeRescan:
		if c.onCommand != nil {
			c.onCommand(msg.Type, msg.Payload)
		}
	case coreWS.TypeShellOpen, coreWS.TypeShellData, coreWS.TypeShellClose:
		if c.onCommand != nil {
			c.onCommand(msg.Type, msg.Payload)
		}
	}
}
