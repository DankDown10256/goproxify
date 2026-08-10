// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package corews fournit le client WebSocket persistant Admin→Core.
// Il remplace progressivement le pusher HTTP (internal/admin/corepush).
// Les méthodes publiques ont la même signature que corepush.Pusher
// pour permettre une migration transparente.
package corews

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	coreWS "github.com/vincamok/goproxify/internal/core/ws"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

const (
	reconnectBase = 1 * time.Second
	reconnectMax  = 60 * time.Second
	wsPath        = "/ws/admin"
)

// Client maintient une connexion WS persistante vers un Core.
// Il gère la reconnexion automatique avec backoff exponentiel.
type Client struct {
	coreID   string
	endpoint string // ex: http://goproxify-core:8000
	secret   string // clé HMAC partagée

	conn   *websocket.Conn
	connMu sync.Mutex
	writeMu sync.Mutex // sérialise les écritures WS (ordre FIFO des messages)
	seq    atomic.Int64

	// Queue des messages en attente lors d'une déconnexion.
	// Vidée en full_sync à la reconnexion.
	pendingMu sync.Mutex
	pending   []coreWS.Message

	log *slog.Logger

	// Callbacks pour le full_sync (appelé à chaque reconnexion).
	onFullSync func(ctx context.Context) error

	// Callback pour les messages entrants Core → Admin.
	onMsg func(coreWS.Message)

	ctx    context.Context
	cancel context.CancelFunc
}

// NewClient crée un nouveau client WS Admin→Core.
// onFullSync est appelé après chaque reconnexion pour ré-envoyer l'état complet.
// onMsg est appelé pour chaque message reçu du Core (peut être nil).
func NewClient(coreID, endpoint, hmacSecret string, onFullSync func(ctx context.Context) error, onMsg func(coreWS.Message), log *slog.Logger) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		coreID:     coreID,
		endpoint:   endpoint,
		secret:     hmacSecret,
		onFullSync: onFullSync,
		onMsg:      onMsg,
		log:        log.With("core", coreID),
		ctx:        ctx,
		cancel:     cancel,
	}
	go c.connectLoop()
	return c
}

// Close arrête le client et ferme la connexion.
func (c *Client) Close() {
	c.cancel()
	c.connMu.Lock()
	if c.conn != nil {
		c.conn.Close(websocket.StatusNormalClosure, "shutdown")
	}
	c.connMu.Unlock()
}

// Send envoie un message au Core. Si non connecté, le message est mis en queue.
func (c *Client) Send(msg coreWS.Message) {
	c.connMu.Lock()
	conn := c.conn
	c.connMu.Unlock()

	if conn == nil {
		c.pendingMu.Lock()
		c.pending = append(c.pending, msg)
		c.pendingMu.Unlock()
		return
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := wsjson.Write(ctx, conn, msg); err != nil {
		c.log.Warn("corews: erreur envoi message", "type", msg.Type, "err", err)
		c.connMu.Lock()
		c.conn = nil
		c.connMu.Unlock()
	}
}

// nextSeq retourne le prochain numéro de séquence.
func (c *Client) nextSeq() int64 {
	return c.seq.Add(1)
}

// connectLoop maintient la connexion WS avec backoff exponentiel.
func (c *Client) connectLoop() {
	backoff := reconnectBase
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		if err := c.connect(); err != nil {
			c.log.Warn("corews: connexion échouée", "err", err, "retry", backoff)
		}

		// Attendre avant de réessayer
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(backoff + coreWS.RandomJitter(backoff/5)):
		}

		// Backoff exponentiel avec cap
		backoff *= 2
		if backoff > reconnectMax {
			backoff = reconnectMax
		}
	}
}

// connect établit la connexion WS et effectue le full_sync initial.
func (c *Client) connect() error {
	wsURL := "ws" + c.endpoint[4:] + wsPath // http://... → ws://..../ws/admin
	if c.endpoint[:5] == "https" {
		wsURL = "wss" + c.endpoint[5:] + wsPath
	}

	header := http.Header{}
	header.Set("X-Node-ID", c.coreID)
	if c.secret != "" {
		sig := coreWS.BuildAdminSignature(c.secret, "GET", wsPath)
		header.Set("X-Goproxify-Signature", sig)
	}

	dialCtx, cancel := context.WithTimeout(c.ctx, 15*time.Second)
	conn, _, err := websocket.Dial(dialCtx, wsURL, &websocket.DialOptions{
		HTTPHeader: header,
	})
	cancel()
	if err != nil {
		return err
	}

	conn.SetReadLimit(4 * 1024 * 1024) // 4 MiB — full_sync peut être volumineux

	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()

	c.log.Info("corews: connexion WS établie", "url", wsURL)

	// Full sync après connexion
	if c.onFullSync != nil {
		if err := c.onFullSync(c.ctx); err != nil {
			c.log.Warn("corews: full_sync échoué", "err", err)
		}
	}

	// Vider la queue des messages en attente
	c.pendingMu.Lock()
	queued := c.pending
	c.pending = nil
	c.pendingMu.Unlock()
	for _, msg := range queued {
		c.Send(msg)
	}

	// Lire les messages entrants (Core → Admin) jusqu'à déconnexion
	for {
		var msg coreWS.Message
		if err := wsjson.Read(c.ctx, conn, &msg); err != nil {
			c.log.Debug("corews: connexion WS perdue", "err", err)
			break
		}
		c.log.Debug("corews: message reçu du Core", "type", msg.Type)
		if c.onMsg != nil {
			c.onMsg(msg)
		}
	}

	c.connMu.Lock()
	c.conn = nil
	c.connMu.Unlock()

	// Réinitialiser le backoff après une connexion réussie
	return nil
}

// --- Méthodes de push (même signature que corepush.Pusher) ---

// PushJSON envoie un message de type msgType avec le payload fourni.
func (c *Client) PushJSON(msgType string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	msg := coreWS.Message{
		Seq:     c.nextSeq(),
		Type:    msgType,
		Payload: b,
	}
	c.Send(msg)
	return nil
}
