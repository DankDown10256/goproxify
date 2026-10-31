// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package edgews fournit le client WebSocket persistant Admin→Passerelle.
// Il a remplacé l'ancien pusher HTTP, retiré depuis.
package edgews

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
	"github.com/vincamok/goproxify/internal/pairing"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

var wsReconnectsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "goproxify",
	Subsystem: "controlplane",
	Name:      "ws_reconnects_total",
	Help:      "Reconnexions WebSocket Admin→Passerelle (vue Admin).",
}, []string{"edge_id"})

const (
	reconnectBase = 1 * time.Second
	reconnectMax  = 60 * time.Second
	wsPath        = "/ws/admin"
)

// Client maintient une connexion WS persistante vers une passerelle.
// Il gère la reconnexion automatique avec backoff exponentiel.
type Client struct {
	edgeID   string
	nodeName string // nom de la passerelle : sa clé de canal peut s'en dériver quand l'identifiant n'est pas connu d'avance
	endpoint string // ex: http://goproxify-edge:8000
	secret   string // secret racine : signe le canal, ou en dérive la clé de la passerelle (avec edgeID)
	// rootKeys donne le secret racine courant et ses précédents (rotation), relus à chaque connexion ; nil = seulement secret.
	rootKeys func() []pairing.Key
	// preferName : la dernière connexion a été validée par la clé dérivée du nom ; on l'essaie d'abord, pour ne pas payer
	// un refus à chaque reconnexion. Ne concerne que les clés dérivées : la racine passe toujours en dernier.
	preferName atomic.Bool
	// lastKind : ce qui a validé la dernière connexion (signKind*). Ne sert qu'à ne journaliser un repli qu'une fois par
	// changement d'état : la clé dérivée du secret courant est toujours essayée en premier.
	lastKind atomic.Int32

	conn   *websocket.Conn
	connMu sync.Mutex
	writeMu sync.Mutex // sérialise les écritures WS (ordre FIFO des messages)
	seq    atomic.Int64

	// Queue des messages en attente lors d'une déconnexion.
	// Vidée en full_sync à la reconnexion.
	pendingMu sync.Mutex
	pending   []edgeWS.Message

	log *slog.Logger

	// Callbacks pour le full_sync (appelé à chaque reconnexion).
	onFullSync func(ctx context.Context) error

	// Callback pour les messages entrants passerelle → Admin.
	onMsg func(edgeWS.Message)

	ctx    context.Context
	cancel context.CancelFunc
}

// NewClient crée un nouveau client WS Admin→Passerelle.
// onFullSync est appelé après chaque reconnexion pour ré-envoyer l'état complet.
// onMsg est appelé pour chaque message reçu de la passerelle (peut être nil).
func NewClient(edgeID, nodeName, endpoint, hmacSecret string, rootKeys func() []pairing.Key, onFullSync func(ctx context.Context) error, onMsg func(edgeWS.Message), log *slog.Logger) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		edgeID:     edgeID,
		nodeName:   nodeName,
		endpoint:   endpoint,
		secret:     hmacSecret,
		rootKeys:   rootKeys,
		onFullSync: onFullSync,
		onMsg:      onMsg,
		log:        log.With("edge", edgeID),
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

// Connected dit si la connexion WebSocket à la passerelle est établie.
func (c *Client) Connected() bool {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	return c.conn != nil
}

// Send envoie un message à la passerelle. Si non connecté, le message est mis en queue.
func (c *Client) Send(msg edgeWS.Message) {
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
		c.log.Warn("edgews: erreur envoi message", "type", msg.Type, "err", err)
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
	attempt := 0
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		if err := c.connect(); err != nil {
			c.log.Warn("edgews: connexion échouée", "err", err, "retry", backoff)
		} else if attempt > 0 {
			wsReconnectsTotal.WithLabelValues(c.edgeID).Inc()
		}
		attempt++

		// Attendre avant de réessayer
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(backoff + edgeWS.RandomJitter(backoff/5)):
		}

		// Backoff exponentiel avec cap
		backoff *= 2
		if backoff > reconnectMax {
			backoff = reconnectMax
		}
	}
}

// Ce qui signe une connexion, du plus au moins souhaitable.
const (
	signKindCurrent  int32 = iota // clé de canal dérivée du secret courant
	signKindPrevious              // clé de canal dérivée d'un secret précédent (rotation en cours)
	signKindRoot                  // secret racine lui-même (passerelle qui n'a pas sa clé dérivée)
)

// signer est une clé avec laquelle l'Admin signe sa connexion.
type signer struct {
	key    string
	kind   int32
	byName bool // clé dérivée du nom de la passerelle plutôt que de son identifiant
}

func (c *Client) roots() []pairing.Key {
	if c.rootKeys != nil {
		return c.rootKeys()
	}
	if c.secret != "" {
		return []pairing.Key{{Value: c.secret}}
	}
	return nil
}

// signers donne les clés à essayer, dans l'ordre. La clé dérivée de la passerelle d'abord, avec le secret courant puis les
// précédents : une passerelle qui ne détient plus le secret racine n'accepte qu'elle, et pendant une rotation elle peut
// encore n'avoir que l'ancienne. Le secret racine ensuite, pour une passerelle qui ne l'a pas encore reçue
// (GPX_EDGE_CHANNEL_ROOT_FALLBACK=false l'interdit). Sans secret, la connexion n'est pas signée.
func (c *Client) signers() []signer {
	roots := c.roots()
	if len(roots) == 0 {
		return []signer{{}}
	}
	var list, raw []signer
	for _, r := range roots {
		kind := signKindCurrent
		if r.Previous {
			kind = signKindPrevious
		}
		byID := signer{key: pairing.EdgeChannelKey(r.Value, c.edgeID), kind: kind}
		// Helm et le démarrage rapide ne connaissent pas l'identifiant que l'Admin attribue : ils dérivent la clé du nom.
		byName := signer{key: pairing.EdgeChannelKey(r.Value, c.nodeName), kind: kind, byName: true}
		pair := []signer{byID, byName}
		if c.preferName.Load() {
			pair = []signer{byName, byID}
		}
		for _, sg := range pair {
			if sg.key != "" && (!sg.byName || sg.key != byID.key) {
				list = append(list, sg)
			}
		}
		raw = append(raw, signer{key: r.Value, kind: signKindRoot})
	}
	if len(list) == 0 || os.Getenv("GPX_EDGE_CHANNEL_ROOT_FALLBACK") != "false" {
		list = append(list, raw...)
	}
	return list
}

// dial ouvre le WebSocket en essayant chaque clé tant que la passerelle refuse la signature (401/403).
func (c *Client) dial(wsURL string) (*websocket.Conn, error) {
	var lastErr error
	for _, sg := range c.signers() {
		header := http.Header{}
		header.Set("X-Node-ID", c.edgeID)
		if sg.key != "" {
			header.Set("X-Goproxify-Signature", edgeWS.BuildAdminSignature(sg.key, "GET", wsPath))
		}
		dialCtx, cancel := context.WithTimeout(c.ctx, 15*time.Second)
		conn, resp, err := websocket.Dial(dialCtx, wsURL, &websocket.DialOptions{HTTPHeader: header})
		cancel()
		if err == nil {
			if sg.kind != signKindRoot {
				c.preferName.Store(sg.byName)
			}
			if sg.key != "" && c.lastKind.Swap(sg.kind) != sg.kind {
				switch sg.kind {
				case signKindRoot:
					c.log.Warn("edgews: la passerelle n'accepte que le secret racine — lui donner GPX_EDGE_CHANNEL_KEY (clé dérivée de son identifiant, voir GET /api/v1/pairing-secret?node=), puis retirer le secret racine de son hôte", "node_id", c.edgeID)
				case signKindPrevious:
					c.log.Warn("edgews: la passerelle n'accepte encore que la clé de l'ancien secret — rotation en cours : lui donner la nouvelle GPX_EDGE_CHANNEL_KEY", "node_id", c.edgeID)
				}
			}
			return conn, nil
		}
		lastErr = err
		if resp == nil || (resp.StatusCode != http.StatusUnauthorized && resp.StatusCode != http.StatusForbidden) {
			return nil, err
		}
	}
	return nil, lastErr
}

// connect établit la connexion WS et effectue le full_sync initial.
func (c *Client) connect() error {
	wsURL := "ws" + c.endpoint[4:] + wsPath // http://... → ws://..../ws/admin
	if c.endpoint[:5] == "https" {
		wsURL = "wss" + c.endpoint[5:] + wsPath
	}

	conn, err := c.dial(wsURL)
	if err != nil {
		return err
	}

	conn.SetReadLimit(4 * 1024 * 1024) // 4 MiB — full_sync peut être volumineux

	c.connMu.Lock()
	c.conn = conn
	c.connMu.Unlock()

	c.log.Info("edgews: connexion WS établie", "url", wsURL)
	edgeproxy.MarkReachable(c.endpoint)

	// Full sync après connexion
	if c.onFullSync != nil {
		if err := c.onFullSync(c.ctx); err != nil {
			c.log.Warn("edgews: full_sync échoué", "err", err)
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

	// Lire les messages entrants (Passerelle → Admin) jusqu'à déconnexion
	for {
		var msg edgeWS.Message
		if err := wsjson.Read(c.ctx, conn, &msg); err != nil {
			c.log.Debug("edgews: connexion WS perdue", "err", err)
			break
		}
		c.log.Debug("edgews: message reçu de la passerelle", "type", msg.Type)
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

// --- Méthodes de push ---

// PushJSON envoie un message de type msgType avec le payload fourni.
func (c *Client) PushJSON(msgType string, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	msg := edgeWS.Message{
		Seq:     c.nextSeq(),
		Type:    msgType,
		Payload: b,
	}
	c.Send(msg)
	return nil
}
