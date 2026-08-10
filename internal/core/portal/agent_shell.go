// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	corews "github.com/vincamok/goproxify/internal/core/ws"
)

// AgentShellSender envoie des messages shell vers un Agent nommé.
type AgentShellSender interface {
	SendToAgentByName(name string, msg corews.Message) error
	IsAgentConnected(name string) bool
}

// ShellBroker multiplexe les sessions docker exec via le hub WS Core↔Agent.
type ShellBroker struct {
	hub  AgentShellSender
	mu   sync.Mutex
	sess map[string]*brokerSess
}

type brokerSess struct {
	id        string
	agentName string
	stdout    chan []byte
	closed    chan struct{}
	closeOnce sync.Once
	readyOnce sync.Once
	readyCh   chan error
}

// NewShellBroker crée un broker.
func NewShellBroker(hub AgentShellSender) *ShellBroker {
	return &ShellBroker{hub: hub, sess: map[string]*brokerSess{}}
}

// Open démarre un docker exec sur l'Agent et retourne un ReadWriteCloser prêt.
func (b *ShellBroker) Open(agentName, container string) (io.ReadWriteCloser, error) {
	if b == nil || b.hub == nil {
		return nil, fmt.Errorf("shell broker indisponible")
	}
	if !b.hub.IsAgentConnected(agentName) {
		return nil, fmt.Errorf("agent %q non connecté", agentName)
	}
	id := uuid.NewString()
	s := &brokerSess{
		id: id, agentName: agentName,
		stdout:  make(chan []byte, 64),
		closed:  make(chan struct{}),
		readyCh: make(chan error, 1),
	}
	b.mu.Lock()
	b.sess[id] = s
	b.mu.Unlock()

	msg, err := corews.NewMessage(0, corews.TypeShellOpen, corews.ShellOpenPayload{
		SessionID: id, Container: container, Cmd: []string{"/bin/sh"},
	})
	if err != nil {
		b.remove(id)
		return nil, err
	}
	if err := b.hub.SendToAgentByName(agentName, msg); err != nil {
		b.remove(id)
		return nil, err
	}

	select {
	case err := <-s.readyCh:
		if err != nil {
			b.remove(id)
			return nil, err
		}
	case <-time.After(20 * time.Second):
		b.closeRemote(s)
		return nil, fmt.Errorf("timeout ouverture docker exec sur agent %q", agentName)
	case <-s.closed:
		return nil, fmt.Errorf("session shell fermée avant prêt")
	}
	return &brokerConn{broker: b, sess: s}, nil
}

// HandleAgentMessage traite shell_ready / data / close / error venant d'un Agent.
func (b *ShellBroker) HandleAgentMessage(msgType string, payload []byte) {
	switch msgType {
	case corews.TypeShellReady:
		var p corews.ShellReadyPayload
		if json.Unmarshal(payload, &p) != nil || p.SessionID == "" {
			return
		}
		b.mu.Lock()
		s := b.sess[p.SessionID]
		b.mu.Unlock()
		if s != nil {
			s.signalReady(nil)
		}
	case corews.TypeShellData:
		var p corews.ShellDataPayload
		if json.Unmarshal(payload, &p) != nil {
			return
		}
		raw, err := base64.StdEncoding.DecodeString(p.Data)
		if err != nil {
			return
		}
		b.mu.Lock()
		s := b.sess[p.SessionID]
		b.mu.Unlock()
		if s == nil {
			return
		}
		select {
		case s.stdout <- raw:
		case <-s.closed:
		default:
		}
	case corews.TypeShellError:
		var p corews.ShellErrorPayload
		if json.Unmarshal(payload, &p) != nil || p.SessionID == "" {
			return
		}
		b.mu.Lock()
		s := b.sess[p.SessionID]
		b.mu.Unlock()
		if s != nil {
			errMsg := p.Error
			if errMsg == "" {
				errMsg = "erreur shell agent"
			}
			s.signalReady(fmt.Errorf("%s", errMsg))
		}
		b.remove(p.SessionID)
	case corews.TypeShellClose:
		var p corews.ShellClosePayload
		_ = json.Unmarshal(payload, &p)
		if p.SessionID != "" {
			b.remove(p.SessionID)
		}
	}
}

func (s *brokerSess) signalReady(err error) {
	s.readyOnce.Do(func() {
		s.readyCh <- err
	})
}

func (b *ShellBroker) remove(id string) {
	b.mu.Lock()
	s := b.sess[id]
	delete(b.sess, id)
	b.mu.Unlock()
	if s == nil {
		return
	}
	s.closeOnce.Do(func() { close(s.closed) })
}

func (b *ShellBroker) writeToAgent(s *brokerSess, data []byte) error {
	msg, err := corews.NewMessage(0, corews.TypeShellData, corews.ShellDataPayload{
		SessionID: s.id, Data: base64.StdEncoding.EncodeToString(data),
	})
	if err != nil {
		return err
	}
	return b.hub.SendToAgentByName(s.agentName, msg)
}

func (b *ShellBroker) closeRemote(s *brokerSess) {
	msg, _ := corews.NewMessage(0, corews.TypeShellClose, corews.ShellClosePayload{SessionID: s.id})
	_ = b.hub.SendToAgentByName(s.agentName, msg)
	b.remove(s.id)
}

type brokerConn struct {
	broker *ShellBroker
	sess   *brokerSess
	rbuf   []byte
}

func (c *brokerConn) Read(p []byte) (int, error) {
	if len(c.rbuf) > 0 {
		n := copy(p, c.rbuf)
		c.rbuf = c.rbuf[n:]
		return n, nil
	}
	select {
	case <-c.sess.closed:
		return 0, io.EOF
	case chunk, ok := <-c.sess.stdout:
		if !ok {
			return 0, io.EOF
		}
		n := copy(p, chunk)
		if n < len(chunk) {
			c.rbuf = append([]byte(nil), chunk[n:]...)
		}
		return n, nil
	case <-time.After(30 * time.Minute):
		return 0, fmt.Errorf("shell idle timeout")
	}
}

func (c *brokerConn) Write(p []byte) (int, error) {
	select {
	case <-c.sess.closed:
		return 0, io.ErrClosedPipe
	default:
	}
	if err := c.broker.writeToAgent(c.sess, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *brokerConn) Close() error {
	c.broker.closeRemote(c.sess)
	return nil
}
