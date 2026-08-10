// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"sync"

	agentdocker "github.com/vincamok/goproxify/internal/agent/docker"
	"github.com/vincamok/goproxify/internal/agent/wsclient"
	corews "github.com/vincamok/goproxify/internal/core/ws"
)

// shellHub gère les sessions docker exec relayées via WS.
type shellHub struct {
	mu        sync.Mutex
	sessions  map[string]*shellSession
	client    *agentdocker.Client
	ws        *wsclient.Client
	allowCont func(containerID string) bool // nil = autoriser (tests)
}

type shellSession struct {
	id     string
	conn   io.ReadWriteCloser
	cancel context.CancelFunc
}

func newShellHub(client *agentdocker.Client, ws *wsclient.Client, allowCont func(string) bool) *shellHub {
	return &shellHub{
		sessions:  map[string]*shellSession{},
		client:    client,
		ws:        ws,
		allowCont: allowCont,
	}
}

func (h *shellHub) Handle(msgType string, payload json.RawMessage) {
	switch msgType {
	case corews.TypeShellOpen:
		var p corews.ShellOpenPayload
		if json.Unmarshal(payload, &p) != nil || p.SessionID == "" || p.Container == "" {
			return
		}
		h.open(p)
	case corews.TypeShellData:
		var p corews.ShellDataPayload
		if json.Unmarshal(payload, &p) != nil {
			return
		}
		h.writeStdin(p)
	case corews.TypeShellClose:
		var p corews.ShellClosePayload
		if json.Unmarshal(payload, &p) != nil {
			return
		}
		h.close(p.SessionID)
	}
}

func (h *shellHub) open(p corews.ShellOpenPayload) {
	cmd := p.Cmd
	if len(cmd) == 0 {
		cmd = []string{"/bin/sh"}
	}
	if !shellCmdAllowed(cmd) {
		h.ws.SendShellError(p.SessionID, "commande shell non autorisée")
		return
	}
	if h.allowCont != nil && !h.allowCont(p.Container) {
		h.ws.SendShellError(p.SessionID, "conteneur non autorisé (hors catalogue découvert)")
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	execID, err := h.client.ExecCreate(ctx, p.Container, cmd)
	if err != nil {
		h.ws.SendShellError(p.SessionID, err.Error())
		cancel()
		return
	}
	conn, err := h.client.ExecAttach(ctx, execID)
	if err != nil {
		h.ws.SendShellError(p.SessionID, err.Error())
		cancel()
		return
	}
	sess := &shellSession{id: p.SessionID, conn: conn, cancel: cancel}
	h.mu.Lock()
	if old, ok := h.sessions[p.SessionID]; ok {
		old.cancel()
		_ = old.conn.Close()
	}
	h.sessions[p.SessionID] = sess
	h.mu.Unlock()

	h.ws.SendShellReady(p.SessionID)
	go h.pumpStdout(sess)
}

func (h *shellHub) pumpStdout(sess *shellSession) {
	defer h.close(sess.id)
	buf := make([]byte, 32*1024)
	for {
		n, err := sess.conn.Read(buf)
		if n > 0 {
			h.ws.SendShellData(sess.id, buf[:n])
		}
		if err != nil {
			return
		}
	}
}

func (h *shellHub) writeStdin(p corews.ShellDataPayload) {
	raw, err := base64.StdEncoding.DecodeString(p.Data)
	if err != nil || len(raw) == 0 {
		return
	}
	h.mu.Lock()
	sess := h.sessions[p.SessionID]
	h.mu.Unlock()
	if sess == nil {
		return
	}
	_, _ = sess.conn.Write(raw)
}

func (h *shellHub) close(id string) {
	h.mu.Lock()
	sess := h.sessions[id]
	delete(h.sessions, id)
	h.mu.Unlock()
	if sess == nil {
		return
	}
	sess.cancel()
	_ = sess.conn.Close()
	h.ws.SendShellClose(id)
}

// shellCmdAllowed restreint docker exec aux shells interactifs connus.
func shellCmdAllowed(cmd []string) bool {
	if len(cmd) == 0 {
		return false
	}
	switch cmd[0] {
	case "/bin/sh", "/bin/bash", "sh", "bash":
		return len(cmd) == 1
	default:
		return false
	}
}
