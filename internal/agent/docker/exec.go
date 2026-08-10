// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// ExecCreate crée un exec interactif dans un conteneur.
func (c *Client) ExecCreate(ctx context.Context, containerID string, cmd []string) (string, error) {
	if len(cmd) == 0 {
		cmd = []string{"/bin/sh"}
	}
	body := map[string]any{
		"AttachStdin":  true,
		"AttachStdout": true,
		"AttachStderr": true,
		"Tty":          true,
		"Cmd":          cmd,
	}
	var out struct {
		ID string `json:"Id"`
	}
	if err := c.Post(ctx, "/containers/"+containerID+"/exec", body, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", fmt.Errorf("docker exec: id vide")
	}
	return out.ID, nil
}

// ExecAttach démarre l'exec et retourne le flux hijacké (TTY : stdin/stdout raw).
func (c *Client) ExecAttach(ctx context.Context, execID string) (net.Conn, error) {
	payload, err := json.Marshal(map[string]any{"Detach": false, "Tty": true})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/exec/"+execID+"/start"), bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp")
	req.Host = "docker"

	dialer := net.Dialer{Timeout: 5 * time.Second}
	raw, err := dialer.DialContext(ctx, "unix", c.socket)
	if err != nil {
		return nil, err
	}
	if err := req.Write(raw); err != nil {
		raw.Close()
		return nil, err
	}

	br := bufio.NewReader(raw)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		raw.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSwitchingProtocols {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		_ = resp.Body.Close()
		raw.Close()
		return nil, fmt.Errorf("docker exec start → %d: %s", resp.StatusCode, b)
	}
	_ = resp.Body.Close()

	return &hijackConn{Conn: raw, r: br}, nil
}

// hijackConn lit d'abord le reste du buffer HTTP puis le socket.
type hijackConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *hijackConn) Read(p []byte) (int, error) {
	if c.r != nil && c.r.Buffered() > 0 {
		return c.r.Read(p)
	}
	return c.Conn.Read(p)
}
