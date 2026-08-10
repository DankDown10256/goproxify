// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// LogForwarder collecte les logs des conteneurs labellisés et les transmet au Core.
type LogForwarder struct {
	client        *Client
	adminEndpoint string
	authToken     string
	bufferLines   int
	log           *slog.Logger

	mu       sync.Mutex
	watching map[string]context.CancelFunc // containerID → cancel
}

// NewLogForwarder crée un LogForwarder.
func NewLogForwarder(client *Client, adminEndpoint, authToken string, bufferLines int, log *slog.Logger) *LogForwarder {
	if bufferLines <= 0 {
		bufferLines = 500
	}
	return &LogForwarder{
		client:        client,
		adminEndpoint: adminEndpoint,
		authToken:     authToken,
		bufferLines:   bufferLines,
		log:           log,
		watching:      make(map[string]context.CancelFunc),
	}
}

// Watch démarre le suivi des logs d'un conteneur.
func (f *LogForwarder) Watch(ctx context.Context, containerID, containerName string) {
	f.mu.Lock()
	if _, ok := f.watching[containerID]; ok {
		f.mu.Unlock()
		return
	}
	cctx, cancel := context.WithCancel(ctx)
	f.watching[containerID] = cancel
	f.mu.Unlock()

	go f.stream(cctx, containerID, containerName)
}

// Unwatch arrête le suivi d'un conteneur.
func (f *LogForwarder) Unwatch(containerID string) {
	f.mu.Lock()
	if cancel, ok := f.watching[containerID]; ok {
		cancel()
		delete(f.watching, containerID)
	}
	f.mu.Unlock()
}

func (f *LogForwarder) stream(ctx context.Context, containerID, containerName string) {
	// Logs depuis maintenant, en continu, stdout+stderr
	path := "/containers/" + containerID + "/logs?follow=1&stdout=1&stderr=1&timestamps=1"

	buf := make([]logEntry, 0, f.bufferLines)
	flushTicker := time.NewTicker(5 * time.Second)
	defer flushTicker.Stop()

	lines := make(chan []byte, 256)
	go func() {
		_ = f.client.StreamLines(ctx, path, func(line []byte) {
			// Les logs Docker sont préfixés par 8 octets de header (stream type + size)
			if len(line) > 8 {
				line = line[8:]
			}
			select {
			case lines <- append([]byte(nil), line...):
			default:
			}
		})
		close(lines)
	}()

	flush := func() {
		if len(buf) == 0 {
			return
		}
		f.send(ctx, containerID, containerName, buf)
		buf = buf[:0]
	}

	for {
		select {
		case <-ctx.Done():
			flush()
			return
		case <-flushTicker.C:
			flush()
		case line, ok := <-lines:
			if !ok {
				flush()
				return
			}
			buf = append(buf, logEntry{T: time.Now().UTC(), Line: string(line)})
			if len(buf) >= f.bufferLines {
				flush()
			}
		}
	}
}

type logEntry struct {
	T    time.Time `json:"t"`
	Line string    `json:"line"`
}

type logBatch struct {
	ContainerID   string     `json:"container_id"`
	ContainerName string     `json:"container_name"`
	Entries       []logEntry `json:"entries"`
}

func (f *LogForwarder) send(ctx context.Context, containerID, containerName string, entries []logEntry) {
	batch := logBatch{
		ContainerID:   containerID,
		ContainerName: containerName,
		Entries:       entries,
	}
	body, _ := json.Marshal(batch)
	url := f.adminEndpoint + "/internal/v1/agent/logs"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+f.authToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.log.Warn("logs: envoi vers Admin", "container", containerName, "err", err)
		return
	}
	defer resp.Body.Close()
	f.log.Debug("logs: batch envoyé", "container", containerName, "lines", len(entries))
}
