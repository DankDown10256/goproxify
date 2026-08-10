// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package stream

import (
	"io"
	"log/slog"
	"net"
	"time"

	"github.com/vincamok/goproxify/internal/core/middleware"
	"github.com/vincamok/goproxify/internal/core/router"
)

// TCPListener gère un proxy TCP L4 sur un port local.
type TCPListener struct {
	route    *router.Route
	listener net.Listener
	log      *slog.Logger
	metrics  *Metrics
}

func NewTCPListener(route *router.Route, log *slog.Logger, m *Metrics) *TCPListener {
	return &TCPListener{route: route, log: log, metrics: m}
}

func (l *TCPListener) Start() error {
	addr := addrForRoute(l.route)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	l.listener = ln
	l.log.Info("TCP stream listen", "addr", addr, "route", l.route.ID)
	go l.accept()
	return nil
}

func (l *TCPListener) Stop() {
	if l.listener != nil {
		l.listener.Close()
	}
}

func (l *TCPListener) accept() {
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			return
		}
		go l.handle(conn)
	}
}

func (l *TCPListener) handle(client net.Conn) {
	defer client.Close()

	backend := pickBackend(l.route)
	if backend == nil {
		return
	}

	upstream, err := net.DialTimeout("tcp", backend.URL, 10*time.Second)
	if err != nil {
		l.log.Warn("TCP dial failed", "backend", backend.URL, "err", err)
		return
	}
	defer upstream.Close()

	l.metrics.ActiveConnections.Add(1)
	defer l.metrics.ActiveConnections.Add(-1)

	done := make(chan struct{}, 2)
	pipe := func(dst, src net.Conn) {
		buf := middleware.GetBuf()
		defer middleware.PutBuf(buf)
		n, _ := io.CopyBuffer(dst, src, *buf)
		l.metrics.BytesOut.Add(n)
		done <- struct{}{}
	}
	go pipe(upstream, client)
	go pipe(client, upstream)
	<-done
}
