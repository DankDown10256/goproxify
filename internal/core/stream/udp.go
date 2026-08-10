// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package stream

import (
	"log/slog"
	"net"
	"time"

	"github.com/vincamok/goproxify/internal/core/router"
)

// UDPListener gère un tunnel UDP L4 sur un port local.
type UDPListener struct {
	route   *router.Route
	conn    *net.UDPConn
	log     *slog.Logger
	metrics *Metrics
}

func NewUDPListener(route *router.Route, log *slog.Logger, m *Metrics) *UDPListener {
	return &UDPListener{route: route, log: log, metrics: m}
}

func (l *UDPListener) Start() error {
	addr := addrForRoute(l.route)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	l.conn = conn
	l.log.Info("UDP stream listen", "addr", addr, "route", l.route.ID)
	go l.loop()
	return nil
}

func (l *UDPListener) Stop() {
	if l.conn != nil {
		l.conn.Close()
	}
}

func (l *UDPListener) loop() {
	buf := make([]byte, 64*1024)
	for {
		n, clientAddr, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		go l.forward(payload, clientAddr)
	}
}

func (l *UDPListener) forward(payload []byte, clientAddr *net.UDPAddr) {
	backend := pickBackend(l.route)
	if backend == nil {
		return
	}
	upstreamAddr, err := net.ResolveUDPAddr("udp", backend.URL)
	if err != nil {
		l.log.Warn("UDP resolve failed", "backend", backend.URL, "err", err)
		return
	}
	conn, err := net.DialUDP("udp", nil, upstreamAddr)
	if err != nil {
		l.log.Warn("UDP dial failed", "backend", backend.URL, "err", err)
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))
	n, _ := conn.Write(payload)
	l.metrics.BytesOut.Add(int64(n))

	// Réponse backend → client
	resp := make([]byte, 64*1024)
	nr, _ := conn.Read(resp)
	if nr > 0 {
		l.conn.WriteToUDP(resp[:nr], clientAddr)
		l.metrics.BytesIn.Add(int64(nr))
	}
}
