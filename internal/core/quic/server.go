// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package quic

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/quic-go/quic-go/http3"
	"github.com/vincamok/goproxify/internal/config"
	coretls "github.com/vincamok/goproxify/internal/core/tls"
)

// QUICServer expose le proxy via HTTP/3 (QUIC / UDP).
type QUICServer struct {
	srv *http3.Server
}

// Start démarre le serveur HTTP/3 sur UDP.
func (q *QUICServer) Start(cfg *config.CoreConfig, handler http.Handler, certStore *coretls.CertStore) error {
	addr := fmt.Sprintf("%s:%d", cfg.Network.BindAddress, cfg.Network.QUICPort)

	quicPort := cfg.Network.QUICPort
	altSvcHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", fmt.Sprintf(`h3=":%d"; ma=86400`, quicPort))
		handler.ServeHTTP(w, r)
	})

	tlsCfg := &tls.Config{
		GetCertificate: certStore.GetCertificate,
		MinVersion:     tls.VersionTLS13,
		NextProtos:     []string{"h3"},
	}

	q.srv = &http3.Server{
		Addr:      addr,
		Handler:   altSvcHandler,
		TLSConfig: tlsCfg,
	}

	go func() {
		if err := q.srv.ListenAndServe(); err != nil {
			_ = err
		}
	}()
	return nil
}

// Stop arrête proprement le serveur HTTP/3.
func (q *QUICServer) Stop() {
	if q.srv != nil {
		q.srv.Close() //nolint:errcheck
	}
}
