// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tunnel

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
)

// ListenerConfig configure le listener mTLS acceptant des tunnels entrants.
type ListenerConfig struct {
	Addr    string // ex: ":9443"
	CACert  []byte // CA pour valider les clients (mTLS)
	CertPEM []byte
	KeyPEM  []byte
}

// Serve démarre le listener mTLS et route chaque flux vers le targetAddr demandé.
// Bloque jusqu'à ce que le listener soit fermé.
func Serve(cfg ListenerConfig, log *slog.Logger) error {
	cert, err := tls.X509KeyPair(cfg.CertPEM, cfg.KeyPEM)
	if err != nil {
		return fmt.Errorf("tunnel listener: certificat: %w", err)
	}
	pool := x509.NewCertPool()
	if len(cfg.CACert) > 0 {
		pool.AppendCertsFromPEM(cfg.CACert)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}
	ln, err := tls.Listen("tcp", cfg.Addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("tunnel listener: écoute sur %s: %w", cfg.Addr, err)
	}
	log.Info("tunnel: listener mTLS démarré", "addr", cfg.Addr)
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return nil
			}
			log.Warn("tunnel: accept", "err", err)
			continue
		}
		go handleTunnelConn(conn, log)
	}
}

func handleTunnelConn(conn net.Conn, log *slog.Logger) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	target := strings.TrimSpace(line)
	if target == "" {
		fmt.Fprintf(conn, "ERR empty target\n") //nolint:errcheck
		return
	}
	back, err := net.Dial("tcp", target)
	if err != nil {
		fmt.Fprintf(conn, "ERR %s\n", err) //nolint:errcheck
		log.Warn("tunnel: connexion backend refusée", "target", target, "err", err)
		return
	}
	defer back.Close()
	fmt.Fprintf(conn, "OK\n") //nolint:errcheck
	// Flush le bufio.Reader en recopiant les octets déjà lus.
	joined := io.MultiReader(br, conn)
	done := make(chan struct{}, 2)
	go func() { io.Copy(back, joined); done <- struct{}{} }()  //nolint:errcheck
	go func() { io.Copy(conn, back); done <- struct{}{} }()    //nolint:errcheck
	<-done
}
