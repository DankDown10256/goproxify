// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package tunnel fournit un dialer mTLS persistant Core↔Core pour le trafic L4.
// Il maintient un pool de connexions vers des nœuds distants et assure le
// failover automatique entre tunnels actifs.
package tunnel

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// PeerConfig décrit un nœud distant joignable via tunnel mTLS.
type PeerConfig struct {
	Name     string // nom du nœud (ex: core-2)
	Addr     string // host:port du listener tunnel (ex: core-2:9443)
	CACert   []byte // certificat CA en PEM pour valider le pair
	CertPEM  []byte // certificat TLS local (mTLS client auth)
	KeyPEM   []byte // clé TLS locale
}

// Peer représente un pair distant avec son état de connexion.
type Peer struct {
	cfg    PeerConfig
	mu     sync.Mutex
	conn   net.Conn
	broken bool
}

// Manager maintient les tunnels vers plusieurs Cores distants et offre
// un Dial(peerName, targetAddr) avec failover automatique.
type Manager struct {
	mu    sync.RWMutex
	peers map[string]*Peer
	log   *slog.Logger
}

// New crée un Manager de tunnels.
func New(log *slog.Logger) *Manager {
	return &Manager{
		peers: make(map[string]*Peer),
		log:   log,
	}
}

// SetPeers remplace la liste complète des pairs (diff : retire les disparus, ajoute/update).
func (m *Manager) SetPeers(peers []PeerConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()

	keep := make(map[string]bool, len(peers))
	for _, cfg := range peers {
		keep[cfg.Name] = true
	}
	for name, p := range m.peers {
		if !keep[name] {
			p.mu.Lock()
			if p.conn != nil {
				p.conn.Close()
			}
			p.mu.Unlock()
			delete(m.peers, name)
		}
	}
	for _, cfg := range peers {
		if p, ok := m.peers[cfg.Name]; ok {
			p.mu.Lock()
			if p.conn != nil {
				p.conn.Close()
			}
			p.cfg = cfg
			p.conn = nil
			p.broken = false
			p.mu.Unlock()
		} else {
			m.peers[cfg.Name] = &Peer{cfg: cfg}
		}
	}
}

// AddPeer enregistre ou met à jour un pair distant.
func (m *Manager) AddPeer(cfg PeerConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.peers[cfg.Name]; ok {
		p.mu.Lock()
		if p.conn != nil {
			p.conn.Close()
		}
		p.cfg = cfg
		p.conn = nil
		p.broken = false
		p.mu.Unlock()
		return
	}
	m.peers[cfg.Name] = &Peer{cfg: cfg}
}

// RemovePeer ferme et retire un pair.
func (m *Manager) RemovePeer(name string) {
	m.mu.Lock()
	p, ok := m.peers[name]
	if ok {
		delete(m.peers, name)
	}
	m.mu.Unlock()
	if p != nil {
		p.mu.Lock()
		if p.conn != nil {
			p.conn.Close()
		}
		p.mu.Unlock()
	}
}

// Dial ouvre un flux multiplexé vers targetAddr via le tunnel du pair peerName.
// Si la connexion tunnel est rompue, elle est rétablie (reconnect automatique).
// Si le pair nommé n'est pas disponible, les autres pairs actifs sont essayés en ordre.
func (m *Manager) Dial(peerName, targetAddr string) (net.Conn, error) {
	m.mu.RLock()
	primary, ok := m.peers[peerName]
	var fallbacks []*Peer
	if ok {
		for name, p := range m.peers {
			if name != peerName {
				fallbacks = append(fallbacks, p)
			}
		}
	} else {
		for _, p := range m.peers {
			fallbacks = append(fallbacks, p)
		}
	}
	m.mu.RUnlock()

	if primary != nil {
		if conn, err := dialVia(primary, targetAddr, m.log); err == nil {
			return conn, nil
		}
	}
	for _, p := range fallbacks {
		if conn, err := dialVia(p, targetAddr, m.log); err == nil {
			m.log.Info("tunnel: failover vers pair", "peer", p.cfg.Name, "target", targetAddr)
			return conn, nil
		}
	}
	return nil, fmt.Errorf("tunnel: aucun pair disponible pour %q", targetAddr)
}

// dialVia établit ou réutilise la connexion mTLS vers le pair, puis envoie
// le targetAddr comme première ligne (CONNECT-style) pour que le listener remote
// ouvre la connexion TCP finale.
func dialVia(p *Peer, targetAddr string, log *slog.Logger) (net.Conn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.broken || p.conn == nil {
		c, err := mtlsDial(p.cfg)
		if err != nil {
			p.broken = true
			return nil, err
		}
		p.conn = c
		p.broken = false
	}

	// Envoyer le targetAddr suivi de '\n' pour que le serveur ouvre la connexion.
	if _, err := fmt.Fprintf(p.conn, "%s\n", targetAddr); err != nil {
		p.conn.Close()
		p.conn = nil
		p.broken = true
		return nil, fmt.Errorf("tunnel: envoi target: %w", err)
	}

	// Lire la confirmation (OK\n ou ERR ...\n).
	buf := make([]byte, 4)
	p.conn.SetReadDeadline(time.Now().Add(5 * time.Second)) //nolint:errcheck
	n, err := io.ReadAtLeast(p.conn, buf, 3)
	p.conn.SetReadDeadline(time.Time{}) //nolint:errcheck
	if err != nil || string(buf[:n])[:2] != "OK" {
		p.conn.Close()
		p.conn = nil
		p.broken = true
		return nil, fmt.Errorf("tunnel: pair a refusé: %s", buf[:n])
	}

	// Retourner la connexion "splittée" — le reste du flux appartient à l'appelant.
	// On enveloppe dans une pipeConn pour que la fermeture de l'appelant ne ferme pas
	// la connexion tunnel partagée.
	pr, pw := io.Pipe()
	go func() {
		io.Copy(pw, p.conn) //nolint:errcheck
		pw.Close()
	}()
	return &pipeConn{PipeReader: pr, Conn: p.conn}, nil
}

func mtlsDial(cfg PeerConfig) (net.Conn, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: len(cfg.CACert) == 0, //nolint:gosec — fallback si pas de CA fourni
	}
	if len(cfg.CertPEM) > 0 && len(cfg.KeyPEM) > 0 {
		cert, err := tls.X509KeyPair(cfg.CertPEM, cfg.KeyPEM)
		if err != nil {
			return nil, fmt.Errorf("tunnel: certificat local invalide: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	if len(cfg.CACert) > 0 {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(cfg.CACert)
		tlsCfg.RootCAs = pool
		tlsCfg.ServerName = cfg.Name
	}
	return tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", cfg.Addr, tlsCfg,
	)
}

// pipeConn enveloppe une connexion réseau en substituant le Reader par un io.Pipe
// pour isoler la lecture de l'appelant de la connexion sous-jacente partagée.
type pipeConn struct {
	*io.PipeReader
	net.Conn
}

func (pc *pipeConn) Read(b []byte) (int, error) { return pc.PipeReader.Read(b) }
func (pc *pipeConn) Close() error               { return pc.PipeReader.Close() }
