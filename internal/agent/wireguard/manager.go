// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package wireguard gère les tunnels WireGuard entre Agent et Core.
// Utilise les commandes système wg/ip pour l'interface ; keygen en Go (curve25519).
package wireguard

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"strings"

	"golang.org/x/crypto/curve25519"
)

// Peer représente un pair WireGuard.
type Peer struct {
	PublicKey  string
	Endpoint   string // "host:port"
	AllowedIPs []string
}

// Manager gère une interface WireGuard locale.
type Manager struct {
	iface      string
	privateKey string
	publicKey  string
	listenPort int
	log        *slog.Logger
}

// New crée un Manager WireGuard et génère une paire de clés.
func New(iface string, listenPort int, log *slog.Logger) (*Manager, error) {
	priv, pub, err := generateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("wireguard: keygen: %w", err)
	}
	return &Manager{
		iface:      iface,
		privateKey: priv,
		publicKey:  pub,
		listenPort: listenPort,
		log:        log,
	}, nil
}

// PublicKey retourne la clé publique locale.
func (m *Manager) PublicKey() string { return m.publicKey }

// Setup crée l'interface WireGuard et la configure.
func (m *Manager) Setup(localIP string) error {
	cmds := [][]string{
		{"ip", "link", "add", "dev", m.iface, "type", "wireguard"},
		{"ip", "address", "add", localIP, "dev", m.iface},
		{"wg", "set", m.iface, "listen-port", fmt.Sprintf("%d", m.listenPort),
			"private-key", "/dev/stdin"},
		{"ip", "link", "set", "up", "dev", m.iface},
	}
	for _, args := range cmds[:2] {
		if err := run(args...); err != nil {
			// ignore "already exists"
			if !strings.Contains(err.Error(), "exists") {
				return fmt.Errorf("wireguard setup: %w", err)
			}
		}
	}
	// wg set avec clé privée via stdin
	cmd := exec.Command("wg", "set", m.iface,
		"listen-port", fmt.Sprintf("%d", m.listenPort),
		"private-key", "/dev/stdin")
	cmd.Stdin = strings.NewReader(m.privateKey)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("wireguard: wg set: %s: %w", out, err)
	}
	if err := run("ip", "link", "set", "up", "dev", m.iface); err != nil {
		if !strings.Contains(err.Error(), "exists") {
			return fmt.Errorf("wireguard up: %w", err)
		}
	}
	m.log.Info("wireguard interface up", "iface", m.iface, "ip", localIP)
	return nil
}

// AddPeer ajoute ou met à jour un pair WireGuard.
func (m *Manager) AddPeer(peer Peer) error {
	args := []string{"wg", "set", m.iface,
		"peer", peer.PublicKey,
		"endpoint", peer.Endpoint,
		"allowed-ips", strings.Join(peer.AllowedIPs, ","),
		"persistent-keepalive", "25",
	}
	if err := run(args...); err != nil {
		return fmt.Errorf("wireguard: add peer: %w", err)
	}
	m.log.Info("wireguard peer ajouté", "pub", peer.PublicKey[:8]+"...", "endpoint", peer.Endpoint)
	return nil
}

// RemovePeer supprime un pair WireGuard.
func (m *Manager) RemovePeer(publicKey string) error {
	if err := run("wg", "set", m.iface, "peer", publicKey, "remove"); err != nil {
		return fmt.Errorf("wireguard: remove peer: %w", err)
	}
	return nil
}

// Teardown supprime l'interface WireGuard.
func (m *Manager) Teardown() error {
	return run("ip", "link", "del", "dev", m.iface)
}

// AllocateIP alloue une adresse IP dans un sous-réseau /24.
func AllocateIP(subnet string, index int) (string, error) {
	_, ipNet, err := net.ParseCIDR(subnet)
	if err != nil {
		return "", fmt.Errorf("wireguard: parse subnet: %w", err)
	}
	ip := ipNet.IP.To4()
	if ip == nil {
		return "", fmt.Errorf("wireguard: IPv6 non supporté")
	}
	ip[3] = byte(index)
	ones, _ := ipNet.Mask.Size()
	return fmt.Sprintf("%s/%d", ip.String(), ones), nil
}

func run(args ...string) error {
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", strings.Join(args, " "), out)
	}
	return nil
}

// generateKeyPair génère une paire de clés Curve25519 pour WireGuard.
func generateKeyPair() (priv, pub string, err error) {
	var privKey [32]byte
	if _, err = rand.Read(privKey[:]); err != nil {
		return
	}
	// Clamp selon RFC 7748
	privKey[0] &= 248
	privKey[31] &= 127
	privKey[31] |= 64

	pubKey, err := curve25519ScalarBaseMult(privKey)
	if err != nil {
		return "", "", err
	}
	priv = base64.StdEncoding.EncodeToString(privKey[:])
	pub = base64.StdEncoding.EncodeToString(pubKey[:])
	return
}

// curve25519ScalarBaseMult calcule la clé publique Curve25519 (sans fallback dangereux).
func curve25519ScalarBaseMult(priv [32]byte) ([32]byte, error) {
	var zero [32]byte
	out, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return zero, fmt.Errorf("curve25519: %w", err)
	}
	var pub [32]byte
	copy(pub[:], out)
	return pub, nil
}
