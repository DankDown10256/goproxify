// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// SSHServer accepte ssh <uuid>@host et ponte vers la cible.
type SSHServer struct {
	sessions *SessionManager
	log      *slog.Logger
	hostKey  ssh.Signer
	ln       net.Listener
	mu       sync.Mutex
	audit    func(AuditEvent)
	shell    *ShellBroker
}

type connAuth struct {
	uuid           string
	clientPassword string // mot de passe tapé au prompt client → cible si vault vide
}

// NewSSHServer prépare le serveur (host key RSA éphémère si nil).
func NewSSHServer(sessions *SessionManager, hostKey ssh.Signer, log *slog.Logger, audit func(AuditEvent)) (*SSHServer, error) {
	if hostKey == nil {
		key, err := generateHostKey()
		if err != nil {
			return nil, err
		}
		hostKey = key
	}
	if audit == nil {
		audit = func(AuditEvent) {}
	}
	return &SSHServer{sessions: sessions, log: log, hostKey: hostKey, audit: audit}, nil
}

func generateHostKey() (ssh.Signer, error) {
	key, err := generateRSAKey()
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

func generateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// Start écoute addr (ex. :2222).
func (s *SSHServer) Start(addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	s.log.Info("portal ssh listen", "addr", addr)
	go s.acceptLoop()
	return nil
}

// Stop ferme le listener.
func (s *SSHServer) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln != nil {
		_ = s.ln.Close()
		s.ln = nil
	}
}

func (s *SSHServer) acceptLoop() {
	for {
		s.mu.Lock()
		ln := s.ln
		s.mu.Unlock()
		if ln == nil {
			return
		}
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *SSHServer) handleConn(nConn net.Conn) {
	defer nConn.Close()
	auth := &connAuth{}

	config := &ssh.ServerConfig{
		// Pas de PublicKeyCallback : force un prompt password/KBI pour
		// transmettre le mot de passe cible (vault vide) ou valider la session.
		PasswordCallback: func(c ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			perms, err := s.authUUID(c.User(), auth)
			if err != nil {
				return nil, err
			}
			auth.clientPassword = string(password)
			return perms, nil
		},
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			if _, err := s.authUUID(c.User(), auth); err != nil {
				return nil, err
			}
			answers, err := challenge("goproxify", "Mot de passe de la machine cible (ou Entrée si déjà en vault)", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			if len(answers) > 0 {
				auth.clientPassword = answers[0]
			}
			return &ssh.Permissions{Extensions: map[string]string{"uuid": auth.uuid}}, nil
		},
	}
	config.AddHostKey(s.hostKey)

	serverConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		s.log.Debug("portal ssh handshake", "err", err)
		return
	}
	defer serverConn.Close()
	go ssh.DiscardRequests(reqs)

	uuid := auth.uuid
	if uuid == "" {
		return
	}
	clientPW := auth.clientPassword

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			_ = newChannel.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(ch, requests, uuid, clientPW, nConn.RemoteAddr().String())
	}
}

func (s *SSHServer) authUUID(id string, auth *connAuth) (*ssh.Permissions, error) {
	if _, ok := s.sessions.Peek(id); !ok {
		return nil, fmt.Errorf("session invalide ou expirée")
	}
	auth.uuid = id
	return &ssh.Permissions{Extensions: map[string]string{"uuid": id}}, nil
}

func (s *SSHServer) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request, sessionID, clientPW, remote string) {
	defer ch.Close()

	sess, ok := s.sessions.Acquire(sessionID)
	if !ok {
		_, _ = ch.Write([]byte("session invalide ou déjà utilisée\n"))
		s.audit(AuditEvent{
			Actor: remote, TargetID: "", Facade: FacadeSSH, Success: false, Detail: "consume failed",
		})
		return
	}

	if sess.Target.Kind == TargetDocker {
		if s.shell == nil {
			_, _ = ch.Write([]byte("docker: shell broker indisponible\n"))
			return
		}
		if sess.Target.AgentName == "" || sess.Target.Container == "" {
			_, _ = ch.Write([]byte("docker: agent_name + container requis\n"))
			return
		}
		remote, err := s.shell.Open(sess.Target.AgentName, sess.Target.Container)
		if err != nil {
			_, _ = fmt.Fprintf(ch, "docker exec: %v\n", err)
			s.audit(AuditEvent{Actor: sess.Username, TargetID: sess.TargetID, Facade: FacadeSSH, Success: false, Detail: err.Error()})
			return
		}
		s.audit(AuditEvent{Actor: sess.Username, TargetID: sess.TargetID, Facade: FacadeSSH, Success: true, Detail: "docker start"})
		_ = BridgeSSHChannelIO(remote, ch, reqs)
		s.audit(AuditEvent{Actor: sess.Username, TargetID: sess.TargetID, Facade: FacadeSSH, Success: true, Detail: "docker end"})
		return
	}

	if sess.Target.Kind != TargetSSH {
		_, _ = ch.Write([]byte("type de cible inconnu\n"))
		return
	}

	target := sess.Target
	// Si le vault n'a pas de mot de passe, utiliser celui tapé au prompt ssh client.
	if target.Password == "" && clientPW != "" {
		target.Password = clientPW
	}
	if target.Username == "" {
		_, _ = ch.Write([]byte("username SSH cible manquant — renseignez « User SSH » dans le portail\n"))
		s.audit(AuditEvent{
			Actor: sess.Username, TargetID: sess.TargetID, Facade: FacadeSSH, Success: false, Detail: "missing username",
		})
		return
	}

	s.audit(AuditEvent{
		Actor: sess.Username, TargetID: sess.TargetID, Facade: FacadeSSH, Success: true, Detail: "start",
	})
	err := BridgeSSH(target, ch, reqs)
	okEnd := err == nil
	detail := "end"
	if err != nil {
		detail = err.Error()
		s.log.Info("portal ssh bridge end", "err", err, "user", sess.Username, "target", sess.TargetID, "ssh_user", target.Username)
		_, _ = fmt.Fprintf(ch, "goproxify portal: %v\n", err)
	}
	s.audit(AuditEvent{
		Actor: sess.Username, TargetID: sess.TargetID, Facade: FacadeSSH, Success: okEnd, Detail: detail,
	})
}
