// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

func targetSSHConfig(target dialTarget) (*ssh.ClientConfig, error) {
	cfg := &ssh.ClientConfig{
		User:            target.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // cibles gérées par l'opérateur portail
		Timeout:         15 * time.Second,
	}
	if target.PrivateKey != "" {
		signer, err := ssh.ParsePrivateKey([]byte(target.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("clé privée cible: %w", err)
		}
		cfg.Auth = append(cfg.Auth, ssh.PublicKeys(signer))
	}
	if target.Password != "" {
		pw := target.Password
		cfg.Auth = append(cfg.Auth, ssh.Password(pw))
		// Beaucoup de sshd n'acceptent que keyboard-interactive pour le mot de passe.
		cfg.Auth = append(cfg.Auth, ssh.KeyboardInteractive(
			func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = pw
				}
				return answers, nil
			},
		))
	}
	if len(cfg.Auth) == 0 {
		return nil, fmt.Errorf("aucun credential pour la cible (renseignez mot de passe/clé dans le portail, ou tapez le mot de passe cible au prompt ssh)")
	}
	return cfg, nil
}

// BridgeSSH dial la cible sshd et ponte le canal client (PTY puis shell).
func BridgeSSH(target dialTarget, clientSSH ssh.Channel, reqs <-chan *ssh.Request) error {
	cfg, err := targetSSHConfig(target)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))
	conn, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return fmt.Errorf("dial ssh %s (user=%s): %w", addr, target.Username, err)
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return err
	}

	// OpenSSH envoie pty-req puis shell : appliquer le PTY avant Shell().
	pending := reqs
	started := false
	for req := range pending {
		switch req.Type {
		case "pty-req":
			ok := false
			if term, h, w, modes, perr := parsePtyReq(req.Payload); perr == nil {
				ok = session.RequestPty(term, h, w, modes) == nil
			}
			if req.WantReply {
				_ = req.Reply(ok, nil)
			}
		case "window-change":
			if h, w, ok := parseWinCh(req.Payload); ok {
				_ = session.WindowChange(h, w)
			}
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "env":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		case "shell":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			if err := session.Shell(); err != nil {
				return fmt.Errorf("shell: %w", err)
			}
			started = true
			goto bridge
		case "exec":
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
			cmd, _ := parseExec(req.Payload)
			if err := session.Start(cmd); err != nil {
				return fmt.Errorf("exec: %w", err)
			}
			started = true
			goto bridge
		default:
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}
	if !started {
		_ = session.RequestPty("xterm-256color", 40, 120, ssh.TerminalModes{})
		if err := session.Shell(); err != nil {
			return fmt.Errorf("shell: %w", err)
		}
	}

bridge:
	// window-change / signaux restants
	go func() {
		for req := range pending {
			switch req.Type {
			case "window-change":
				if h, w, ok := parseWinCh(req.Payload); ok {
					_ = session.WindowChange(h, w)
				}
				if req.WantReply {
					_ = req.Reply(true, nil)
				}
			default:
				if req.WantReply {
					_ = req.Reply(false, nil)
				}
			}
		}
	}()

	errCh := make(chan error, 3)
	go func() { _, e := io.Copy(stdin, clientSSH); _ = stdin.Close(); errCh <- e }()
	go func() { _, e := io.Copy(clientSSH, stdout); errCh <- e }()
	go func() { _, e := io.Copy(clientSSH.Stderr(), stderr); errCh <- e }()
	<-errCh
	return nil
}

// BridgeWebSSH ouvre une session SSH cible et ponte vers un ReadWriteCloser (WS).
func BridgeWebSSH(target dialTarget, rw io.ReadWriteCloser) error {
	cfg, err := targetSSHConfig(target)
	if err != nil {
		return err
	}
	addr := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))
	conn, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		return fmt.Errorf("dial ssh %s (user=%s): %w", addr, target.Username, err)
	}
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	_ = session.RequestPty("xterm-256color", 40, 120, ssh.TerminalModes{})
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	if err := session.Shell(); err != nil {
		return err
	}
	go func() { _, _ = io.Copy(stdin, rw); _ = stdin.Close() }()
	_, err = io.Copy(rw, stdout)
	return err
}

func parsePtyReq(b []byte) (term string, h, w int, modes ssh.TerminalModes, err error) {
	// string term, uint32 w, h, pixw, pixh, string modes
	var payload struct {
		Term  string
		W, H  uint32
		Wpix  uint32
		Hpix  uint32
		Modes string
	}
	if err = ssh.Unmarshal(b, &payload); err != nil {
		return "", 0, 0, nil, err
	}
	term = payload.Term
	h = int(payload.H)
	w = int(payload.W)
	if h == 0 {
		h = 40
	}
	if w == 0 {
		w = 120
	}
	modes = ssh.TerminalModes{}
	return term, h, w, modes, nil
}

func parseWinCh(b []byte) (h, w int, ok bool) {
	var payload struct {
		W, H, Wpix, Hpix uint32
	}
	if err := ssh.Unmarshal(b, &payload); err != nil {
		return 0, 0, false
	}
	return int(payload.H), int(payload.W), true
}

func parseExec(b []byte) (string, error) {
	var payload struct {
		Command string
	}
	if err := ssh.Unmarshal(b, &payload); err != nil {
		return "", err
	}
	return payload.Command, nil
}

// BridgeWebIO ponte un ReadWriteCloser (WS ou docker shell) vers le client web.
func BridgeWebIO(rwRemote io.ReadWriteCloser, rwLocal io.ReadWriteCloser) error {
	defer rwRemote.Close()
	errCh := make(chan error, 2)
	go func() { _, e := io.Copy(rwRemote, rwLocal); errCh <- e }()
	go func() { _, e := io.Copy(rwLocal, rwRemote); errCh <- e }()
	<-errCh
	return nil
}

// BridgeSSHChannelIO ponte un shell distant vers un canal SSH client (sans PTY distant SSH).
func BridgeSSHChannelIO(remote io.ReadWriteCloser, clientSSH ssh.Channel, reqs <-chan *ssh.Request) error {
	defer remote.Close()
	go func() {
		for req := range reqs {
			if req.WantReply {
				_ = req.Reply(true, nil)
			}
		}
	}()
	errCh := make(chan error, 2)
	go func() { _, e := io.Copy(remote, clientSSH); errCh <- e }()
	go func() { _, e := io.Copy(clientSSH, remote); errCh <- e }()
	<-errCh
	return nil
}
