// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"

	"github.com/vincamok/goproxify/internal/i18n"
)

// EmailSender envoie des notifications par SMTP.
type EmailSender struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	To       []string
	// Locale for email chrome (labels). Empty → English (product default).
	Locale string
}

func (s *EmailSender) Send(_ context.Context, msg Message) error {
	if len(s.To) == 0 {
		return fmt.Errorf("email: no recipients")
	}
	loc := i18n.Parse(s.Locale)
	addr := net.JoinHostPort(s.Host, fmt.Sprintf("%d", s.Port))
	body := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: [Goproxify] %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n\n%s : %s\n%s : %s\n%s : %s",
		s.From, strings.Join(s.To, ", "), msg.Title, msg.Body,
		i18n.T(loc, "email.alert.trigger"), msg.Trigger,
		i18n.T(loc, "email.alert.severity"), msg.Severity,
		i18n.T(loc, "email.alert.date"), msg.FiredAt.Format("2006-01-02 15:04:05"),
	)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("email: SMTP connect: %w", err)
	}
	client, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("email: SMTP client: %w", err)
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: s.Host}); err != nil {
			return fmt.Errorf("email: STARTTLS: %w", err)
		}
	}
	if s.Username != "" {
		auth := smtp.PlainAuth("", s.Username, s.Password, s.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("email: SMTP auth: %w", err)
		}
	}
	if err := client.Mail(s.From); err != nil {
		return err
	}
	for _, to := range s.To {
		if err := client.Rcpt(to); err != nil {
			return err
		}
	}
	wc, err := client.Data()
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(wc, body)
	if err != nil {
		return err
	}
	return wc.Close()
}
