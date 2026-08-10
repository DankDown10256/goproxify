// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"log/slog"
	"time"
)

// AuditEvent métadonnées de session — pas de contenu terminal ni secrets.
type AuditEvent struct {
	Ts       time.Time     `json:"ts"`
	Actor    string        `json:"actor"`
	TargetID string        `json:"target_id"`
	Facade   SessionFacade `json:"facade"`
	Success  bool          `json:"success"`
	Detail   string        `json:"detail,omitempty"`
}

const maxAuditEvents = 500

// AuditLogger écrit les événements en slog JSON-friendly.
func AuditLogger(log *slog.Logger) func(AuditEvent) {
	return func(e AuditEvent) {
		if e.Ts.IsZero() {
			e.Ts = time.Now().UTC()
		}
		log.Info("portal.audit",
			"ts", e.Ts.Format(time.RFC3339),
			"actor", e.Actor,
			"target_id", e.TargetID,
			"facade", string(e.Facade),
			"success", e.Success,
			"detail", e.Detail,
		)
	}
}

func (h *HTTPServer) emitAudit(e AuditEvent) {
	if e.Ts.IsZero() {
		e.Ts = time.Now().UTC()
	}
	if h.audit != nil {
		h.audit(e)
	}
}
