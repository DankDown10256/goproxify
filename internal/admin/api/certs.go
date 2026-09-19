// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// CertObtainer est implémenté par acme.Manager.
type CertObtainer interface {
	ObtainCert(ctx context.Context, domain string) error
}

// CertsHandler expose la liste des certs et déclenche l'obtention via ACME.
type CertsHandler struct {
	DB      *sql.DB
	Log     *slog.Logger
	Manager CertObtainer
}

type certRow struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	Issuer    string    `json:"issuer"`
	ExpiresAt time.Time `json:"expires_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (h *CertsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/certs")
	path = strings.TrimPrefix(path, "/")
	domain := strings.Split(path, "/")[0]

	switch {
	case r.Method == http.MethodGet && domain == "":
		h.list(w, r)
	case r.Method == http.MethodGet && domain == "acme-monitor":
		h.monitor(w, r)
	case r.Method == http.MethodPost && domain == "":
		h.obtain(w, r)
	case r.Method == http.MethodDelete && domain != "":
		h.delete(w, r, domain)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func (h *CertsHandler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, domain, issuer, expires_at, updated_at FROM certs ORDER BY domain`)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("certs: list", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()

	result := make([]certRow, 0)
	for rows.Next() {
		var c certRow
		if err := rows.Scan(&c.ID, &c.Domain, &c.Issuer, &c.ExpiresAt, &c.UpdatedAt); err != nil {
			continue
		}
		result = append(result, c)
	}
	jsonOK(w, result)
}

type obtainRequest struct {
	Domain string `json:"domain"`
}

func (h *CertsHandler) obtain(w http.ResponseWriter, r *http.Request) {
	var req obtainRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Domain == "" {
		http.Error(w, "domain requis", http.StatusBadRequest)
		return
	}
	if h.Manager == nil {
		http.Error(w, "ACME non configuré", http.StatusServiceUnavailable)
		return
	}
	go func() {
		if err := h.Manager.ObtainCert(context.Background(), req.Domain); err != nil {
			if !isCtxErr(err) { h.Log.Error("certs: obtention async", "domain", req.Domain, "err", err) }
		}
	}()
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending", "domain": req.Domain})
}

// certMonitorRow enrichit certRow avec le statut d'expiration calculé.
type certMonitorRow struct {
	ID        string `json:"id"`
	Domain    string `json:"domain"`
	Issuer    string `json:"issuer"`
	ExpiresAt string `json:"expires_at"`
	UpdatedAt string `json:"updated_at"`
	DaysLeft  int    `json:"days_left"`
	// ok | warning (≤30j) | critical (≤7j) | expired
	Status string `json:"status"`
}

type acmeMonitorResponse struct {
	Certs    []certMonitorRow `json:"certs"`
	Total    int              `json:"total"`
	OK       int              `json:"ok"`
	Warning  int              `json:"warning"`
	Critical int              `json:"critical"`
	Expired  int              `json:"expired"`
}

func (h *CertsHandler) monitor(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, domain, issuer, expires_at, updated_at FROM certs ORDER BY expires_at ASC`)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("certs: monitor", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()

	now := time.Now()
	resp := acmeMonitorResponse{Certs: make([]certMonitorRow, 0)}
	for rows.Next() {
		var c certRow
		if err := rows.Scan(&c.ID, &c.Domain, &c.Issuer, &c.ExpiresAt, &c.UpdatedAt); err != nil {
			continue
		}
		daysLeft := int(c.ExpiresAt.Sub(now).Hours() / 24)
		status := "ok"
		switch {
		case daysLeft < 0:
			status = "expired"
			daysLeft = 0
		case daysLeft <= 7:
			status = "critical"
		case daysLeft <= 30:
			status = "warning"
		}
		resp.Certs = append(resp.Certs, certMonitorRow{
			ID:        c.ID,
			Domain:    c.Domain,
			Issuer:    c.Issuer,
			ExpiresAt: c.ExpiresAt.UTC().Format(time.RFC3339),
			UpdatedAt: c.UpdatedAt.UTC().Format(time.RFC3339),
			DaysLeft:  daysLeft,
			Status:    status,
		})
		resp.Total++
		switch status {
		case "ok":
			resp.OK++
		case "warning":
			resp.Warning++
		case "critical":
			resp.Critical++
		case "expired":
			resp.Expired++
		}
	}
	jsonOK(w, resp)
}

func (h *CertsHandler) delete(w http.ResponseWriter, r *http.Request, domain string) {
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM certs WHERE domain=?`, domain)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("certs: delete", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "certificat introuvable", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
