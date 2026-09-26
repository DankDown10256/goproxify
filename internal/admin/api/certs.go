// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// CertObtainer est implémenté par acme.Manager.
type CertObtainer interface {
	ObtainCert(ctx context.Context, domain string) error
}

// CertImportPusher pousse un cert importé vers les passerelles connectées.
type CertImportPusher interface {
	PushCert(ctx context.Context, name string, certPEM, keyPEM []byte)
}

// CertsHandler expose la liste des certs et déclenche l'obtention via ACME.
type CertsHandler struct {
	DB      *sql.DB
	Log     *slog.Logger
	Manager CertObtainer
	// Pusher optionnel — pousse les certs importés manuellement vers les passerelles.
	Pusher CertImportPusher
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
	case r.Method == http.MethodPost && domain == "import":
		h.importCert(w, r)
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
		if !isCtxErr(err) {
			h.Log.Error("certs: list", "err", err)
		}
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
			if !isCtxErr(err) {
				h.Log.Error("certs: obtention async", "domain", req.Domain, "err", err)
			}
		}
	}()
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "pending", "domain": req.Domain})
}

// certMonitorRow enrichit certRow avec le statut d'expiration calculé.
type certMonitorRow struct {
	ID     string `json:"id"`
	Domain string `json:"domain"`
	// DomainID référence domains.id — vide si le cert n'a pas de domaine déclaré (ex. import manuel).
	DomainID    string `json:"domain_id"`
	Issuer      string `json:"issuer"`
	ExpiresAt   string `json:"expires_at"`
	UpdatedAt   string `json:"updated_at"`
	DaysLeft    int    `json:"days_left"`
	DNSProvider string `json:"dns_provider"`
	CertMethod  string `json:"cert_method"`
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
		`SELECT c.id, c.domain, c.issuer, c.expires_at, c.updated_at,
		        COALESCE(d.dns_provider,''), COALESCE(d.cert_method,''), COALESCE(d.id,'')
		 FROM certs c
		 LEFT JOIN domains d ON d.domain = c.domain
		 ORDER BY c.expires_at ASC`)
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
		var dnsProv, certMethod, domainID string
		if err := rows.Scan(&c.ID, &c.Domain, &c.Issuer, &c.ExpiresAt, &c.UpdatedAt, &dnsProv, &certMethod, &domainID); err != nil {
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
			ID:          c.ID,
			Domain:      c.Domain,
			DomainID:    domainID,
			Issuer:      c.Issuer,
			ExpiresAt:   c.ExpiresAt.UTC().Format(time.RFC3339),
			UpdatedAt:   c.UpdatedAt.UTC().Format(time.RFC3339),
			DaysLeft:    daysLeft,
			DNSProvider: dnsProv,
			CertMethod:  certMethod,
			Status:      status,
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
		if !isCtxErr(err) {
			h.Log.Error("certs: delete", "err", err)
		}
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

type importCertReq struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
	// Issuer optionnel — "custom" par défaut
	Issuer string `json:"issuer"`
}

// importCert valide et stocke un certificat fourni manuellement (non-ACME).
func (h *CertsHandler) importCert(w http.ResponseWriter, r *http.Request) {
	var req importCertReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_request")
		return
	}
	if strings.TrimSpace(req.CertPEM) == "" || strings.TrimSpace(req.KeyPEM) == "" {
		http.Error(w, "cert_pem et key_pem requis", http.StatusBadRequest)
		return
	}

	// Parse le premier bloc PEM pour extraire domain et expiration
	block, _ := pem.Decode([]byte(req.CertPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		http.Error(w, "cert_pem invalide : bloc CERTIFICATE introuvable", http.StatusBadRequest)
		return
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		http.Error(w, "cert_pem invalide : "+err.Error(), http.StatusBadRequest)
		return
	}

	// Détermine le nom canonique : CN ou premier SAN DNS
	domain := leaf.Subject.CommonName
	if len(leaf.DNSNames) > 0 {
		domain = leaf.DNSNames[0]
	}
	if domain == "" {
		http.Error(w, "impossible de déterminer le domaine depuis le certificat", http.StatusBadRequest)
		return
	}

	issuer := req.Issuer
	if issuer == "" {
		issuer = "custom"
	}

	var id string
	err = h.DB.QueryRowContext(r.Context(),
		`INSERT INTO certs (id, domain, issuer, expires_at, cert_pem, key_pem)
		 VALUES (lower(hex(randomblob(16))), ?, ?, ?, ?, ?)
		 ON CONFLICT(domain) DO UPDATE SET
		   issuer=excluded.issuer, expires_at=excluded.expires_at,
		   cert_pem=excluded.cert_pem, key_pem=excluded.key_pem,
		   updated_at=CURRENT_TIMESTAMP
		 RETURNING id`,
		domain, issuer, leaf.NotAfter, req.CertPEM, req.KeyPEM).Scan(&id)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("certs: import", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	// Pousse vers les passerelles si disponible
	if h.Pusher != nil {
		go h.Pusher.PushCert(context.Background(), domain, []byte(req.CertPEM), []byte(req.KeyPEM))
	}

	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"id":         id,
		"domain":     domain,
		"expires_at": leaf.NotAfter.UTC().Format(time.RFC3339),
	})
}
