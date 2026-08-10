// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/core/errorpages"
)

// ErrorPageTemplatePusher pousse la bibliothèque vers les Cores.
type ErrorPageTemplatePusher interface {
	PushErrorPages(ctx context.Context)
}

// ErrorPageAssetDTO est un asset (image, CSS…) attaché à un template.
type ErrorPageAssetDTO struct {
	ID          string `json:"id,omitempty"`
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	// ContentB64 : contenu encodé base64 (écriture / sync).
	ContentB64 string `json:"content_b64,omitempty"`
	// Size : taille en octets (lecture liste, sans body).
	Size int `json:"size,omitempty"`
}

// ErrorPageTemplateDTO est un template de la bibliothèque Admin.
type ErrorPageTemplateDTO struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Body        string              `json:"body"`
	ScopeType   string              `json:"scope_type"`
	ScopeID     string              `json:"scope_id"`
	Assets      []ErrorPageAssetDTO `json:"assets,omitempty"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
}

// ErrorPageTemplatesHandler CRUD + sync Core.
type ErrorPageTemplatesHandler struct {
	DB     *sql.DB
	Log    *slog.Logger
	Pusher ErrorPageTemplatePusher
}

func (h *ErrorPageTemplatesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/error-page-templates")
	path = strings.TrimPrefix(path, "/")
	parts := strings.Split(path, "/")
	id := parts[0]

	switch {
	case r.Method == http.MethodGet && id == "":
		h.list(w, r)
	case r.Method == http.MethodGet && id != "" && len(parts) == 1:
		h.get(w, r, id)
	case r.Method == http.MethodPost && id == "":
		h.create(w, r)
	case r.Method == http.MethodPut && id != "" && len(parts) == 1:
		h.update(w, r, id)
	case r.Method == http.MethodDelete && id != "" && len(parts) == 1:
		h.delete(w, r, id)
	case r.Method == http.MethodPost && id != "" && len(parts) == 2 && parts[1] == "assets":
		h.addAsset(w, r, id)
	case r.Method == http.MethodDelete && id != "" && len(parts) == 3 && parts[1] == "assets":
		h.deleteAsset(w, r, id, parts[2])
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func (h *ErrorPageTemplatesHandler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, name, description, body, scope_type, scope_id, created_at, updated_at
		 FROM error_page_templates WHERE scope_type='admin' ORDER BY name`)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("error-page-templates: list", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()

	out := make([]ErrorPageTemplateDTO, 0)
	for rows.Next() {
		var t ErrorPageTemplateDTO
		if err := rows.Scan(&t.ID, &t.Name, &t.Description, &t.Body, &t.ScopeType, &t.ScopeID, &t.CreatedAt, &t.UpdatedAt); err != nil {
			continue
		}
		t.Assets = h.listAssetsMeta(r.Context(), t.ID)
		out = append(out, t)
	}
	jsonOK(w, out)
}

func (h *ErrorPageTemplatesHandler) get(w http.ResponseWriter, r *http.Request, id string) {
	t, err := h.loadTemplate(r.Context(), id, true)
	if err == sql.ErrNoRows {
		http.Error(w, "template introuvable", http.StatusNotFound)
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, t)
}

type errorPageTemplateRequest struct {
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Body        string              `json:"body"`
	Assets      []ErrorPageAssetDTO `json:"assets,omitempty"`
}

func (h *ErrorPageTemplatesHandler) create(w http.ResponseWriter, r *http.Request) {
	var req errorPageTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || strings.TrimSpace(req.Body) == "" {
		http.Error(w, "name et body requis", http.StatusBadRequest)
		return
	}
	id := uuid.New().String()
	_, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO error_page_templates (id, name, description, body, scope_type, scope_id)
		 VALUES (?, ?, ?, ?, 'admin', '')`,
		id, req.Name, req.Description, req.Body)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("error-page-templates: create", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if err := h.replaceAssets(r.Context(), id, req.Assets); err != nil {
		h.Log.Error("error-page-templates: assets", "err", err)
		http.Error(w, "assets invalides", http.StatusBadRequest)
		return
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "create", "error_page_template:"+id, req.Name)
	h.push(r.Context())

	t, _ := h.loadTemplate(r.Context(), id, true)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(t) //nolint:errcheck
}

func (h *ErrorPageTemplatesHandler) update(w http.ResponseWriter, r *http.Request, id string) {
	var req errorPageTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || strings.TrimSpace(req.Body) == "" {
		http.Error(w, "name et body requis", http.StatusBadRequest)
		return
	}
	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE error_page_templates SET name=?, description=?, body=?, updated_at=CURRENT_TIMESTAMP
		 WHERE id=? AND scope_type='admin'`,
		req.Name, req.Description, req.Body, id)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("error-page-templates: update", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "template introuvable", http.StatusNotFound)
		return
	}
	// Si assets fournis (même vide), remplacer ; sinon laisser les existants.
	if req.Assets != nil {
		if err := h.replaceAssets(r.Context(), id, req.Assets); err != nil {
			http.Error(w, "assets invalides", http.StatusBadRequest)
			return
		}
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "update", "error_page_template:"+id, req.Name)
	h.push(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (h *ErrorPageTemplatesHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	_, _ = h.DB.ExecContext(r.Context(), `DELETE FROM error_page_assets WHERE template_id=?`, id)
	res, err := h.DB.ExecContext(r.Context(),
		`DELETE FROM error_page_templates WHERE id=? AND scope_type='admin'`, id)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("error-page-templates: delete", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "template introuvable", http.StatusNotFound)
		return
	}
	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "delete", "error_page_template:"+id, "")
	h.push(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (h *ErrorPageTemplatesHandler) addAsset(w http.ResponseWriter, r *http.Request, templateID string) {
	var req ErrorPageAssetDTO
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	fn, ok := errorpages.SanitizeFilename(req.Filename)
	if !ok {
		http.Error(w, "filename invalide", http.StatusBadRequest)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(req.ContentB64)
	if err != nil || len(raw) == 0 {
		http.Error(w, "content_b64 invalide", http.StatusBadRequest)
		return
	}
	var exists string
	err = h.DB.QueryRowContext(r.Context(),
		`SELECT id FROM error_page_templates WHERE id=? AND scope_type='admin'`, templateID).Scan(&exists)
	if err == sql.ErrNoRows {
		http.Error(w, "template introuvable", http.StatusNotFound)
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	ct := req.ContentType
	if ct == "" {
		ct = "application/octet-stream"
	}
	id := uuid.New().String()
	_, err = h.DB.ExecContext(r.Context(),
		`INSERT INTO error_page_assets (id, template_id, filename, content_type, content)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(template_id, filename) DO UPDATE SET
		   content_type=excluded.content_type, content=excluded.content`,
		id, templateID, fn, ct, raw)
	if err != nil {
		h.Log.Error("error-page-templates: add asset", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	_, _ = h.DB.ExecContext(r.Context(),
		`UPDATE error_page_templates SET updated_at=CURRENT_TIMESTAMP WHERE id=?`, templateID)
	h.push(r.Context())
	jsonOK(w, ErrorPageAssetDTO{ID: id, Filename: fn, ContentType: ct, Size: len(raw)})
}

func (h *ErrorPageTemplatesHandler) deleteAsset(w http.ResponseWriter, r *http.Request, templateID, filename string) {
	fn, ok := errorpages.SanitizeFilename(filename)
	if !ok {
		http.Error(w, "filename invalide", http.StatusBadRequest)
		return
	}
	res, err := h.DB.ExecContext(r.Context(),
		`DELETE FROM error_page_assets WHERE template_id=? AND filename=?`, templateID, fn)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "asset introuvable", http.StatusNotFound)
		return
	}
	h.push(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (h *ErrorPageTemplatesHandler) push(ctx context.Context) {
	if h.Pusher != nil {
		h.Pusher.PushErrorPages(ctx)
	}
}

func (h *ErrorPageTemplatesHandler) loadTemplate(ctx context.Context, id string, withContent bool) (ErrorPageTemplateDTO, error) {
	var t ErrorPageTemplateDTO
	err := h.DB.QueryRowContext(ctx,
		`SELECT id, name, description, body, scope_type, scope_id, created_at, updated_at
		 FROM error_page_templates WHERE id=?`, id,
	).Scan(&t.ID, &t.Name, &t.Description, &t.Body, &t.ScopeType, &t.ScopeID, &t.CreatedAt, &t.UpdatedAt)
	if err != nil {
		return t, err
	}
	if withContent {
		t.Assets = h.listAssetsFull(ctx, id)
	} else {
		t.Assets = h.listAssetsMeta(ctx, id)
	}
	return t, nil
}

func (h *ErrorPageTemplatesHandler) listAssetsMeta(ctx context.Context, templateID string) []ErrorPageAssetDTO {
	rows, err := h.DB.QueryContext(ctx,
		`SELECT id, filename, content_type, length(content) FROM error_page_assets WHERE template_id=? ORDER BY filename`,
		templateID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []ErrorPageAssetDTO
	for rows.Next() {
		var a ErrorPageAssetDTO
		if err := rows.Scan(&a.ID, &a.Filename, &a.ContentType, &a.Size); err != nil {
			continue
		}
		out = append(out, a)
	}
	return out
}

func (h *ErrorPageTemplatesHandler) listAssetsFull(ctx context.Context, templateID string) []ErrorPageAssetDTO {
	rows, err := h.DB.QueryContext(ctx,
		`SELECT id, filename, content_type, content FROM error_page_assets WHERE template_id=? ORDER BY filename`,
		templateID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []ErrorPageAssetDTO
	for rows.Next() {
		var a ErrorPageAssetDTO
		var raw []byte
		if err := rows.Scan(&a.ID, &a.Filename, &a.ContentType, &raw); err != nil {
			continue
		}
		a.ContentB64 = base64.StdEncoding.EncodeToString(raw)
		a.Size = len(raw)
		out = append(out, a)
	}
	return out
}

func (h *ErrorPageTemplatesHandler) replaceAssets(ctx context.Context, templateID string, assets []ErrorPageAssetDTO) error {
	_, err := h.DB.ExecContext(ctx, `DELETE FROM error_page_assets WHERE template_id=?`, templateID)
	if err != nil {
		return err
	}
	for _, a := range assets {
		fn, ok := errorpages.SanitizeFilename(a.Filename)
		if !ok {
			return errInvalidAsset
		}
		raw, err := base64.StdEncoding.DecodeString(a.ContentB64)
		if err != nil {
			return err
		}
		ct := a.ContentType
		if ct == "" {
			ct = "application/octet-stream"
		}
		_, err = h.DB.ExecContext(ctx,
			`INSERT INTO error_page_assets (id, template_id, filename, content_type, content)
			 VALUES (?, ?, ?, ?, ?)`,
			uuid.New().String(), templateID, fn, ct, raw)
		if err != nil {
			return err
		}
	}
	return nil
}

var errInvalidAsset = errString("asset invalide")

type errString string

func (e errString) Error() string { return string(e) }
