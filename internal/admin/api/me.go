// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// MeHandler gère /api/v1/me — profil de l'utilisateur connecté.
type MeHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

type meScope struct {
	Type       string `json:"type"`
	Value      string `json:"value"`
	AccessMode string `json:"access_mode,omitempty"`
}

type meTeam struct {
	TeamID   string    `json:"team_id"`
	TeamName string    `json:"team_name"`
	Scopes   []meScope `json:"scopes"`
}

type meResponse struct {
	ID              string     `json:"id"`
	Email           string     `json:"email"`
	Role            string     `json:"role"` // "superadmin" | "admin" | "user"
	IsSuper         bool       `json:"is_super"`
	CreatedAt       *time.Time `json:"created_at,omitempty"`
	Teams           []meTeam   `json:"teams"`
	EffectiveScopes []meScope  `json:"effective_scopes"`
}

func (h *MeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userID := adminauth.UserIDFromContext(r.Context())
	if userID == "" {
		writeErr(w, r, http.StatusUnauthorized, "api.err.unauth")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/me")
	path = strings.TrimPrefix(path, "/")

	switch {
	case r.Method == http.MethodGet && path == "":
		h.getMe(w, r, userID)
	case r.Method == http.MethodPatch && path == "":
		h.updateEmail(w, r, userID)
	case r.Method == http.MethodPost && path == "change-password":
		h.changePassword(w, r, userID)
	case path == "tokens" || strings.HasPrefix(path, "tokens/"):
		// Fallback si le mux envoie /me/tokens vers MeHandler.
		(&UserTokensHandler{DB: h.DB, Log: h.Log}).ServeHTTP(w, r)
	default:
		http.Error(w, "route inconnue", http.StatusNotFound)
	}
}

// GetMeHTTP est un http.HandlerFunc compatible pour GET /api/v1/auth/me.
func (h *MeHandler) GetMeHTTP(w http.ResponseWriter, r *http.Request) {
	userID := adminauth.UserIDFromContext(r.Context())
	if userID == "" {
		writeErr(w, r, http.StatusUnauthorized, "api.err.unauth")
		return
	}
	h.getMe(w, r, userID)
}

func (h *MeHandler) getMe(w http.ResponseWriter, r *http.Request, userID string) {
	var me meResponse
	var createdAt sql.NullTime
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, email, role, created_at FROM users WHERE id=?`, userID,
	).Scan(&me.ID, &me.Email, &me.Role, &createdAt)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "api.err.user_not_found")
		return
	}
	if createdAt.Valid {
		me.CreatedAt = &createdAt.Time
	}
	me.IsSuper = me.Role == "superadmin"

	// Équipes + grants ; effective = union user_scopes + team_scopes (max mode côté client via mode)
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT tm.team_id, t.name
		FROM team_members tm
		JOIN teams t ON t.id = tm.team_id
		WHERE tm.user_id = ?
		ORDER BY t.name`, userID)
	me.Teams = []meTeam{}
	me.EffectiveScopes = []meScope{}
	seenScopes := map[string]string{} // key → access_mode (write gagne)
	addEffective := func(s meScope) {
		key := s.Type + ":" + s.Value
		prev, ok := seenScopes[key]
		if !ok || (s.AccessMode == "write" && prev != "write") {
			seenScopes[key] = s.AccessMode
		}
	}
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var mt meTeam
			if rows.Scan(&mt.TeamID, &mt.TeamName) != nil {
				continue
			}
			srows, _ := h.DB.QueryContext(r.Context(),
				`SELECT scope_type, scope_value, access_mode FROM team_scopes WHERE team_id=? ORDER BY scope_type, scope_value`,
				mt.TeamID)
			mt.Scopes = []meScope{}
			if srows != nil {
				for srows.Next() {
					var s meScope
					if srows.Scan(&s.Type, &s.Value, &s.AccessMode) == nil {
						mt.Scopes = append(mt.Scopes, s)
						addEffective(s)
					}
				}
				srows.Close()
			}
			me.Teams = append(me.Teams, mt)
		}
	}
	urow, _ := h.DB.QueryContext(r.Context(),
		`SELECT scope_type, scope_value, access_mode FROM user_scopes WHERE user_id=?`, userID)
	if urow != nil {
		defer urow.Close()
		for urow.Next() {
			var s meScope
			if urow.Scan(&s.Type, &s.Value, &s.AccessMode) == nil {
				addEffective(s)
			}
		}
	}
	for key, mode := range seenScopes {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) != 2 {
			continue
		}
		me.EffectiveScopes = append(me.EffectiveScopes, meScope{Type: parts[0], Value: parts[1], AccessMode: mode})
	}

	jsonOK(w, me)
}

func (h *MeHandler) updateEmail(w http.ResponseWriter, r *http.Request, userID string) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Email) == "" {
		http.Error(w, "email invalide", http.StatusBadRequest)
		return
	}
	_, err := h.DB.ExecContext(r.Context(),
		`UPDATE users SET email=? WHERE id=?`, strings.TrimSpace(req.Email), userID)
	if err != nil {
		writeErr(w, r, http.StatusConflict, "api.err.email_taken")
		return
	}
	_ = admindb.WriteAudit(h.DB, userID, "update_email", "user:"+userID, req.Email)
	w.WriteHeader(http.StatusNoContent)
}

type changePwReq struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (h *MeHandler) changePassword(w http.ResponseWriter, r *http.Request, userID string) {
	var req changePwReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		http.Error(w, "champs requis", http.StatusBadRequest)
		return
	}

	var hash string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT password_hash FROM users WHERE id=?`, userID).Scan(&hash); err != nil {
		writeErr(w, r, http.StatusNotFound, "api.err.user_not_found")
		return
	}
	if !adminauth.CheckPassword(hash, req.CurrentPassword) {
		http.Error(w, "mot de passe actuel incorrect", http.StatusUnauthorized)
		return
	}

	newHash, err := adminauth.HashPassword(req.NewPassword)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	h.DB.ExecContext(r.Context(), `UPDATE users SET password_hash=? WHERE id=?`, newHash, userID) //nolint:errcheck
	_ = admindb.WriteAudit(h.DB, userID, "change_password", "user:"+userID, "")
	w.WriteHeader(http.StatusNoContent)
}
