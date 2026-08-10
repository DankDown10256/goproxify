// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mfa

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Method représente le type de 2FA.
type Method string

const (
	MethodTOTP       Method = "totp"
	MethodEmail      Method = "email"
	MethodSMS        Method = "sms"
	MethodPushNtfy   Method = "push_ntfy"
	MethodPushGotify Method = "push_gotify"
	MethodWebAuthn   Method = "webauthn"
	MethodBackup     Method = "backup_codes"
)

// Store gère la persistance des données MFA.
type Store struct {
	db *sql.DB
}

// NewStore crée un Store.
func NewStore(db *sql.DB) *Store { return &Store{db: db} }

// UserMFA représente une méthode MFA activée pour un utilisateur.
type UserMFA struct {
	ID       string          `json:"id"`
	UserID   string          `json:"user_id"`
	Method   Method          `json:"method"`
	Config   json.RawMessage `json:"config"`
	Enabled  bool            `json:"enabled"`
	Verified bool            `json:"verified"`
}

// ListMethods retourne toutes les méthodes MFA d'un utilisateur.
func (s *Store) ListMethods(ctx context.Context, userID string) ([]UserMFA, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, user_id, method, config, enabled, verified FROM user_mfa WHERE user_id=?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []UserMFA
	for rows.Next() {
		var m UserMFA
		var cfg string
		var enabled, verified int
		if err := rows.Scan(&m.ID, &m.UserID, &m.Method, &cfg, &enabled, &verified); err != nil {
			continue
		}
		m.Config = json.RawMessage(cfg)
		m.Enabled = enabled == 1
		m.Verified = verified == 1
		list = append(list, m)
	}
	return list, nil
}

// HasVerifiedMFA indique si l'utilisateur a au moins une méthode MFA activée et vérifiée.
func (s *Store) HasVerifiedMFA(ctx context.Context, userID string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM user_mfa WHERE user_id=? AND enabled=1 AND verified=1`, userID,
	).Scan(&count)
	return count > 0, err
}

// UpsertMethod crée ou met à jour une méthode MFA (non encore vérifiée par défaut).
func (s *Store) UpsertMethod(ctx context.Context, userID string, method Method, cfg any, verified bool) error {
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	id := uuid.New().String()
	v := 0
	if verified {
		v = 1
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO user_mfa (id, user_id, method, config, enabled, verified)
		 VALUES (?, ?, ?, ?, 1, ?)
		 ON CONFLICT(user_id, method) DO UPDATE SET config=excluded.config, verified=excluded.verified, enabled=1`,
		id, userID, method, string(b), v,
	)
	return err
}

// MarkVerified marque une méthode MFA comme vérifiée.
func (s *Store) MarkVerified(ctx context.Context, userID string, method Method) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE user_mfa SET verified=1 WHERE user_id=? AND method=?`, userID, method)
	return err
}

// DeleteMethod supprime une méthode MFA.
func (s *Store) DeleteMethod(ctx context.Context, userID string, method Method) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM user_mfa WHERE user_id=? AND method=?`, userID, method)
	return err
}

// GetMethodConfig lit la config JSON d'une méthode MFA et la désérialise dans dest.
func (s *Store) GetMethodConfig(ctx context.Context, userID string, method Method, dest any) error {
	var cfg string
	err := s.db.QueryRowContext(ctx,
		`SELECT config FROM user_mfa WHERE user_id=? AND method=? AND enabled=1`, userID, method,
	).Scan(&cfg)
	if err == sql.ErrNoRows {
		return fmt.Errorf("mfa: méthode %s non configurée", method)
	}
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(cfg), dest)
}

// --- Challenges OTP ---

// CreateChallenge crée un challenge OTP (code hashé bcrypt, TTL 5 min).
func (s *Store) CreateChallenge(ctx context.Context, userID string, method Method, code string, extraData any) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	data := "{}"
	if extraData != nil {
		b, _ := json.Marshal(extraData)
		data = string(b)
	}
	id := uuid.New().String()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO user_mfa_challenges (id, user_id, method, code_hash, data, expires_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, userID, method, string(hash), data,
		time.Now().Add(5*time.Minute),
	)
	return id, err
}

// VerifyChallenge vérifie un code OTP et marque le challenge comme utilisé.
func (s *Store) VerifyChallenge(ctx context.Context, userID string, method Method, code string) (string, bool) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, code_hash FROM user_mfa_challenges
		 WHERE user_id=? AND method=? AND used=0 AND expires_at > CURRENT_TIMESTAMP
		 ORDER BY created_at DESC LIMIT 5`,
		userID, method,
	)
	if err != nil {
		return "", false
	}
	defer rows.Close()
	for rows.Next() {
		var id, hash string
		if err := rows.Scan(&id, &hash); err != nil {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(code)) == nil {
			s.db.ExecContext(ctx, `UPDATE user_mfa_challenges SET used=1 WHERE id=?`, id) //nolint:errcheck
			return id, true
		}
	}
	return "", false
}

// CreateWebAuthnChallenge stocke les données de session WebAuthn.
func (s *Store) CreateWebAuthnChallenge(ctx context.Context, userID string, sessionData any) (string, error) {
	b, err := json.Marshal(sessionData)
	if err != nil {
		return "", err
	}
	id := uuid.New().String()
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO user_mfa_challenges (id, user_id, method, data, expires_at)
		 VALUES (?, ?, 'webauthn', ?, ?)`,
		id, userID, string(b), time.Now().Add(5*time.Minute),
	)
	return id, err
}

// GetWebAuthnChallenge lit et consomme les données de session WebAuthn.
func (s *Store) GetWebAuthnChallenge(ctx context.Context, challengeID string, dest any) error {
	var data string
	err := s.db.QueryRowContext(ctx,
		`SELECT data FROM user_mfa_challenges WHERE id=? AND used=0 AND expires_at > CURRENT_TIMESTAMP`,
		challengeID,
	).Scan(&data)
	if err == sql.ErrNoRows {
		return fmt.Errorf("mfa: challenge expiré ou introuvable")
	}
	if err != nil {
		return err
	}
	s.db.ExecContext(ctx, `UPDATE user_mfa_challenges SET used=1 WHERE id=?`, challengeID) //nolint:errcheck
	return json.Unmarshal([]byte(data), dest)
}

// --- Backup codes ---

// SaveBackupCodes remplace les backup codes existants d'un utilisateur.
func (s *Store) SaveBackupCodes(ctx context.Context, userID string, hashes []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_backup_codes WHERE user_id=?`, userID); err != nil {
		return err
	}
	for _, h := range hashes {
		_, err := tx.ExecContext(ctx,
			`INSERT INTO user_backup_codes (id, user_id, code_hash) VALUES (?, ?, ?)`,
			uuid.New().String(), userID, h,
		)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

// VerifyBackupCode vérifie et consomme un code de secours.
func (s *Store) VerifyBackupCode(ctx context.Context, userID, code string) bool {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, code_hash FROM user_backup_codes WHERE user_id=? AND used=0`, userID)
	if err != nil {
		return false
	}
	defer rows.Close()
	normalized := code
	for _, c := range []string{"-", " "} {
		normalized = replaceAll(normalized, c, "")
	}
	for rows.Next() {
		var id, hash string
		if err := rows.Scan(&id, &hash); err != nil {
			continue
		}
		if CheckBackupCode(hash, normalized) {
			s.db.ExecContext(ctx, //nolint:errcheck
				`UPDATE user_backup_codes SET used=1, used_at=CURRENT_TIMESTAMP WHERE id=?`, id)
			return true
		}
	}
	return false
}

// BackupCodesLeft retourne le nombre de codes non utilisés restants.
func (s *Store) BackupCodesLeft(ctx context.Context, userID string) int {
	var n int
	s.db.QueryRowContext(ctx, //nolint:errcheck
		`SELECT COUNT(*) FROM user_backup_codes WHERE user_id=? AND used=0`, userID,
	).Scan(&n)
	return n
}

// --- Trusted devices ---

// TrustedDevice représente un appareil de confiance.
type TrustedDevice struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateTrustedDevice enregistre un nouvel appareil de confiance.
func (s *Store) CreateTrustedDevice(ctx context.Context, userID, tokenHash, name string) (string, error) {
	id := uuid.New().String()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO user_trusted_devices (id, user_id, token_hash, name, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		id, userID, tokenHash, name,
		time.Now().AddDate(0, 0, TrustedDeviceTTLDays),
	)
	return id, err
}

// IsTrustedDevice vérifie qu'un token appareil est valide pour cet utilisateur.
func (s *Store) IsTrustedDevice(ctx context.Context, userID, tokenHash string) bool {
	var id string
	err := s.db.QueryRowContext(ctx,
		`SELECT id FROM user_trusted_devices WHERE user_id=? AND token_hash=? AND expires_at > CURRENT_TIMESTAMP`,
		userID, tokenHash,
	).Scan(&id)
	return err == nil
}

// ListTrustedDevices liste les appareils de confiance d'un utilisateur.
func (s *Store) ListTrustedDevices(ctx context.Context, userID string) ([]TrustedDevice, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, expires_at, created_at FROM user_trusted_devices WHERE user_id=? ORDER BY created_at DESC`,
		userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []TrustedDevice
	for rows.Next() {
		var d TrustedDevice
		if err := rows.Scan(&d.ID, &d.Name, &d.ExpiresAt, &d.CreatedAt); err != nil {
			continue
		}
		list = append(list, d)
	}
	return list, nil
}

// DeleteTrustedDevice révoque un appareil de confiance.
func (s *Store) DeleteTrustedDevice(ctx context.Context, userID, deviceID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM user_trusted_devices WHERE id=? AND user_id=?`, deviceID, userID)
	return err
}

func replaceAll(s, old, new string) string {
	result := ""
	for _, c := range s {
		if string(c) == old {
			result += new
		} else {
			result += string(c)
		}
	}
	return result
}
