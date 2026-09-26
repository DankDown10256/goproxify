// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
)

// maxRecordingBytes borne la sortie gardée en mémoire puis écrite pour une session.
const maxRecordingBytes = 8 << 20

var recordingIDRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// RecordingMeta décrit un enregistrement (non sensible, stocké en clair à côté du fichier chiffré).
type RecordingMeta struct {
	ID          string  `json:"id"`
	Actor       string  `json:"actor"`
	TargetID    string  `json:"target_id"`
	Facade      string  `json:"facade"`
	Remote      string  `json:"remote,omitempty"`
	Started     string  `json:"started"`
	DurationSec float64 `json:"duration_sec"`
	Bytes       int     `json:"bytes"`
	Truncated   bool    `json:"truncated,omitempty"`
}

// RecordingStore range les enregistrements de sessions : sortie du terminal (format asciicast v2),
// chiffrée au repos avec une clé dérivée du secret du portail. La saisie de l'utilisateur n'est jamais gardée.
type RecordingStore struct {
	dir string
	key [32]byte
}

// NewRecordingStore prépare le dossier et la clé.
func NewRecordingStore(dir, secret string) (*RecordingStore, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &RecordingStore{dir: dir}
	r := hkdf.New(sha256.New, []byte(secret), []byte("goproxify-portal-recording"), nil)
	_, _ = io.ReadFull(r, s.key[:])
	return s, nil
}

// Recording accumule la sortie d'une session ; sûr d'appel sur un pointeur nul.
type Recording struct {
	store *RecordingStore
	meta  RecordingMeta
	start time.Time

	mu        sync.Mutex
	buf       bytes.Buffer
	truncated bool
}

// Start ouvre l'enregistrement d'une session.
func (s *RecordingStore) Start(actor, targetID, facade, remote string) *Recording {
	if s == nil {
		return nil
	}
	now := time.Now().UTC()
	r := &Recording{
		store: s,
		start: now,
		meta: RecordingMeta{
			ID: uuid.NewString(), Actor: actor, TargetID: targetID, Facade: facade, Remote: remote,
			Started: now.Format(time.RFC3339),
		},
	}
	hdr, _ := json.Marshal(map[string]any{
		"version": 2, "width": 120, "height": 40, "timestamp": now.Unix(),
		"title": actor + " → " + targetID,
	})
	r.buf.Write(hdr)
	r.buf.WriteByte('\n')
	return r
}

// Output ajoute des octets envoyés au terminal de l'utilisateur.
func (r *Recording) Output(p []byte) {
	if r == nil || len(p) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.truncated || r.buf.Len() > maxRecordingBytes {
		r.truncated = true
		return
	}
	line, _ := json.Marshal([]any{time.Since(r.start).Seconds(), "o", string(p)})
	r.buf.Write(line)
	r.buf.WriteByte('\n')
}

// Close écrit l'enregistrement chiffré et ses métadonnées.
func (r *Recording) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.meta.DurationSec = time.Since(r.start).Seconds()
	r.meta.Bytes = r.buf.Len()
	r.meta.Truncated = r.truncated
	data := append([]byte(nil), r.buf.Bytes()...)
	meta := r.meta
	r.mu.Unlock()
	_ = r.store.save(meta, data)
}

func (s *RecordingStore) path(id, ext string) string { return filepath.Join(s.dir, id+ext) }

func writeFileAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *RecordingStore) save(meta RecordingMeta, cast []byte) error {
	enc, err := encryptWithKey(cast, s.key)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(s.path(meta.ID, ".cast.gpx"), enc); err != nil {
		return err
	}
	raw, _ := json.Marshal(meta)
	return writeFileAtomic(s.path(meta.ID, ".json"), raw)
}

// List retourne les enregistrements, les plus récents d'abord.
func (s *RecordingStore) List() ([]RecordingMeta, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	out := []RecordingMeta{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			continue
		}
		var m RecordingMeta
		if json.Unmarshal(raw, &m) == nil && recordingIDRe.MatchString(m.ID) {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Started > out[j].Started })
	return out, nil
}

// Read retourne l'enregistrement déchiffré (asciicast v2).
func (s *RecordingStore) Read(id string) ([]byte, error) {
	if !recordingIDRe.MatchString(id) {
		return nil, os.ErrNotExist
	}
	enc, err := os.ReadFile(s.path(id, ".cast.gpx"))
	if err != nil {
		return nil, err
	}
	return decryptWithKey(enc, s.key)
}

// Delete supprime un enregistrement.
func (s *RecordingStore) Delete(id string) error {
	if !recordingIDRe.MatchString(id) {
		return os.ErrNotExist
	}
	if _, err := os.Stat(s.path(id, ".json")); err != nil {
		return err
	}
	_ = os.Remove(s.path(id, ".cast.gpx"))
	return os.Remove(s.path(id, ".json"))
}

// Purge supprime les enregistrements plus vieux que days jours et retourne leur nombre.
func (s *RecordingStore) Purge(days int, now time.Time) int {
	if s == nil || days <= 0 {
		return 0
	}
	list, err := s.List()
	if err != nil {
		return 0
	}
	limit := now.AddDate(0, 0, -days)
	n := 0
	for _, m := range list {
		if t, err := time.Parse(time.RFC3339, m.Started); err == nil && t.Before(limit) {
			if s.Delete(m.ID) == nil {
				n++
			}
		}
	}
	return n
}


func (h *HTTPServer) startRecording(actor, targetID, facade, remote string) *Recording {
	if h.record == nil {
		return nil
	}
	return h.record(actor, targetID, facade, remote)
}
