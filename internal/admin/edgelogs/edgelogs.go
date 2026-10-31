// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package edgelogs est le volume de logs de l'Admin (ADR 0018) : un store du moteur de la passerelle
// (internal/edge/logstore) par passerelle, dans un dossier à part de la base de gestion. L'Admin y range toutes les lignes que
// chaque passerelle lui envoie ; la position de chaque flux vit avec les lignes, dans le même volume.
package edgelogs

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logserve"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

// ErrClosed : le volume de logs est fermé.
var ErrClosed = errors.New("edgelogs: volume de logs fermé")

// Vault ouvre, à la demande, le store de chaque passerelle.
type Vault struct {
	dir string
	key []byte
	log *slog.Logger

	mu        sync.Mutex
	stores    map[string]*entry
	retention map[logstore.Kind]time.Duration // durées de conservation réglées par l'Admin ; vide : celles du moteur (365 et 90 jours)
	readOnly  bool                            // volume ouvert pour lire seulement (commande locale) : ni écriture, ni purge
	closed    bool                            // après Close, plus aucun store n'est rouvert (un acquittement différé ne doit pas reprendre un fichier)
}

type entry struct {
	svc   *logserve.Service
	store *logstore.Store
	name  string
}

// Open prépare le volume de logs. key chiffre l'IP réelle des lignes pseudonymisées (la clé de l'Admin) ; sans clé
// valide, une IP réelle reçue est ignorée et seule l'IP tronquée est gardée.
func Open(dir string, key []byte, log *slog.Logger) (*Vault, error) {
	if dir == "" {
		return nil, fmt.Errorf("edgelogs: dossier requis")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("edgelogs: %w", err)
	}
	if log == nil {
		log = slog.Default()
	}
	return &Vault{dir: dir, key: key, log: log, stores: map[string]*entry{}}, nil
}

// Dir rend le dossier du volume de logs.
func (v *Vault) Dir() string { return v.dir }

// Store rend le store de la passerelle nodeID. name, quand il est connu, est retenu dans le dossier (node.json) pour qu'on
// sache à qui appartient un dossier même quand la passerelle a été retirée ou renommée.
func (v *Vault) Store(nodeID, name string) (*logstore.Store, error) {
	if nodeID == "" {
		return nil, fmt.Errorf("edgelogs: identifiant de passerelle requis")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil, ErrClosed
	}
	if e, ok := v.stores[nodeID]; ok {
		if name != "" && name != e.name {
			e.name = name
			v.writeMeta(nodeID, name)
		}
		return e.store, nil
	}
	dir := filepath.Join(v.dir, dirName(nodeID))
	s, err := logstore.Open(logstore.Options{
		Dir:   dir,
		IPKey: v.key,
		// Un seul registre de gels légaux pour tout le volume : un gel vaut pour toutes les passerelles.
		Retention: v.retentionCopy(),
		HoldsPath: filepath.Join(v.dir, "legal-holds.json"),
		ReadOnly:  v.readOnly,
		OnError: func(err error) {
			v.log.Warn("edgelogs: écriture dans le store d'une passerelle", "edge", nodeID, "err", err)
		},
	})
	if err != nil {
		return nil, err
	}
	e := &entry{store: s, name: name}
	v.stores[nodeID] = e
	if name != "" {
		v.writeMeta(nodeID, name)
	}
	return s, nil
}

type meta struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func (v *Vault) writeMeta(nodeID, name string) {
	raw, err := json.Marshal(meta{ID: nodeID, Name: name})
	if err != nil {
		return
	}
	path := filepath.Join(v.dir, dirName(nodeID), "node.json")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		v.log.Warn("edgelogs: écriture de node.json", "edge", nodeID, "err", err)
	}
}

// Close ferme tous les stores ouverts.
func (v *Vault) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.closed = true
	for id, e := range v.stores {
		if err := e.store.Close(); err != nil {
			v.log.Warn("edgelogs: fermeture du store d'une passerelle", "edge", id, "err", err)
		}
		delete(v.stores, id)
	}
}

// dirName donne un nom de dossier sûr pour un identifiant de passerelle : l'identifiant vient d'une connexion, jamais
// d'un chemin.
func dirName(nodeID string) string {
	var b strings.Builder
	for _, r := range nodeID {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 || b.String() == "." || b.String() == ".." {
		return "_"
	}
	return b.String()
}

// EraseIP supprime d'une IP les lignes de tous les stores du volume (droit à l'effacement RGPD), passerelles retirées
// comprises, et rend leur nombre. Une IP pseudonymisée est retrouvée par son empreinte.
func (v *Vault) EraseIP(ip string) (int64, error) {
	entries, err := os.ReadDir(v.dir)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, de := range entries {
		if !de.IsDir() {
			continue
		}
		s, err := v.Store(de.Name(), "")
		if err != nil {
			return total, err
		}
		n, err := s.EraseIP(ip)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// OpenReadOnly ouvre le volume pour une commande locale (export, gel légal) : les stores sont ouverts en lecture seule,
// sans écriture ni purge, même quand l'Admin tourne.
func OpenReadOnly(dir string, key []byte, log *slog.Logger) (*Vault, error) {
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("dossier du volume de logs introuvable (%s)", dir)
	}
	v, err := Open(dir, key, log)
	if err != nil {
		return nil, err
	}
	v.readOnly = true
	return v, nil
}

// retentionCopy rend les durées réglées (v.mu tenu).
func (v *Vault) retentionCopy() map[logstore.Kind]time.Duration {
	out := make(map[logstore.Kind]time.Duration, len(v.retention))
	for k, d := range v.retention {
		out[k] = d
	}
	return out
}

// SetRetention règle la durée de conservation d'un type de logs, pour tous les stores du volume, ouverts ou à venir ; la purge
// horaire l'applique. Une durée nulle ou négative est ignorée. Réduire une durée supprime les lignes les plus anciennes.
func (v *Vault) SetRetention(kind logstore.Kind, d time.Duration) {
	if d <= 0 {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.retention == nil {
		v.retention = map[logstore.Kind]time.Duration{}
	}
	v.retention[kind] = d
	for _, e := range v.stores {
		e.store.SetRetention(kind, d)
	}
}

// Retention rend la durée réglée d'un type de logs (0 : celle par défaut du moteur).
func (v *Vault) Retention(kind logstore.Kind) time.Duration {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.retention[kind]
}
