// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/proxy"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// Configuration poussée par l'Admin, partagée entre les passerelles d'un groupe HA (ADR 0014, étape 4). L'Admin
// publie chaque document sur chaque passerelle, une par une : celle qui était absente (redémarrage, panne, Admin
// injoignable à ce moment) garde l'ancienne version. Chaque membre retient donc le dernier document reçu de l'Admin
// pour chaque type, avec l'instant de réception, et le propose à ses pairs ; un pair dont la copie est plus ancienne
// le réapplique par le chemin qu'emprunte une poussée de l'Admin. Le journal est une copie locale chiffrée : un membre
// qui redémarre pendant la coupure de l'Admin retrouve la même version qu'avant et la même date.
//
// Seuls les documents identiques pour tout le groupe y entrent. Les réglages propres à une passerelle (réglages
// d'exploitation, délais du serveur, pairs, jeton Admin) n'y sont pas, ni les bans (déjà répliqués) ni le portail
// (déjà répliqué).

const (
	pushedReplicaPath     = "/internal/v1/replica/pushed"
	pushedReplicaMaxBytes = 128 << 20
	pushedReplicaLabel    = "gpx-pushed-replica|"
)

func pushedJournalPath() string {
	if p := os.Getenv("GPX_PUSHED_JOURNAL_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/pushed-journal.gpx"
}

// replicablePushes : types de messages Admin→passerelle dont le contenu est le même pour tout le groupe.
var replicablePushes = map[string]bool{
	edgews.TypePushCert:            true, // une entrée par nom de certificat
	edgews.TypePushPlugins:         true,
	edgews.TypePushSnippets:        true,
	edgews.TypePushAuthProviders:   true,
	edgews.TypePushIPProfiles:      true,
	edgews.TypePushCrowdSecConfig:  true,
	edgews.TypePushThreatConfig:    true,
	edgews.TypePushWAFConfig:       true,
	edgews.TypePushErrorPages:      true,
	edgews.TypePushPortalTemplates: true,
	edgews.TypePushAutoRules:       true,
	edgews.TypePushDelegations:     true,
	edgews.TypePushGroupCard:       true,
	edgews.TypePushDisabledRoutes:  true,
}

type pushedEntry struct {
	Key     string          `json:"key"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
	At      time.Time       `json:"at"`
	Hash    string          `json:"hash"`
}

type pushedDoc struct {
	Entries []pushedEntry `json:"entries"`
}

// pushedJournal retient le dernier document reçu pour chaque clé (type, ou type et nom pour un certificat).
type pushedJournal struct {
	mu      sync.Mutex
	entries map[string]pushedEntry
}

func pushedKey(typ string, payload json.RawMessage) string {
	if typ != edgews.TypePushCert {
		return typ
	}
	var c struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(payload, &c)
	return typ + "|" + c.Name
}

func pushedHash(payload json.RawMessage) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// record retient le document s'il diffère de celui qu'on a pour cette clé et que at ne le précède pas. Rend vrai quand
// le journal a changé.
func (j *pushedJournal) record(e pushedEntry) bool { return j.put(e, false) }

// put : replace=true retient le document même s'il est plus ancien que celui qu'on a, quand un autre ordre que celui des
// dates décide (la version d'une fiche de groupe).
func (j *pushedJournal) put(e pushedEntry, replace bool) bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.entries == nil {
		j.entries = map[string]pushedEntry{}
	}
	cur, ok := j.entries[e.Key]
	if ok && (cur.Hash == e.Hash || (!replace && e.At.Before(cur.At))) {
		return false
	}
	j.entries[e.Key] = e
	return true
}

func (j *pushedJournal) get(key string) (pushedEntry, bool) {
	j.mu.Lock()
	defer j.mu.Unlock()
	e, ok := j.entries[key]
	return e, ok
}

func (j *pushedJournal) doc() pushedDoc {
	j.mu.Lock()
	defer j.mu.Unlock()
	var d pushedDoc
	for _, e := range j.entries {
		d.Entries = append(d.Entries, e)
	}
	sort.Slice(d.Entries, func(a, b int) bool { return d.Entries[a].Key < d.Entries[b].Key })
	return d
}

// digest résume le contenu retenu : deux membres au même condensé n'ont rien à s'échanger, même si leurs dates de
// réception diffèrent de quelques secondes.
func (d pushedDoc) digest() string {
	h := sha256.New()
	for _, e := range d.Entries {
		h.Write([]byte(e.Key + "|" + e.Hash + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// handleWSAdminMessage applique un message de l'Admin puis, s'il a réussi, le retient pour les pairs du groupe.
func (s *Server) handleWSAdminMessage(connID string, msg edgews.Message) error {
	if err := s.applyAdminMessage(connID, msg); err != nil {
		return err
	}
	s.journalAdminMessage(msg)
	return nil
}

// journalAdminMessage retient les documents réplicables d'un message de l'Admin. full_sync porte plusieurs listes :
// chacune est retenue comme la poussée de son type.
func (s *Server) journalAdminMessage(msg edgews.Message) {
	now := time.Now().UTC()
	switch {
	case replicablePushes[msg.Type]:
		s.journalPushed(msg.Type, msg.Payload, now)
	case msg.Type == edgews.TypeFullSync:
		var fs struct {
			Snippets  json.RawMessage `json:"snippets"`
			Providers json.RawMessage `json:"providers"`
			Profiles  json.RawMessage `json:"ip_profiles"`
		}
		if json.Unmarshal(msg.Payload, &fs) != nil {
			return
		}
		for typ, raw := range map[string]json.RawMessage{
			edgews.TypePushSnippets:      fs.Snippets,
			edgews.TypePushAuthProviders: fs.Providers,
			edgews.TypePushIPProfiles:    fs.Profiles,
		} {
			if len(raw) > 0 && string(raw) != "null" {
				s.journalPushed(typ, raw, now)
			}
		}
	}
}

func (s *Server) journalPushed(typ string, payload json.RawMessage, at time.Time) {
	e := pushedEntry{Key: pushedKey(typ, payload), Type: typ, Payload: append(json.RawMessage(nil), payload...), At: at, Hash: pushedHash(payload)}
	if s.adminDocs.record(e) {
		s.savePushedJournal()
	}
}

func (s *Server) savePushedJournal() {
	if s.cache == nil {
		return
	}
	if err := s.cache.SaveFile(pushedJournalPath(), s.adminDocs.doc()); err != nil {
		s.log.Warn("pushed: persistance du journal échouée", "err", err)
	}
}

// loadPushedJournalFromDisk rend à la passerelle la mémoire de ce que l'Admin lui a poussé, sans l'Admin. Elle ne
// réapplique rien : les copies locales de chaque document sont déjà relues par ailleurs.
func (s *Server) loadPushedJournalFromDisk() {
	if s.cache == nil {
		return
	}
	var d pushedDoc
	ok, err := s.cache.LoadFile(pushedJournalPath(), &d)
	if err != nil {
		s.log.Warn("pushed: journal local illisible — il se reconstituera", "err", err)
		return
	}
	if !ok {
		return
	}
	for _, e := range d.Entries {
		s.adminDocs.record(e)
		// Les routes désactivées n'ont pas de copie à part : le journal est leur copie locale.
		if e.Type == edgews.TypePushDisabledRoutes {
			if err := s.applyDisabledRoutes(e.Payload); err != nil {
				s.log.Warn("pushed: routes désactivées illisibles", "err", err)
			}
		}
	}
	s.log.Info("pushed: journal chargé depuis le disque", "documents", len(d.Entries))
}

// GET /internal/v1/replica/pushed : les documents poussés par l'Admin, chiffrés par la clé du groupe. 304 si le
// demandeur a déjà les mêmes contenus.
func (s *Server) handlePushedReplicaExport(w http.ResponseWriter, r *http.Request) {
	if s.portal == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	_, key, _, ok := s.portal.HAGroupInfo()
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	doc := s.adminDocs.doc()
	if r.Header.Get("If-None-Match") == `"`+doc.digest()+`"` {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	sealed, err := sealGroupJSON(doc, key, pushedReplicaLabel)
	if err != nil {
		http.Error(w, "réplication indisponible", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(sealed)
}

// syncPushedFromPeer tire les documents de l'Admin retenus par un pair et applique ceux qui sont plus récents.
func (s *Server) syncPushedFromPeer(ctx context.Context, client *http.Client, p proxy.PeerInfo) {
	_, key, ok := s.haAgentPeers()
	if !ok {
		return
	}
	_, _, members, _ := s.portal.HAGroupInfo()
	if !isPortalMember(p.Name, members) {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Endpoint+pushedReplicaPath, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	req.Header.Set("If-None-Match", `"`+s.adminDocs.doc().digest()+`"`)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, pushedReplicaMaxBytes))
	if err != nil {
		return
	}
	var doc pushedDoc
	if err := openGroupJSON(data, key, pushedReplicaLabel, &doc); err != nil {
		s.log.Warn("pushed: réplication — document illisible (clé de groupe différente ?)", "pair", p.Name, "err", err)
		return
	}
	s.mergePushedReplica(doc, p.Name)
}

// mergePushedReplica applique les documents d'un pair plus récents que les nôtres. Rend le nombre appliqué.
func (s *Server) mergePushedReplica(doc pushedDoc, from string) int {
	applied := 0
	for _, e := range doc.Entries {
		if !replicablePushes[e.Type] || e.Key != pushedKey(e.Type, e.Payload) || e.Hash != pushedHash(e.Payload) {
			continue
		}
		byVersion := e.Type == edgews.TypePushGroupCard // la version de la fiche décide, pas la date de réception
		if cur, ok := s.adminDocs.get(e.Key); ok && (cur.Hash == e.Hash || (!byVersion && !e.At.After(cur.At))) {
			continue
		}
		if byVersion && !s.groupCardNewer(e.Payload) {
			continue
		}
		if err := s.applyAdminMessage("peer:"+from, edgews.Message{Type: e.Type, Payload: e.Payload}); err != nil {
			s.log.Warn("pushed: réplication — application refusée", "type", e.Type, "pair", from, "err", err)
			continue
		}
		if s.adminDocs.put(e, byVersion) {
			s.savePushedJournal()
		}
		applied++
		s.log.Info("pushed: configuration de l'Admin rattrapée auprès d'un pair du groupe HA", "type", e.Type, "pair", from)
	}
	return applied
}
