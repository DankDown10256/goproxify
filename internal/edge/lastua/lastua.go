// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package lastua retient le dernier User-Agent vu pour chaque IP, afin qu'un ban dise quel client l'a provoqué
// quel que soit le moteur qui le pose (Ephor, WAF, plugin, règle).
package lastua

import (
	"sync"
	"time"
	"unicode"
)

const (
	shards      = 16
	perShardCap = 2048
	ttl         = time.Hour
	maxLen      = 300
)

type entry struct {
	ua   string
	seen time.Time
}

type shard struct {
	mu sync.Mutex
	m  map[string]entry
}

// Tracker est borné : au-delà de perShardCap IP par segment, les entrées périmées puis la plus ancienne sont écartées.
type Tracker struct {
	s [shards]shard
}

func New() *Tracker {
	t := &Tracker{}
	for i := range t.s {
		t.s[i].m = make(map[string]entry, 64)
	}
	return t
}

func (t *Tracker) shard(ip string) *shard {
	var h uint32 = 2166136261
	for i := 0; i < len(ip); i++ {
		h = (h ^ uint32(ip[i])) * 16777619
	}
	return &t.s[h%shards]
}

// Note enregistre le User-Agent d'une requête. Un User-Agent vide ne remplace rien.
func (t *Tracker) Note(ip, ua string) {
	if t == nil || ip == "" || ua == "" {
		return
	}
	sh := t.shard(ip)
	now := time.Now()
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if e, ok := sh.m[ip]; ok && e.ua == ua && now.Sub(e.seen) < time.Minute {
		return
	}
	if _, ok := sh.m[ip]; !ok && len(sh.m) >= perShardCap {
		sh.evict(now)
	}
	sh.m[ip] = entry{ua: Clip(ua), seen: now}
}

// evict retire les entrées périmées ; si le segment reste plein, la plus ancienne.
func (sh *shard) evict(now time.Time) {
	var oldest string
	var oldestAt time.Time
	for k, e := range sh.m {
		if now.Sub(e.seen) > ttl {
			delete(sh.m, k)
			continue
		}
		if oldest == "" || e.seen.Before(oldestAt) {
			oldest, oldestAt = k, e.seen
		}
	}
	if len(sh.m) >= perShardCap && oldest != "" {
		delete(sh.m, oldest)
	}
}

// Get retourne le dernier User-Agent vu pour l'IP, "" si inconnu ou trop ancien.
func (t *Tracker) Get(ip string) string {
	if t == nil {
		return ""
	}
	sh := t.shard(ip)
	sh.mu.Lock()
	defer sh.mu.Unlock()
	e, ok := sh.m[ip]
	if !ok || time.Since(e.seen) > ttl {
		return ""
	}
	return e.ua
}

// Clip borne un User-Agent et en retire les caractères de contrôle : il vient de la requête, donc de l'attaquant.
func Clip(ua string) string {
	r := make([]rune, 0, len(ua))
	for _, c := range ua {
		if len(r) == maxLen {
			r = append(r, '…')
			break
		}
		if unicode.IsControl(c) {
			c = '?'
		}
		r = append(r, c)
	}
	return string(r)
}
