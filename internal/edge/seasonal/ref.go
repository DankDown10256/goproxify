// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package seasonal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"time"
)

// Métriques apprises par créneau et par pas.
const (
	mReq = iota // requêtes par seconde
	mIPs        // IP distinctes (comptage approché)
	mErr        // part de 4xx et 5xx
	mTop        // part du chemin le plus demandé (par compartiment de hachage)
	metricCount
)

const (
	slotCount     = 168 // jour de la semaine × heure, UTC
	fallbackCount = 48  // semaine ou week-end × heure
	stepCount     = 2   // 10 secondes et 1 minute
)

// Une moyenne glissante exponentielle sur plusieurs semaines absorbe la dérive lente d'un site qui grossit.
var emaWindow = [stepCount]uint32{1440, 240}

// Marge absolue ajoutée au plafond de la dérive : sans elle, un créneau toujours calme n'apprendrait jamais sa première requête.
var driftSlack = [metricCount]float64{0.1, 2, 0.05, 0.05}

type stat struct {
	Mean, Var float32
	N         uint32
}

func (s stat) sd() float64 { return math.Sqrt(float64(s.Var)) }

// add verse une mesure. Une fois la moyenne crue, la mesure est plafonnée : un attaquant qui monte lentement n'enseigne pas un
// « normal » trop haut d'un coup.
func (s *stat) add(x float64, window, warmAt uint32, slack float64) {
	if s.N >= warmAt {
		if limit := float64(s.Mean)*1.25 + 3*s.sd() + slack; x > limit {
			x = limit
		}
	}
	if s.N < math.MaxUint32 {
		s.N++
	}
	n := s.N
	if n > window {
		n = window
	}
	alpha := 1 / float64(n)
	delta := x - float64(s.Mean)
	s.Mean += float32(alpha * delta)
	s.Var = float32((1 - alpha) * (float64(s.Var) + alpha*delta*delta))
}

type slotRef struct {
	stats [stepCount][metricCount]stat
}

func (r *slotRef) warm(step, min int) bool { return r.stats[step][mReq].N >= uint32(min) }

type refTable struct {
	slots [slotCount]slotRef
	fb    [fallbackCount]slotRef
}

// slotsOf donne les deux créneaux d'un instant : le fin (168) et le grossier (48).
func slotsOf(t time.Time) (int, int) {
	t = t.UTC()
	d := int(t.Weekday()+6) % 7 // lundi = 0
	h := t.Hour()
	weekend := 0
	if d >= 5 {
		weekend = 1
	}
	return d*24 + h, weekend*24 + h
}

// pick retourne la référence à croire : le créneau fin quand il a assez d'échantillons, sinon le grossier, sinon rien (froid).
func (t *refTable) pick(s168, s48, min int) *slotRef {
	if t.slots[s168].warm(0, min) {
		return &t.slots[s168]
	}
	if t.fb[s48].warm(0, min) {
		return &t.fb[s48]
	}
	return nil
}

func (t *refTable) learn(s168, s48, step int, o obs, p Params) {
	vals := [metricCount]float64{o.rps, o.ips, o.errShare, o.topShare}
	warmAt := uint32(p.MinSamples)
	if step == 1 {
		warmAt /= SlowBuckets
	}
	for _, r := range []*slotRef{&t.slots[s168], &t.fb[s48]} {
		for m, v := range vals {
			r.stats[step][m].add(v, emaWindow[step], warmAt, driftSlack[m])
		}
	}
}

func (t *refTable) empty() bool {
	for i := range t.slots {
		if t.slots[i].stats[0][mReq].N != 0 {
			return false
		}
	}
	for i := range t.fb {
		if t.fb[i].stats[0][mReq].N != 0 {
			return false
		}
	}
	return true
}

const stateVersion = 1

// RefState est la référence apprise d'une route, telle qu'elle est conservée sur disque (chiffrée par le cache de la passerelle).
type RefState struct {
	At   time.Time `json:"at"`
	Data []byte    `json:"data"`
}

// encode ne garde que les créneaux qui ont vu des échantillons : une route récente tient en quelques centaines d'octets.
func (t *refTable) encode() []byte {
	var buf bytes.Buffer
	buf.WriteByte(stateVersion)
	put := func(idx uint16, r *slotRef) {
		if r.stats[0][mReq].N == 0 {
			return
		}
		_ = binary.Write(&buf, binary.LittleEndian, idx)
		_ = binary.Write(&buf, binary.LittleEndian, r.stats)
	}
	for i := range t.slots {
		put(uint16(i), &t.slots[i])
	}
	for i := range t.fb {
		put(uint16(slotCount+i), &t.fb[i])
	}
	return buf.Bytes()
}

var errBadState = errors.New("seasonal: état illisible")

func (t *refTable) decode(data []byte) error {
	if len(data) == 0 || data[0] != stateVersion {
		return errBadState
	}
	r := bytes.NewReader(data[1:])
	for r.Len() > 0 {
		var idx uint16
		var st [stepCount][metricCount]stat
		if err := binary.Read(r, binary.LittleEndian, &idx); err != nil {
			return errBadState
		}
		if err := binary.Read(r, binary.LittleEndian, &st); err != nil {
			return errBadState
		}
		switch {
		case int(idx) < slotCount:
			t.slots[idx].stats = st
		case int(idx) < slotCount+fallbackCount:
			t.fb[int(idx)-slotCount].stats = st
		default:
			return errBadState
		}
	}
	return nil
}

// Export copie les références apprises. Une route sans échantillon est omise.
func (t *Tracker) Export() map[string]RefState {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[string]RefState{}
	for name, rs := range *t.routes.Load() {
		if rs.ref.empty() {
			continue
		}
		out[name] = RefState{At: now, Data: rs.ref.encode()}
	}
	return out
}

// Import réinjecte des références relues du disque. Une copie illisible ou trop ancienne est ignorée, et la référence d'une
// route déjà apprise depuis le démarrage n'est jamais écrasée.
func (t *Tracker) Import(in map[string]RefState) {
	now := t.now()
	for name, st := range in {
		if now.Sub(st.At) > idleForget {
			continue
		}
		var ref refTable
		if ref.decode(st.Data) != nil {
			continue
		}
		rs := t.route(name)
		t.mu.Lock()
		if rs.ref.empty() {
			rs.ref = ref
			rs.lastSeen = st.At
		}
		t.mu.Unlock()
	}
}
