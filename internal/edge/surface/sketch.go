// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package surface

import (
	"math"
	"math/bits"
)

// Sketch compte des IP distinctes sans en garder aucune (HyperLogLog). Les registres ne permettent pas de retrouver une
// adresse, et l'union de deux sketchs ne compte pas deux fois une IP vue par deux passerelles.
type Sketch struct {
	Regs []byte `json:"r"`
}

const (
	routePrecision    = 10 // 1 Kio par route
	templatePrecision = 6  // 64 octets par gabarit
)

func newSketch(precision uint) *Sketch { return &Sketch{Regs: make([]byte, 1<<precision)} }

// hashIP : FNV-1a de l'IP, brassé pour répartir les bits (le sketch lit les bits hauts et compte les zéros bas).
func hashIP(s string) uint64 {
	h := uint64(14695981039346656037)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	h ^= h >> 30
	h *= 0xbf58476d1ce4e5b9
	h ^= h >> 27
	h *= 0x94d049bb133111eb
	h ^= h >> 31
	return h
}

func (s *Sketch) add(h uint64) {
	p := uint(bits.TrailingZeros(uint(len(s.Regs))))
	idx := h >> (64 - p)
	rank := uint8(bits.LeadingZeros64(h<<p|1<<(p-1))) + 1
	if rank > s.Regs[idx] {
		s.Regs[idx] = rank
	}
}

// merge fait l'union avec o. Deux sketchs de précisions différentes ne se mélangent pas : o est alors ignoré.
func (s *Sketch) merge(o *Sketch) {
	if o == nil || len(o.Regs) != len(s.Regs) {
		return
	}
	for i, r := range o.Regs {
		if r > s.Regs[i] {
			s.Regs[i] = r
		}
	}
}

// Estimate rend le nombre estimé d'IP distinctes.
func (s *Sketch) Estimate() int {
	if s == nil || len(s.Regs) == 0 {
		return 0
	}
	m := float64(len(s.Regs))
	var sum float64
	zeros := 0
	for _, r := range s.Regs {
		sum += math.Ldexp(1, -int(r))
		if r == 0 {
			zeros++
		}
	}
	var alpha float64
	switch len(s.Regs) {
	case 16:
		alpha = 0.673
	case 32:
		alpha = 0.697
	case 64:
		alpha = 0.709
	default:
		alpha = 0.7213 / (1 + 1.079/m)
	}
	est := alpha * m * m / sum
	if est <= 2.5*m && zeros > 0 {
		est = m * math.Log(m/float64(zeros))
	}
	return int(est + 0.5)
}

func (s *Sketch) clone() *Sketch {
	if s == nil {
		return nil
	}
	return &Sketch{Regs: append([]byte(nil), s.Regs...)}
}
