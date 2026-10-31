// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"encoding/json"
	"strings"
	"unicode"

	"github.com/vincamok/goproxify/internal/edge/router"
)

const (
	maxBanSignals      = 16
	maxBanSignalName   = 40
	maxBanSignalValue  = 200
	maxBanSignalPoints = 1e6
	maxUserAgent       = 300
)

// EncodeBanSignals sérialise pour la colonne `signals` les signaux reçus d'une passerelle. Ils viennent du réseau (et, pour
// la valeur, de l'attaquant) : nombre, longueurs et points sont bornés, une entrée sans nom est écartée. "" s'il n'en
// reste aucune.
func EncodeBanSignals(in []router.BanSignal) string {
	out := make([]router.BanSignal, 0, len(in))
	for _, s := range in {
		name := clipUTF8(strings.TrimSpace(s.Name), maxBanSignalName)
		if name == "" || len(out) == maxBanSignals {
			continue
		}
		pts := s.Points
		if pts != pts || pts < 0 { // NaN ou négatif
			pts = 0
		}
		if pts > maxBanSignalPoints {
			pts = maxBanSignalPoints
		}
		out = append(out, router.BanSignal{Name: name, Points: pts, Value: clipUTF8(s.Value, maxBanSignalValue)})
	}
	if len(out) == 0 {
		return ""
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return ""
	}
	return string(raw)
}

// DecodeBanSignals relit la colonne `signals` ; nil si elle est vide ou illisible.
func DecodeBanSignals(s string) []router.BanSignal {
	if s == "" {
		return nil
	}
	var out []router.BanSignal
	if json.Unmarshal([]byte(s), &out) != nil {
		return nil
	}
	return out
}

// ClipUserAgent borne le User-Agent reçu d'une passerelle (il vient de l'attaquant) et en retire les caractères de contrôle.
func ClipUserAgent(ua string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, clipUTF8(strings.TrimSpace(ua), maxUserAgent))
}

func clipUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
