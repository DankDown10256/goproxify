// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package behavior

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/vincamok/goproxify/internal/edge/tlsfp"
)

// Observation suit une requête à travers la passerelle pour qu'elle ne soit versée qu'une fois au magasin : le WAF y note le score
// de ses règles et, s'il enregistre lui-même l'événement (route avec analyse comportementale), le dit ; Ephor verse sinon la
// requête une fois la réponse connue.
type Observation struct {
	waf      atomic.Int32
	recorded atomic.Bool
	blocked  atomic.Bool
	account  atomic.Pointer[string] // empreinte du compte visé par une connexion (ADR 0020, étape 4.a), jamais l'identifiant
	mu       sync.Mutex
	hits     []WAFHit
}

// WAFHit est une règle du WAF déclenchée par la requête : de quoi, plus tard, dire quelles règles se déclenchent sur des clients
// ordinaires (apprentissage de la surface, ADR 0016).
type WAFHit struct {
	RuleID   int
	Category string
	Message  string
	Target   string
}

// maxWAFHits borne ce qu'une requête retient : une charge qui déclenche tout le jeu de règles n'allonge pas l'observation.
const maxWAFHits = 16

// NoteWAFHits consigne les règles déclenchées par la requête ou sa réponse.
func (o *Observation) NoteWAFHits(hits ...WAFHit) {
	if o == nil || len(hits) == 0 {
		return
	}
	o.mu.Lock()
	for _, h := range hits {
		if len(o.hits) < maxWAFHits {
			o.hits = append(o.hits, h)
		}
	}
	o.mu.Unlock()
}

// WAFHits rend les règles consignées.
func (o *Observation) WAFHits() []WAFHit {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]WAFHit(nil), o.hits...)
}

// NoteWAFBlocked consigne que le WAF a refusé la requête.
func (o *Observation) NoteWAFBlocked() {
	if o != nil {
		o.blocked.Store(true)
	}
}

// WAFBlocked dit si le WAF a refusé la requête.
func (o *Observation) WAFBlocked() bool { return o != nil && o.blocked.Load() }

type obsKey struct{}

// WithObservation attache une observation neuve au contexte de la requête.
func WithObservation(ctx context.Context) (context.Context, *Observation) {
	o := &Observation{}
	return context.WithValue(ctx, obsKey{}, o), o
}

// ObservationFrom retourne l'observation de la requête, nil si elle n'en a pas (tests, appels hors passerelle).
func ObservationFrom(ctx context.Context) *Observation {
	o, _ := ctx.Value(obsKey{}).(*Observation)
	return o
}

// NoteWAFScore consigne le score des règles WAF déclenchées par la requête.
func (o *Observation) NoteWAFScore(score int) {
	if o != nil && score > 0 {
		o.waf.Store(int32(score))
	}
}

// WAFScore retourne le score noté par le WAF.
func (o *Observation) WAFScore() int {
	if o == nil {
		return 0
	}
	return int(o.waf.Load())
}

// MarkRecorded indique que l'événement de la requête est déjà dans le magasin.
func (o *Observation) MarkRecorded() {
	if o != nil {
		o.recorded.Store(true)
	}
}

// Recorded indique si l'événement de la requête est déjà dans le magasin.
func (o *Observation) Recorded() bool { return o != nil && o.recorded.Load() }

var assetExts = map[string]bool{
	".css": true, ".js": true, ".mjs": true, ".map": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".webp": true,
	".avif": true, ".svg": true, ".ico": true, ".woff": true, ".woff2": true, ".ttf": true, ".otf": true,
}

// IsAssetPath indique un chemin d'image, de feuille de style, de script ou de police.
func IsAssetPath(p string) bool {
	if i := strings.LastIndexByte(p, '.'); i >= 0 && i > strings.LastIndexByte(p, '/') {
		return assetExts[strings.ToLower(p[i:])]
	}
	return false
}

// EventFromRequest décrit une requête terminée pour le magasin. route est l'hôte de la route qui l'a servie ("" s'il n'y en a
// pas : la requête ne nourrit alors pas les références par route).
func EventFromRequest(r *http.Request, status, wafScore int, route string) Event {
	ev := Event{
		WafScore: wafScore,
		Status:   status,
		Method:   r.Method,
		Path:     r.URL.Path,
		UA:       r.UserAgent(),
		Route:    route,
	}
	if fp := tlsfp.FromContext(r.Context()); fp != nil {
		ev.TLS = fp.JA4
	}
	switch r.Header.Get("Sec-Fetch-Dest") {
	case "image", "style", "script", "font":
		ev.Asset = true
	}
	if !ev.Asset {
		ev.Asset = IsAssetPath(ev.Path)
	}
	ev.Page = !ev.Asset && r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html")
	return ev
}

// NoteAccount consigne l'empreinte (HMAC) du compte visé par la requête : l'identifiant lui-même n'est pas conservé.
func (o *Observation) NoteAccount(fingerprint string) {
	if o != nil && fingerprint != "" {
		o.account.Store(&fingerprint)
	}
}

// Account retourne l'empreinte du compte visé, vide si la requête n'en vise pas.
func (o *Observation) Account() string {
	if o == nil {
		return ""
	}
	if p := o.account.Load(); p != nil {
		return *p
	}
	return ""
}
