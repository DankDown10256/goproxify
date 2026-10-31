// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package fingerprint retient les applications que les réponses des backends annoncent (ADR 0017, étape 2) : en-têtes Server,
// X-Powered-By, X-Generator et <meta name="generator"> d'une page HTML. La lecture est passive (aucune requête de plus) et se fait
// avant que hide_server ne retire quoi que ce soit : la passerelle voit ce que le client ne voit plus.
//
// L'état est borné et se copie chiffré en local ; les membres d'un groupe HA se le passent sans l'Admin.
package fingerprint

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/appinv"
	"github.com/vincamok/goproxify/internal/edge/router"
)

const (
	// TTL : une observation non revue depuis ce délai sort de l'inventaire (le backend a changé ou n'est plus servi).
	TTL = 30 * 24 * time.Hour
	// maxPerRoute borne le nombre d'observations d'un proxy.
	maxPerRoute = 64
	// touchEvery : une réponse identique ne met l'observation à jour qu'à ce rythme.
	touchEvery = time.Minute
	// sampleEvery : une page HTML d'un backend n'est lue qu'à ce rythme tant qu'aucun générateur n'y a été trouvé ; sampleFoundEvery une fois trouvé.
	sampleEvery      = 10 * time.Minute
	sampleFoundEvery = 6 * time.Hour
	// maxSniff : la part du corps d'une page que l'on garde pour y chercher le générateur.
	maxSniff = 64 << 10
)

// Obs est une application reconnue derrière un backend d'un proxy.
type Obs struct {
	Backend  string    `json:"backend"`
	Product  string    `json:"product"`
	CPE      string    `json:"cpe,omitempty"`
	Version  string    `json:"version,omitempty"`
	Partial  bool      `json:"partial,omitempty"`
	Source   string    `json:"source"`
	Evidence string    `json:"evidence"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
}

// Finding convertit l'observation en entrée d'inventaire.
func (o Obs) Finding() appinv.Finding {
	return appinv.Finding{Product: o.Product, CPE: o.CPE, Version: o.Version, Partial: o.Partial, Source: o.Source, Evidence: o.Evidence}
}

func (o Obs) key() string {
	if o.Product == "" {
		return o.Backend + "||" + o.Source + "|" + o.Evidence
	}
	return o.Backend + "|" + o.Product + "|" + o.Source
}

// Payload est ce qu'un membre d'un groupe HA envoie aux autres, et ce que la passerelle copie chiffré en local.
type Payload struct {
	Routes map[string][]Obs `json:"routes"`
}

// State est la copie locale.
type State = Payload

type sampleState struct {
	next  time.Time
	found bool
}

// Store est le magasin des empreintes d'une passerelle.
type Store struct {
	now func() time.Time

	mu     sync.Mutex
	routes map[string]map[string]*Obs // proxy → clé (backend|produit|source) → observation

	sigMu   sync.Mutex
	sigs    map[string]sigState // backend d'un proxy → dernière signature d'en-têtes vue
	samples map[string]sampleState
}

type sigState struct {
	sig  string
	seen time.Time
}

// NewStore crée un magasin vide.
func NewStore() *Store {
	return &Store{now: time.Now, routes: map[string]map[string]*Obs{}, sigs: map[string]sigState{}, samples: map[string]sampleState{}}
}

// put enregistre une observation. Pour un même backend, produit et source, la plus récente remplace l'autre : une mise à jour du
// backend (nginx 1.24 puis 1.25) ne laisse pas l'ancienne version dans l'inventaire.
func (s *Store) put(route string, o Obs) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.routes[route]
	if m == nil {
		m = map[string]*Obs{}
		s.routes[route] = m
	}
	k := o.key()
	if cur, ok := m[k]; ok {
		if !o.First.IsZero() && (cur.First.IsZero() || o.First.Before(cur.First)) {
			cur.First = o.First
		}
		if o.Last.After(cur.Last) {
			first := cur.First
			*cur = o
			cur.First = first
		}
		return
	}
	cp := o
	m[k] = &cp
	if len(m) > maxPerRoute {
		var oldestKey string
		var oldest time.Time
		for key, v := range m {
			if oldestKey == "" || v.Last.Before(oldest) {
				oldestKey, oldest = key, v.Last
			}
		}
		delete(m, oldestKey)
	}
}

func (s *Store) record(route, backend string, fs []appinv.Finding) {
	now := s.now().UTC()
	for _, f := range fs {
		s.put(route, Obs{Backend: backend, Product: f.Product, CPE: f.CPE, Version: f.Version, Partial: f.Partial, Source: f.Source, Evidence: f.Evidence, First: now, Last: now})
	}
}

// ObserveResponse lit une réponse du backend. Il est appelé pour chaque réponse : le chemin courant ne coûte que la comparaison de la
// signature des en-têtes qui comptent. Le corps d'une page HTML n'est lu que de temps en temps, sans changer ce qui est envoyé au client.
func (s *Store) ObserveResponse(rt *router.Route, backend string, resp *http.Response) {
	if s == nil || rt == nil || resp == nil {
		return
	}
	id := rt.ID
	key := id + "|" + backend
	now := s.now()

	if sig := appinv.HeaderSignature(resp.Header); sig != "" {
		s.sigMu.Lock()
		st, ok := s.sigs[key]
		fresh := ok && st.sig == sig && now.Sub(st.seen) < touchEvery
		if !fresh {
			s.sigs[key] = sigState{sig: sig, seen: now}
		}
		s.sigMu.Unlock()
		if !fresh {
			s.record(id, backend, appinv.FromHeaders(resp.Header))
		}
	}

	if !sniffable(resp) || !s.sampleDue(key, now) {
		return
	}
	resp.Body = &sniffBody{rc: resp.Body, gz: strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip"), done: func(doc []byte) {
		found := false
		if fs := appinv.FromHTML(doc); len(fs) > 0 {
			found = true
			s.record(id, backend, fs)
		}
		s.sigMu.Lock()
		st := s.samples[key]
		st.found = st.found || found
		s.samples[key] = st
		s.sigMu.Unlock()
	}}
}

// sampleDue dit qu'une page de ce backend peut être lue maintenant, et réserve le prochain tour.
func (s *Store) sampleDue(key string, now time.Time) bool {
	s.sigMu.Lock()
	defer s.sigMu.Unlock()
	st := s.samples[key]
	if now.Before(st.next) {
		return false
	}
	every := sampleEvery
	if st.found {
		every = sampleFoundEvery
	}
	st.next = now.Add(every)
	s.samples[key] = st
	return true
}

// sniffable : une page HTML complète, lue telle qu'elle est ou en gzip. Les autres codages et les réponses partielles sont laissés.
func sniffable(resp *http.Response) bool {
	if resp.StatusCode != http.StatusOK || resp.Body == nil || resp.Body == http.NoBody {
		return false
	}
	if resp.Request != nil && resp.Request.Method == http.MethodHead {
		return false
	}
	if !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return false
	}
	enc := strings.ToLower(resp.Header.Get("Content-Encoding"))
	return enc == "" || enc == "identity" || enc == "gzip"
}

// sniffBody copie le début du corps pendant que le client le lit, puis le fait analyser une fois (fin, fermeture ou taille atteinte).
type sniffBody struct {
	rc   io.ReadCloser
	gz   bool
	buf  bytes.Buffer
	once sync.Once
	done func([]byte)
}

func (b *sniffBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if room := maxSniff - b.buf.Len(); room > 0 && n > 0 {
		if n < room {
			room = n
		}
		b.buf.Write(p[:room])
	}
	if err != nil || b.buf.Len() >= maxSniff {
		b.finish()
	}
	return n, err
}

func (b *sniffBody) Close() error {
	b.finish()
	return b.rc.Close()
}

func (b *sniffBody) finish() {
	b.once.Do(func() {
		doc := b.buf.Bytes()
		if b.gz {
			// Le début d'un flux gzip se décompresse même coupé : l'erreur de fin de flux est attendue.
			zr, err := gzip.NewReader(bytes.NewReader(doc))
			if err != nil {
				b.done(nil)
				return
			}
			out, _ := io.ReadAll(io.LimitReader(zr, maxSniff))
			doc = out
		}
		b.done(doc)
	})
}

// Entries rend les observations d'un proxy, les plus récentes d'abord, sans celles qui ont expiré.
func (s *Store) Entries(route string) []Obs {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := s.now().Add(-TTL)
	var out []Obs
	for _, o := range s.routes[route] {
		if o.Last.After(cut) {
			out = append(out, *o)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Backend != out[j].Backend {
			return out[i].Backend < out[j].Backend
		}
		return out[i].Product < out[j].Product
	})
	return out
}

// Forget retire les proxies que keep refuse (proxy supprimé) ainsi que les observations expirées.
func (s *Store) Forget(keep func(routeID string) bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cut := s.now().Add(-TTL)
	for id, m := range s.routes {
		if !keep(id) {
			delete(s.routes, id)
			continue
		}
		for k, o := range m {
			if !o.Last.After(cut) {
				delete(m, k)
			}
		}
		if len(m) == 0 {
			delete(s.routes, id)
		}
	}
}

// Snapshot rend la copie locale à écrire sur disque.
func (s *Store) Snapshot() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := State{Routes: map[string][]Obs{}}
	for id, m := range s.routes {
		for _, o := range m {
			st.Routes[id] = append(st.Routes[id], *o)
		}
	}
	return st
}

// Restore recharge la copie locale (au démarrage), avant toute observation.
func (s *Store) Restore(st State) {
	for id, list := range st.Routes {
		for _, o := range list {
			s.put(id, o)
		}
	}
}

// Export rend ce qu'un pair du groupe vient chercher.
func (s *Store) Export() Payload { return s.Snapshot() }

// ApplyPeer fusionne les observations d'un pair : la plus récente de chaque (backend, produit, source) l'emporte, ce qui rend la fusion
// idempotente et sans ordre (ADR 0014).
func (s *Store) ApplyPeer(_ string, p Payload) {
	s.Restore(p)
}
