// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/ipcrypt"
)

// Query filtre une recherche dans la base de logs. Les champs vides ne filtrent pas.
type Query struct {
	// Kinds : types à parcourir ; vide, les deux.
	Kinds                                              []Kind
	Level, Component, Domain, IP, Method, Status, Path string
	TLSJA3, TLSJA4, Search, RequestID                  string
	// Domains restreint à plusieurs domaines à la fois (sélection multiple de Prism) ; se combine avec Domain.
	Domains []string
	// PathPrefix : chemins qui commencent par cette valeur (Path cherche à l'intérieur).
	PathPrefix string
	// IPFrom et IPTo bornent la colonne ip comme texte, [IPFrom, IPTo[ : un sur-ensemble des adresses d'une plage (voir security.TraceIPRange), à raffiner par l'appelant. IPRanges en combine plusieurs (OU).
	IPFrom, IPTo string
	IPRanges     [][2]string
	// AttributableOnly écarte les lignes à IP tronquée (anonymisation, pseudonymisation) : elles regroupent plusieurs clients.
	AttributableOnly bool
	// From et To bornent les dates de requête (inclusives) ; zéro, pas de borne.
	From, To        time.Time
	ExcludeInternal bool
	// After reprend la recherche après les positions d'une page précédente (Page.Next).
	After map[Kind]Position
	Limit int
}

// Position est celle de la dernière ligne rendue d'un type : la page suivante commence juste après (plus ancien).
type Position struct {
	Ts string // largeur fixe, voir tsLayout
	ID int64
}

func (p Position) zero() bool { return p.Ts == "" }

// Page est une page de résultats, du plus récent au plus ancien.
type Page struct {
	Rows []Row
	// Next porte, pour chaque type, la position de la dernière ligne rendue ; à repasser dans Query.After.
	Next    map[Kind]Position
	HasMore bool
	// Partial : le contexte a expiré avant la fin de la période parcourue.
	Partial bool
}

func (q Query) kinds() []Kind {
	if len(q.Kinds) == 0 {
		return []Kind{KindAccess, KindSystem}
	}
	return q.Kinds
}

func statusRange(s string) (lo, hi int, ok bool) {
	s = strings.TrimSpace(strings.ToLower(s))
	if len(s) == 3 && strings.HasSuffix(s, "xx") {
		base, err := strconv.Atoi(string(s[0]) + "00")
		if err != nil {
			return 0, 0, false
		}
		return base, base + 100, true
	}
	if len(s) == 1 && s[0] >= '1' && s[0] <= '5' {
		base := int(s[0]-'0') * 100
		return base, base + 100, true
	}
	return 0, 0, false
}

// internalPrefixes : réseaux privés, boucle locale et lien local, pour exclure l'auto-supervision.
func internalIPExclusionSQL() string {
	prefixes := []string{"10.", "192.168.", "127.", "169.254.", "fe80:", "fc", "fd"}
	for i := 16; i <= 31; i++ {
		prefixes = append(prefixes, fmt.Sprintf("172.%d.", i))
	}
	conds := []string{"ip != '::1'"}
	for _, p := range prefixes {
		conds = append(conds, "ip NOT LIKE '"+p+"%'")
	}
	return "(" + strings.Join(conds, " AND ") + ")"
}

// where construit la clause des filtres. Une recherche par IP retrouve aussi les lignes pseudonymisées par leur
// empreinte, ce que l'Admin ne pouvait pas faire avant.
func (s *Store) where(q Query) (string, []any) {
	var c []string
	var a []any
	eq := func(col, v string) {
		if v != "" {
			c = append(c, col+" = ?")
			a = append(a, v)
		}
	}
	eq("level", q.Level)
	eq("component", q.Component)
	eq("domain", q.Domain)
	eq("method", q.Method)
	eq("request_id", q.RequestID)
	// Les lignes qu'une ancienne version a répliquées d'un pair (origin non vide) ne sont plus lues : elles partent avec leur fichier.
	c = append(c, "origin = ''")
	if q.IP != "" {
		canon := ipcrypt.CanonicalIP(q.IP)
		if s.key != nil {
			c = append(c, "(ip = ? OR (ip_hmac = ? AND ip_hmac != ''))")
			a = append(a, canon, ipcrypt.IPIndex(s.key, canon))
		} else {
			c = append(c, "ip = ?")
			a = append(a, canon)
		}
	}
	if q.Status != "" {
		if lo, hi, ok := statusRange(q.Status); ok {
			c = append(c, "status >= ? AND status < ?")
			a = append(a, lo, hi)
		} else {
			c = append(c, "status = ?")
			a = append(a, q.Status)
		}
	}
	// Le « != '' » redondant prouve à SQLite que le filtre implique le WHERE de l'index partiel.
	if q.TLSJA3 != "" {
		c = append(c, "tls_ja3 = ? AND tls_ja3 != ''")
		a = append(a, q.TLSJA3)
	}
	if q.TLSJA4 != "" {
		c = append(c, "tls_ja4 = ? AND tls_ja4 != ''")
		a = append(a, q.TLSJA4)
	}
	if len(q.Domains) > 0 {
		c = append(c, "domain IN (?"+strings.Repeat(",?", len(q.Domains)-1)+")")
		for _, d := range q.Domains {
			a = append(a, d)
		}
	}
	if q.IPFrom != "" || q.IPTo != "" {
		if q.IPFrom != "" {
			c = append(c, "ip >= ?")
			a = append(a, q.IPFrom)
		}
		if q.IPTo != "" {
			c = append(c, "ip < ?")
			a = append(a, q.IPTo)
		}
	}
	if q.AttributableOnly {
		c = append(c, "ip_truncated = 0")
	}
	if len(q.IPRanges) > 0 {
		terms := make([]string, len(q.IPRanges))
		for i, r := range q.IPRanges {
			terms[i] = "(ip >= ? AND ip < ?)"
			a = append(a, r[0], r[1])
		}
		c = append(c, "("+strings.Join(terms, " OR ")+")")
	}
	if q.Path != "" {
		c = append(c, "path LIKE ?")
		a = append(a, "%"+q.Path+"%")
	}
	if q.PathPrefix != "" {
		c = append(c, "path LIKE ?")
		a = append(a, q.PathPrefix+"%")
	}
	if q.Search != "" {
		c = append(c, "(message LIKE ? OR path LIKE ? OR ip LIKE ? OR domain LIKE ? OR method LIKE ? OR level LIKE ? OR CAST(status AS TEXT) LIKE ? OR user_agent LIKE ? OR referrer LIKE ?)")
		like := "%" + q.Search + "%"
		for i := 0; i < 9; i++ {
			a = append(a, like)
		}
	}
	if !q.From.IsZero() {
		c = append(c, "ts >= ?")
		a = append(a, q.From.UTC().Format(tsLayout))
	}
	if !q.To.IsZero() {
		c = append(c, "ts <= ?")
		a = append(a, q.To.UTC().Format(tsLayout))
	}
	if q.ExcludeInternal {
		c = append(c, internalIPExclusionSQL())
	}
	if len(c) == 0 {
		return "", a
	}
	return " WHERE " + strings.Join(c, " AND "), a
}

// reached dit si le fichier est hors de la période demandée : plus récent que To, ou fini avant From.
func (q Query) newerThan(f periodFile) bool { return !q.To.IsZero() && f.start.After(q.To) }
func (q Query) olderThan(f periodFile, k Kind) bool {
	return !q.From.IsZero() && k.periodEnd(f.start).Before(q.From)
}

// Search parcourt les fichiers du plus récent au plus ancien et rend une page, ou ce qu'elle a pu lire avant
// l'expiration du contexte (Partial).
func (s *Store) Search(ctx context.Context, q Query) (Page, error) {
	limit := min(max(q.Limit, 1), MaxLimit)
	var all []Row
	var partial bool
	for _, kind := range q.kinds() {
		rows, p, err := s.searchKind(ctx, kind, q, q.After[kind], limit+1)
		if err != nil {
			return Page{}, err
		}
		partial = partial || p
		for i := range rows {
			rows[i].kind = kind
		}
		all = append(all, rows...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Ts.Equal(all[j].Ts) {
			return all[i].ID > all[j].ID
		}
		return all[i].Ts.After(all[j].Ts)
	})
	page := Page{Partial: partial, Next: map[Kind]Position{}}
	for k, p := range q.After {
		page.Next[k] = p
	}
	if len(all) > limit {
		page.HasMore = true
		all = all[:limit]
	}
	for _, r := range all {
		page.Next[r.kind] = Position{Ts: r.Ts.UTC().Format(tsLayout), ID: r.ID}
	}
	page.Rows = all
	return page, nil
}

// MaxLimit est le plafond d'une page.
const MaxLimit = 100000

// searchKind rend jusqu'à limit lignes d'un type après la position pos, du plus récent au plus ancien.
func (s *Store) searchKind(ctx context.Context, kind Kind, q Query, pos Position, limit int) ([]Row, bool, error) {
	files := s.files(kind)
	where, args := s.where(q)
	cursorIdx, cursorLocal := int64(-1), int64(0)
	if !pos.zero() {
		cursorIdx, cursorLocal = pos.ID>>idShift, pos.ID&idMask
	}
	var out []Row
	for i := len(files) - 1; i >= 0 && len(out) < limit; i-- {
		f := files[i]
		if cursorIdx >= 0 && f.index > cursorIdx {
			continue // plus récent que la position
		}
		if q.newerThan(f) {
			continue
		}
		if q.olderThan(f, kind) {
			break // les suivants sont encore plus anciens
		}
		db, err := s.open(kind, f.start)
		if err != nil {
			return out, false, err
		}
		w, a := where, append([]any(nil), args...)
		if cursorIdx >= 0 && f.index == cursorIdx {
			clause := "(ts < ? OR (ts = ? AND id < ?))"
			if w == "" {
				w = " WHERE " + clause
			} else {
				w += " AND " + clause
			}
			a = append(a, pos.Ts, pos.Ts, cursorLocal)
		}
		a = append(a, limit-len(out))
		rows, err := db.QueryContext(ctx, `SELECT `+selectCols+` FROM entries`+w+` ORDER BY ts DESC, id DESC LIMIT ?`, a...)
		if err != nil {
			if ctx.Err() != nil {
				return out, true, nil
			}
			return out, false, err
		}
		for rows.Next() {
			r, _, err := scanRow(rows, f.index)
			if err != nil {
				rows.Close()
				return out, false, err
			}
			out = append(out, r)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			if ctx.Err() != nil {
				return out, true, nil
			}
			return out, false, err
		}
	}
	return out, false, nil
}

// HistPoint compte les entrées d'une tranche de temps, par niveau.
type HistPoint struct {
	Bucket string
	Total  int64
	Warn   int64
	Error  int64
}

func bucketFormat(bucket string) string {
	switch strings.ToLower(bucket) {
	case "minute":
		return "%Y-%m-%dT%H:%M"
	case "day":
		return "%Y-%m-%d"
	}
	return "%Y-%m-%dT%H:00"
}

// Histogram répartit les entrées filtrées par tranche de temps et par niveau. Les tranches sont décalées de
// tzOffsetMin minutes (heure locale de l'Admin qui demande).
func (s *Store) Histogram(ctx context.Context, q Query, bucket string, tzOffsetMin int) ([]HistPoint, bool, error) {
	where, args := s.where(q)
	mod := fmt.Sprintf("%+d minutes", tzOffsetMin)
	merged := map[string]*HistPoint{}
	partial := false
	for _, kind := range q.kinds() {
		files := s.files(kind)
		for i := len(files) - 1; i >= 0; i-- {
			f := files[i]
			if q.newerThan(f) {
				continue
			}
			if q.olderThan(f, kind) {
				break
			}
			db, err := s.open(kind, f.start)
			if err != nil {
				return nil, false, err
			}
			rows, err := db.QueryContext(ctx, `SELECT strftime('`+bucketFormat(bucket)+`', ts, ?) AS b, COUNT(*),
				SUM(CASE WHEN level IN ('warn','warning') THEN 1 ELSE 0 END),
				SUM(CASE WHEN level = 'error' THEN 1 ELSE 0 END)
				FROM entries`+where+` GROUP BY b`, append([]any{mod}, args...)...)
			if err != nil {
				if ctx.Err() != nil {
					partial = true
					break
				}
				return nil, false, err
			}
			for rows.Next() {
				var b string
				var h HistPoint
				if rows.Scan(&b, &h.Total, &h.Warn, &h.Error) != nil || b == "" {
					continue
				}
				m := merged[b]
				if m == nil {
					m = &HistPoint{Bucket: b}
					merged[b] = m
				}
				m.Total += h.Total
				m.Warn += h.Warn
				m.Error += h.Error
			}
			rows.Close()
		}
	}
	out := make([]HistPoint, 0, len(merged))
	for _, p := range merged {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bucket < out[j].Bucket })
	return out, partial, nil
}

// FacetCount : une valeur d'un champ et son nombre d'entrées.
type FacetCount struct {
	Value string
	Count int64
}

var facetColumns = map[string]string{
	"level": "level", "component": "component", "domain": "domain", "method": "method",
	"tls_ja3": "tls_ja3", "tls_ja4": "tls_ja4",
}

// Facets compte les valeurs des champs demandés parmi les entrées filtrées (les 12 plus fréquentes de chacun,
// valeurs vides ignorées) et le nombre total d'entrées filtrées.
func (s *Store) Facets(ctx context.Context, q Query, fields []string) (map[string][]FacetCount, int64, bool, error) {
	where, args := s.where(q)
	counts := map[string]map[string]int64{}
	var total int64
	partial := false
	for _, kind := range q.kinds() {
		files := s.files(kind)
		for i := len(files) - 1; i >= 0; i-- {
			f := files[i]
			if q.newerThan(f) {
				continue
			}
			if q.olderThan(f, kind) {
				break
			}
			db, err := s.open(kind, f.start)
			if err != nil {
				return nil, 0, false, err
			}
			var n int64
			if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM entries`+where, args...).Scan(&n); err != nil {
				if ctx.Err() != nil {
					partial = true
					break
				}
				return nil, 0, false, err
			}
			total += n
			for _, field := range fields {
				col, ok := facetColumns[field]
				if !ok {
					continue
				}
				clause := " WHERE " + col + " != ''"
				if where != "" {
					clause = where + " AND " + col + " != ''"
				}
				rows, err := db.QueryContext(ctx, `SELECT `+col+`, COUNT(*) FROM entries`+clause+` GROUP BY `+col, args...)
				if err != nil {
					if ctx.Err() != nil {
						partial = true
						break
					}
					return nil, 0, false, err
				}
				if counts[field] == nil {
					counts[field] = map[string]int64{}
				}
				for rows.Next() {
					var v string
					var c int64
					if rows.Scan(&v, &c) == nil {
						counts[field][v] += c
					}
				}
				rows.Close()
			}
		}
	}
	out := map[string][]FacetCount{}
	for field, m := range counts {
		list := make([]FacetCount, 0, len(m))
		for v, c := range m {
			list = append(list, FacetCount{v, c})
		}
		sort.Slice(list, func(i, j int) bool {
			if list[i].Count == list[j].Count {
				return list[i].Value < list[j].Value
			}
			return list[i].Count > list[j].Count
		})
		if len(list) > 12 {
			list = list[:12]
		}
		out[field] = list
	}
	return out, total, partial, nil
}

// Kind retourne le type d'une ligne rendue par Search.
func (r Row) Kind() Kind { return r.kind }
