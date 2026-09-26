//go:build ignore

// Génère les contours embarqués depuis Natural Earth (domaine public) : propriétés réduites,
// coordonnées arrondies et simplifiées (Douglas-Peucker) pour rester léger.
//
// Pays (Natural Earth 50m) :
//	curl -L -o ne50.geojson https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_50m_admin_0_countries.geojson
//	go run scripts/gen_world_geojson.go ne50.geojson internal/admin/ui/src/lib/world/countries.geojson
//
// Régions (Natural Earth 10m admin-1, tout pays) : {iso, code, name}
//
//	curl -L -o ne10a1.geojson https://raw.githubusercontent.com/nvkelso/natural-earth-vector/master/geojson/ne_10m_admin_1_states_provinces.geojson
//	go run scripts/gen_world_geojson.go ne10a1.geojson internal/admin/ui/src/lib/world/regions.geojson
package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
)

var tolerance = 0.04 // degrés (~4 km) : invisible jusqu'au zoom 6 ; 0.06 pour les régions

type feature struct {
	Properties map[string]any `json:"properties"`
	Geometry   struct {
		Type        string          `json:"type"`
		Coordinates json.RawMessage `json:"coordinates"`
	} `json:"geometry"`
}

func perpDist(p, a, b [2]float64) float64 {
	dx, dy := b[0]-a[0], b[1]-a[1]
	if dx == 0 && dy == 0 {
		return math.Hypot(p[0]-a[0], p[1]-a[1])
	}
	t := ((p[0]-a[0])*dx + (p[1]-a[1])*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(p[0]-(a[0]+t*dx), p[1]-(a[1]+t*dy))
}

func dp(pts [][2]float64, tol float64) [][2]float64 {
	if len(pts) < 3 {
		return pts
	}
	idx, max := 0, 0.0
	for i := 1; i < len(pts)-1; i++ {
		if d := perpDist(pts[i], pts[0], pts[len(pts)-1]); d > max {
			idx, max = i, d
		}
	}
	if max <= tol {
		return [][2]float64{pts[0], pts[len(pts)-1]}
	}
	l := dp(pts[:idx+1], tol)
	r := dp(pts[idx:], tol)
	return append(l[:len(l)-1], r...)
}

func ring(raw []any) [][]float64 {
	pts := make([][2]float64, len(raw))
	for i, v := range raw {
		c := v.([]any)
		pts[i] = [2]float64{c[0].(float64), c[1].(float64)}
	}
	s := dp(pts, tolerance)
	if len(s) < 4 {
		return nil // îlot trop petit une fois simplifié
	}
	out := make([][]float64, len(s))
	for i, p := range s {
		out[i] = []float64{math.Round(p[0]*100) / 100, math.Round(p[1]*100) / 100}
	}
	return out
}

func polygon(rings []any) [][][]float64 {
	var out [][][]float64
	for i, r := range rings {
		if s := ring(r.([]any)); s != nil {
			out = append(out, s)
		} else if i == 0 {
			return nil // anneau extérieur perdu : on abandonne le polygone
		}
	}
	return out
}

func main() {
	in, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var fc struct {
		Features []feature `json:"features"`
	}
	if err := json.Unmarshal(in, &fc); err != nil {
		panic(err)
	}
	var b strings.Builder
	b.WriteString(`{"type":"FeatureCollection","features":[`)
	first := true
	for _, f := range fc.Features {
		regions := strings.Contains(os.Args[1], "a1")
		if regions {
			tolerance = 0.06
		}
		iso, _ := f.Properties["ISO_A2_EH"].(string)
		name, _ := f.Properties["NAME"].(string)
		code := ""
		if regions {
			iso, _ = f.Properties["iso_a2"].(string)
			name, _ = f.Properties["name"].(string)
			code, _ = f.Properties["iso_3166_2"].(string)
		} else if iso == "" || iso == "-99" {
			iso, _ = f.Properties["ISO_A2"].(string)
		}
		if iso == "" || iso == "-99" {
			continue
		}
		var coords any
		_ = json.Unmarshal(f.Geometry.Coordinates, &coords)
		var polys [][][][]float64
		switch f.Geometry.Type {
		case "Polygon":
			if p := polygon(coords.([]any)); p != nil {
				polys = append(polys, p)
			}
		case "MultiPolygon":
			for _, pc := range coords.([]any) {
				if p := polygon(pc.([]any)); p != nil {
					polys = append(polys, p)
				}
			}
		}
		if len(polys) == 0 {
			continue
		}
		geom, _ := json.Marshal(map[string]any{"type": "MultiPolygon", "coordinates": polys})
		props, _ := json.Marshal(map[string]string{"iso": iso, "code": code, "name": name})
		if !first {
			b.WriteByte(',')
		}
		first = false
		fmt.Fprintf(&b, `{"type":"Feature","properties":%s,"geometry":%s}`, props, geom)
	}
	b.WriteString(`]}`)
	if err := os.WriteFile(os.Args[2], []byte(b.String()), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("%d octets\n", b.Len())
}
