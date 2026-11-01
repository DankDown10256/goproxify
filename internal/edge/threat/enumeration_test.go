// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"fmt"
	"hash/maphash"
	"math"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func enumCount(result string) float64 {
	return testutil.ToFloat64(threatEnumerationTotal.WithLabelValues(result))
}

// userShape : « /api/users/<chiffres> » → gabarit et valeur, comme surface.EnumShape sur un cas simple.
func userShape(path string) (string, string, bool) {
	const p = "/api/users/"
	if !strings.HasPrefix(path, p) || len(path) == len(p) {
		return "", "", false
	}
	return p + "{int}", path[len(p):], true
}

func enumEngine(t *testing.T, mode string, known bool) (*Engine, *time.Time) {
	t.Helper()
	e, now, _ := explainEngine(t, Config{
		IPScore:     IPScoreConfig{Enabled: true, BanThreshold: 100, HalfLife: Duration{time.Hour}},
		Enumeration: EnumerationConfig{Mode: mode},
	})
	e.SetEnumerationHooks(userShape, func(host, path string) bool { return known })
	return e, now
}

func walk(e *Engine, ip string, from, n int) {
	for i := 0; i < n; i++ {
		e.Observe(httptest.NewRequest("GET", fmt.Sprintf("/api/users/%d", from+i), nil), ip, "api.test", 200)
	}
}

func TestEnumerationFlagsAWalkOverManyValuesOnce(t *testing.T) {
	e, _ := enumEngine(t, EnumerationBlock, true)
	hit, shadow := enumCount("hit"), enumCount("shadow")
	walk(e, "203.0.113.5", 1, 20)
	if enumCount("hit") != hit {
		t.Fatal("vingt valeurs : sous le plancher de trente")
	}
	walk(e, "203.0.113.5", 21, 200)
	if got := enumCount("hit"); got != hit+1 {
		t.Fatalf("le dépassement ne se déclenche qu'une fois par fenêtre : %v", got-hit)
	}
	if enumCount("shadow") != shadow {
		t.Fatal("en block rien n'est fantôme")
	}
	if s := e.IPScore("203.0.113.5"); s < 3.5 || s > 4.5 {
		t.Fatalf("le signal verse ses points à la note commune : %v", s)
	}
}

func TestEnumerationDetectCountsWithoutScoring(t *testing.T) {
	e, _ := enumEngine(t, EnumerationDetect, true)
	shadow := enumCount("shadow")
	walk(e, "203.0.113.6", 1, 100)
	if enumCount("shadow") != shadow+1 || e.IPScore("203.0.113.6") != 0 {
		t.Fatalf("detect : compté, jamais noté (score %v)", e.IPScore("203.0.113.6"))
	}
}

func TestOrdinaryClientsAndRepeatedValuesAreNotEnumeration(t *testing.T) {
	e, _ := enumEngine(t, EnumerationBlock, true)
	hit := enumCount("hit")
	walk(e, "203.0.113.7", 1, 10)
	for i := 0; i < 500; i++ { // la même ressource relue : beaucoup de requêtes, une seule valeur
		e.Observe(httptest.NewRequest("GET", "/api/users/42", nil), "203.0.113.8", "api.test", 200)
	}
	if enumCount("hit") != hit {
		t.Fatal("peu de valeurs, ou une seule valeur répétée, ne sont pas une énumération")
	}
}

func TestEnumerationNeedsAConvergedProfileThatKnowsTheTemplate(t *testing.T) {
	e, _ := enumEngine(t, EnumerationBlock, false)
	hit, unproven := enumCount("hit"), enumCount("unproven")
	walk(e, "203.0.113.9", 1, 200)
	if enumCount("hit") != hit || enumCount("unproven") != unproven+1 || e.IPScore("203.0.113.9") != 0 {
		t.Fatal("sans profil convergé qui connaisse le gabarit, on ne sait pas ce qui est normal : rien n'est noté")
	}
}

func TestEnumerationThresholdFollowsWhatOtherClientsDo(t *testing.T) {
	e, now := enumEngine(t, EnumerationBlock, true)
	// Trente clients lisent chacun une quarantaine de ressources : c'est la norme de ce gabarit.
	for c := 0; c < 30; c++ {
		walk(e, fmt.Sprintf("198.51.100.%d", c+1), 1, 40)
	}
	*now = now.Add(11 * time.Minute)
	e.sweepEnumeration()
	hit := enumCount("hit")
	walk(e, "203.0.113.10", 1, 100) // au-dessus du plancher (30) mais pas de la norme (4 × 40)
	if enumCount("hit") != hit {
		t.Fatal("cent valeurs ne sont pas anormales pour une API dont les clients en lisent quarante")
	}
	walk(e, "203.0.113.11", 1, 400)
	if enumCount("hit") != hit+1 {
		t.Fatal("quatre cents valeurs sortent de la norme")
	}
}


func TestEnumerationWindowsRotate(t *testing.T) {
	e, now := enumEngine(t, EnumerationBlock, true)
	hit := enumCount("hit")
	walk(e, "203.0.113.12", 1, 100)
	*now = now.Add(11 * time.Minute)
	walk(e, "203.0.113.12", 1000, 100)
	if enumCount("hit") != hit+2 {
		t.Fatalf("une IP qui recommence dans la fenêtre suivante déclenche de nouveau : %v", enumCount("hit")-hit)
	}
}

func TestEnumerationForgetIPAndNormPersistence(t *testing.T) {
	e, now := enumEngine(t, EnumerationBlock, true)
	for c := 0; c < 25; c++ {
		walk(e, fmt.Sprintf("198.51.100.%d", c+1), 1, 40)
	}
	walk(e, "203.0.113.13", 1, 10)
	*now = now.Add(11 * time.Minute)
	e.sweepEnumeration()
	st := e.SnapshotState()
	if len(st.Enumeration) != 1 {
		t.Fatalf("la norme du gabarit doit être conservée : %+v", st.Enumeration)
	}
	for _, s := range st.Enumeration {
		if s.N < 25 || math.Abs(s.Mean-40) > 5 {
			t.Fatalf("norme attendue autour de 40 sur 25 fenêtres : %+v", s)
		}
	}
	e2, _ := enumEngine(t, EnumerationBlock, true)
	e2.RestoreState(st)
	if n := e2.enum.norm("api.test|/api/users/{int}"); n == nil || n.n < 25 {
		t.Fatalf("la norme doit survivre à un redémarrage : %+v", n)
	}

	walk(e, "203.0.113.14", 1, 10)
	e.ForgetIP("203.0.113.14")
	for i := range e.enum.shards {
		for k := range e.enum.shards[i].m {
			if strings.HasPrefix(k, "203.0.113.14|") {
				t.Fatal("l'effacement d'une IP retire ses fenêtres")
			}
		}
	}
}

func TestEnumerationDistinctEstimate(t *testing.T) {
	for _, want := range []int{10, 100, 500, 1500} {
		var en enumEntry
		tr := newEnumTracker(time.Now)
		for i := 0; i < want; i++ {
			bit := hashOf(tr, fmt.Sprint(i)) % enumBits
			en.bits[bit/64] |= 1 << (bit % 64)
		}
		got := en.distinct()
		if math.Abs(got-float64(want))/float64(want) > 0.12 {
			t.Errorf("%d valeurs estimées à %.0f", want, got)
		}
	}
}

func TestValidateEnumeration(t *testing.T) {
	ok := Config{IPScore: IPScoreConfig{Enabled: true}, Enumeration: EnumerationConfig{Mode: "block", Floor: 50, Window: Duration{time.Hour}, Points: 6}}
	if err := ok.ValidateEnumeration(); err != nil {
		t.Fatalf("réglage valide refusé : %v", err)
	}
	bad := map[string]Config{
		"mode":             {Enumeration: EnumerationConfig{Mode: "ban"}},
		"floor":            {Enumeration: EnumerationConfig{Floor: -1}},
		"window":           {Enumeration: EnumerationConfig{Window: Duration{time.Second}}},
		"points":           {Enumeration: EnumerationConfig{Points: 99}},
		"block sans score": {Enumeration: EnumerationConfig{Mode: "block"}},
	}
	for name, c := range bad {
		if c.ValidateEnumeration() == nil {
			t.Errorf("%s : doit être refusé", name)
		}
	}
}

func hashOf(t *enumTracker, s string) uint64 { return maphash.String(t.seed, s) }

func TestAnEnumeratorCanOnlyNudgeTheNormByABoundedStep(t *testing.T) {
	e, now := enumEngine(t, EnumerationBlock, true)
	for c := 0; c < 30; c++ {
		walk(e, fmt.Sprintf("198.51.100.%d", c+1), 1, 40)
	}
	*now = now.Add(11 * time.Minute)
	e.sweepEnumeration()
	before := e.enum.norm("api.test|/api/users/{int}")
	for c := 0; c < 10; c++ {
		walk(e, fmt.Sprintf("203.0.113.%d", c+1), 1, 800)
	}
	*now = now.Add(11 * time.Minute)
	e.sweepEnumeration()
	after := e.enum.norm("api.test|/api/users/{int}")
	if after.mean > before.mean*2 {
		t.Fatalf("dix énumérateurs ne doivent pas doubler la norme : %.0f → %.0f", before.mean, after.mean)
	}
	hit := enumCount("hit")
	walk(e, "203.0.113.99", 1, 800)
	if enumCount("hit") != hit+1 {
		t.Fatal("un énumérateur reste détecté après les autres")
	}
}
