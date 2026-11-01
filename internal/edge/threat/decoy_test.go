// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func decoyCount(result string) float64 {
	return testutil.ToFloat64(threatDecoyTotal.WithLabelValues(result))
}

func decoyReq(path string) *http.Request { return httptest.NewRequest("GET", path, nil) }

func TestDecoyBlockModeBansWithoutScore(t *testing.T) {
	e, _, bans := explainEngine(t, Config{Decoys: DecoyConfig{Mode: DecoyBlock}})
	hits := decoyCount("hit")
	blocked, reason := e.Check(decoyReq("/.git/config"), "198.51.100.1")
	if !blocked || reason != "threat: decoy" {
		t.Fatalf("un leurre touché en block est refusé : %v %q", blocked, reason)
	}
	if len(*bans) != 1 || (*bans)[0].reason != "threat: decoy" {
		t.Fatalf("sans score cumulé, un signal fort bannit aussitôt : %+v", *bans)
	}
	if got := sumPoints((*bans)[0].signals); got != 8 || (*bans)[0].signals[0].Name != "decoy" || (*bans)[0].signals[0].Value != "/.git/config" {
		t.Fatalf("le ban explique le leurre avec ses points et le chemin demandé : %+v", (*bans)[0].signals)
	}
	if decoyCount("hit") != hits+1 {
		t.Fatal("l'accès doit être compté")
	}
}

func TestDecoyWithTheCumulativeScoreNeedsASecondHit(t *testing.T) {
	e, _, bans := explainEngine(t, Config{
		Decoys:  DecoyConfig{Mode: DecoyBlock},
		IPScore: IPScoreConfig{Enabled: true, BanThreshold: 10, HalfLife: Duration{3600e9}},
	})
	e.Check(decoyReq("/backup.sql"), "198.51.100.1")
	if len(*bans) != 0 {
		t.Fatalf("8 points sous le seuil de 10 : %+v", *bans)
	}
	e.Check(decoyReq("/dump.sql"), "198.51.100.1")
	if len(*bans) != 1 {
		t.Fatalf("un deuxième leurre franchit le seuil : %+v", *bans)
	}
}

func TestDecoyDetectModeOnlyCounts(t *testing.T) {
	e, _, bans := explainEngine(t, Config{Decoys: DecoyConfig{Mode: DecoyDetect}})
	shadow := decoyCount("shadow")
	if blocked, reason := e.Check(decoyReq("/.git/config"), "198.51.100.1"); blocked || reason != "" {
		t.Fatalf("en detect, rien n'est versé à la note : %v %q", blocked, reason)
	}
	if len(*bans) != 0 || decoyCount("shadow") != shadow+1 {
		t.Fatalf("détecté et compté, jamais banni : %+v", *bans)
	}
}

func TestDecoyOffByDefault(t *testing.T) {
	e, _, bans := explainEngine(t, Config{})
	if blocked, _ := e.Check(decoyReq("/.git/config"), "198.51.100.1"); blocked || len(*bans) != 0 {
		t.Fatal("les leurres sont éteints par défaut")
	}
}

func TestDecoyMatching(t *testing.T) {
	e, _, _ := explainEngine(t, Config{Decoys: DecoyConfig{Mode: DecoyBlock, Paths: []string{"/piege-maison", "/zone-interdite/"}}})
	for path, want := range map[string]bool{
		"/.git/config":        true,
		"/.GIT/HEAD":          true, // la casse est ignorée
		"/.git":               true, // le préfixe sans sa barre
		"/backup.sql":         true,
		"/backup.sql/":        true,
		"/piege-maison":       true,
		"/zone-interdite/x/y": true,
		"/page":               false,
		"/backup.sqlx":        false, // une entrée exacte n'est pas un préfixe
		"/piege-maison-bis":   false,
		"/":                   false,
	} {
		ds := e.decoys
		if got := ds.match(path); got != want {
			t.Errorf("match(%q) = %v, attendu %v", path, got, want)
		}
	}
}

func TestDecoyNoDefaultsKeepsOnlyTheAdministratorsPaths(t *testing.T) {
	e, _, _ := explainEngine(t, Config{Decoys: DecoyConfig{Mode: DecoyBlock, NoDefaults: true, Paths: []string{"/piege"}}})
	if e.decoys.match("/.git/config") || !e.decoys.match("/piege") {
		t.Fatal("sans le jeu par défaut, seuls les chemins de l'administrateur piègent")
	}
}

// Un chemin que le trafic légitime de la route utilise n'est jamais un piège.
func TestDecoyGuardSkipsWhatTheAppServes(t *testing.T) {
	e, _, bans := explainEngine(t, Config{Decoys: DecoyConfig{Mode: DecoyBlock}})
	e.SetDecoyGuard(func(r *http.Request) bool { return r.URL.Path == "/.git/config" })
	skipped := decoyCount("skipped")
	if blocked, _ := e.Check(decoyReq("/.git/config"), "198.51.100.1"); blocked || len(*bans) != 0 {
		t.Fatalf("le garde-fou écarte le leurre : %+v", *bans)
	}
	if decoyCount("skipped") != skipped+1 {
		t.Fatal("le leurre écarté est compté")
	}
	if blocked, _ := e.Check(decoyReq("/.git/HEAD"), "198.51.100.1"); !blocked {
		t.Fatal("un autre leurre, que la route n'utilise pas, reste un piège")
	}
}

func TestDecoySkipsWhitelistedPaths(t *testing.T) {
	e, _, bans := explainEngine(t, Config{Decoys: DecoyConfig{Mode: DecoyBlock}, Whitelist: Whitelist{Paths: []string{"/.git/"}}})
	if blocked, _ := e.Check(decoyReq("/.git/config"), "198.51.100.1"); blocked || len(*bans) != 0 {
		t.Fatal("un chemin en liste blanche n'est jamais un piège")
	}
}

func TestValidateDecoys(t *testing.T) {
	ok := Config{Decoys: DecoyConfig{Mode: DecoyBlock, Paths: []string{"/a", "/zone/"}}}
	if err := ok.ValidateDecoys(); err != nil {
		t.Fatalf("configuration valide refusée : %v", err)
	}
	many := make([]string, maxDecoyPaths+1)
	for i := range many {
		many[i] = "/x" + strings.Repeat("a", i%5+1)
	}
	for what, c := range map[string]Config{
		"mode inconnu":        {Decoys: DecoyConfig{Mode: "bloque"}},
		"sans barre initiale": {Decoys: DecoyConfig{Paths: []string{"git"}}},
		"racine seule":        {Decoys: DecoyConfig{Paths: []string{"/"}}},
		"trop de chemins":     {Decoys: DecoyConfig{Paths: many}},
	} {
		if err := c.ValidateDecoys(); err == nil {
			t.Errorf("%s : la configuration devait être refusée", what)
		}
	}
}
