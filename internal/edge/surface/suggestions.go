// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package surface

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Suggestions d'ajout à la politique (ADR 0016, étape 5). Le mode `learn` reste actif une fois la politique posée, et les violations
// que le contrôle voit alimentent le profil. Un chemin (ou une méthode) hors politique qui revient de plusieurs clients ordinaires
// sur plusieurs jours devient une suggestion. La politique ne s'élargit jamais seule : l'administrateur accepte, ligne par ligne.

// Suggestion est un ajout proposé à la politique.
type Suggestion struct {
	// Key désigne la violation (« raison MÉTHODE chemin ») ; c'est ce que l'acceptation efface du profil.
	Key    string `json:"key"`
	Reason string `json:"reason"` // unknown_path | unknown_method
	Method string `json:"method"`
	Path   string `json:"path"` // normalisé : les identifiants sont des classes ({int}, {uuid}…)
	// Confidence : « high » (le backend a servi ces requêtes, depuis plusieurs clients propres, sur plusieurs jours) ou « low »
	// (le contrôle les a refusées : on sait seulement que des clients propres reviennent).
	Confidence   string    `json:"confidence"`
	Count        int64     `json:"count"`
	Legit        int64     `json:"legit"`
	Blocked      int64     `json:"blocked"`
	CleanClients int       `json:"clean_clients"`
	Days         int       `json:"days"`
	First        time.Time `json:"first"`
	Last         time.Time `json:"last"`
	Why          []string  `json:"why"`
	Cautions     []string  `json:"cautions,omitempty"`
}

// probeMarks : morceaux de chemin que visent les scanners. Un chemin qui en contient n'est jamais suggéré : même demandé par
// beaucoup d'IP, c'est une sonde distribuée plus souvent qu'une fonction de l'application.
var probeMarks = []string{
	".env", ".git", ".svn", ".ssh", ".aws", ".htaccess", ".htpasswd", ".ds_store", "wp-login", "wp-admin", "wp-content", "wp-includes",
	"xmlrpc.php", "phpmyadmin", "cgi-bin", "phpunit", "eval-stdin", "passwd", "boot.ini", "webshell", "setup.php", "install.php",
	"config.php", "backup.sql", "dump.sql", "adminer",
}

func isProbePath(path string) bool {
	p := strings.ToLower(path)
	for _, m := range probeMarks {
		if strings.Contains(p, m) {
			return true
		}
	}
	return false
}

// suggestionsOf liste les ajouts que le profil suggère, les plus sûrs d'abord.
func suggestionsOf(rp *RouteProfile) []Suggestion {
	out := []Suggestion{}
	if IsSite(rp.Type) {
		return out // une liste de chemins n'a pas de sens pour un site
	}
	for key, v := range rp.Violations {
		parts := strings.SplitN(key, " ", 3)
		if len(parts) != 3 || (parts[0] != "unknown_path" && parts[0] != "unknown_method") {
			continue
		}
		reason, method, path := parts[0], parts[1], parts[2]
		if strings.Contains(path, clsMore) || !oaMethods[method] || isProbePath(path) {
			continue
		}
		clients, days := v.CleanClients.Estimate(), len(v.Days)
		s := Suggestion{
			Key: key, Reason: reason, Method: method, Path: path, Count: v.Count, Legit: v.Legit, Blocked: v.Blocked,
			CleanClients: clients, Days: days, First: unix(v.First), Last: unix(v.Last),
		}
		switch {
		case v.Legit >= 5 && clients >= MinSupportIPs && days >= MinSupportDay && v.Legit*2 >= v.Count:
			s.Confidence = "high"
			s.Why = []string{
				fmt.Sprintf("le backend a servi %d de ces %d requêtes", v.Legit, v.Count),
				fmt.Sprintf("%d client(s) propre(s) distinct(s), sur %d jour(s)", clients, days),
			}
		case v.Blocked*2 >= v.Count && v.Clean >= 10 && clients >= 5 && days >= 3 && v.Clean*10 >= v.Count*7:
			s.Confidence = "low"
			s.Why = []string{
				fmt.Sprintf("%d client(s) propre(s) distinct(s) sont revenus pendant %d jour(s) (%d requêtes refusées sur %d)", clients, days, v.Blocked, v.Count),
			}
			s.Cautions = []string{"ces requêtes sont refusées par la politique : on ne sait pas si le backend les aurait servies ; un scanner distribué ressemble à ceci"}
		default:
			continue
		}
		if reason == "unknown_method" {
			s.Cautions = append(s.Cautions, "ajoute la méthode "+method+" à un chemin que la politique connaît déjà")
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence == "high"
		}
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}
