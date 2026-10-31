// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package surface

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// ParseSpec lit la spécification d'un contrôle openapi telle qu'elle est stockée : un objet JSON, ou une chaîne qui en contient un.
// Une spécification en YAML n'est pas modifiable ici (la réécrire en JSON perdrait ses commentaires et sa mise en forme).
func ParseSpec(raw any) (map[string]any, error) {
	switch v := raw.(type) {
	case map[string]any:
		return v, nil
	case string:
		var m map[string]any
		if err := json.Unmarshal([]byte(v), &m); err != nil {
			return nil, fmt.Errorf("la spécification est un texte YAML : ajoutez le chemin à la main")
		}
		return m, nil
	}
	return nil, fmt.Errorf("spécification illisible")
}

// AddToSpec ajoute la méthode et le chemin (normalisé : /nouveau/{int}) à une spécification OpenAPI JSON, sans rien retirer. Rend
// vrai si la spécification a changé. Un chemin qui a déjà la même forme (/u/{u_id} pour /u/{int}) reçoit la méthode ; si le type de son
// paramètre diffère de celui du chemin ajouté, il est élargi en texte, sans quoi les valeurs de l'autre type resteraient refusées.
func AddToSpec(spec map[string]any, method, path string) (bool, error) {
	if !oaMethods[method] {
		return false, fmt.Errorf("méthode %q inexprimable dans OpenAPI", method)
	}
	if strings.Contains(path, clsMore) {
		return false, fmt.Errorf("chemin trop profond pour être ajouté")
	}
	paths, _ := spec["paths"].(map[string]any)
	if paths == nil {
		paths = map[string]any{}
		spec["paths"] = paths
	}
	var segs []oaSeg
	for _, s := range strings.Split(strings.Trim(path, "/"), "/") {
		if s != "" {
			segs = append(segs, oaSeg{key: s, class: isClassKey(s)})
		}
	}
	acc := &pathAcc{segs: segs}
	for _, s := range segs {
		if s.class {
			acc.kinds = append(acc.kinds, map[string]bool{s.key: true})
		}
	}
	_, shown := pathParamNames(acc)
	sig := signatureOf(shown)

	key := shown
	for k := range paths {
		if signatureOf(k) == sig {
			key = k
			break
		}
	}
	item, _ := paths[key].(map[string]any)
	if item == nil {
		item = map[string]any{}
		paths[key] = item
	}
	lm := strings.ToLower(method)
	if _, ok := item[lm]; ok {
		return false, nil
	}

	// Les paramètres de chemin de l'opération : les noms de la clé retenue, typés comme leurs frères ou, à défaut, d'après la classe.
	keyNames := paramNamesOf(key)
	newSchemas := make([]map[string]any, len(keyNames))
	pi := 0
	for _, s := range segs {
		if !s.class {
			continue
		}
		if pi < len(keyNames) {
			newSchemas[pi] = classSchema(map[string]bool{s.key: true})
		}
		pi++
	}
	params := make([]any, 0, len(keyNames))
	for i, n := range keyNames {
		sch := newSchemas[i]
		if existing := siblingSchema(item, n); existing != nil {
			if !reflect.DeepEqual(toAny(existing), toAny(sch)) {
				sch = map[string]any{"type": "string"}
				widenParam(item, n)
			} else {
				sch = existing
			}
		}
		params = append(params, map[string]any{"name": n, "in": "path", "required": true, "schema": sch})
	}
	op := map[string]any{
		"summary":   "ajouté depuis une suggestion de l'apprentissage de surface",
		"responses": map[string]any{"default": map[string]any{"description": "observé"}},
	}
	if len(params) > 0 {
		op["parameters"] = params
	}
	item[lm] = op
	return true, nil
}

func toAny(m map[string]any) any {
	b, _ := json.Marshal(m)
	var v any
	_ = json.Unmarshal(b, &v)
	return v
}

// signatureOf remplace chaque segment {nom} par {} : deux chemins de même signature se recouvrent.
func signatureOf(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segs {
		if len(s) > 2 && s[0] == '{' && s[len(s)-1] == '}' {
			segs[i] = "{}"
		}
	}
	return strings.Join(segs, "/")
}

func paramNamesOf(p string) []string {
	var out []string
	for _, s := range strings.Split(strings.Trim(p, "/"), "/") {
		if len(s) > 2 && s[0] == '{' && s[len(s)-1] == '}' {
			out = append(out, s[1:len(s)-1])
		}
	}
	return out
}

// siblingSchema rend le schéma que les autres opérations du chemin donnent au paramètre de chemin name.
func siblingSchema(item map[string]any, name string) map[string]any {
	for _, v := range item {
		op, _ := v.(map[string]any)
		list, _ := op["parameters"].([]any)
		for _, e := range list {
			pm, _ := e.(map[string]any)
			if pm["name"] == name && pm["in"] == "path" {
				if sch, ok := pm["schema"].(map[string]any); ok {
					return sch
				}
			}
		}
	}
	return nil
}

// widenParam remplace par un texte le schéma du paramètre de chemin name dans toutes les opérations du chemin.
func widenParam(item map[string]any, name string) {
	for _, v := range item {
		op, _ := v.(map[string]any)
		list, _ := op["parameters"].([]any)
		for _, e := range list {
			pm, _ := e.(map[string]any)
			if pm["name"] == name && pm["in"] == "path" {
				pm["schema"] = map[string]any{"type": "string"}
			}
		}
	}
}
