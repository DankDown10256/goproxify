// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"strings"
)

// createSpec est le corps de POST /containers/create reconstruit depuis l'inspection d'un conteneur, avec les
// réseaux à brancher après la création (l'API ne prend qu'un réseau à la création).
type createSpec struct {
	body      map[string]any
	extraNets map[string]map[string]any
}

// specFromInspect reprend la configuration complète du conteneur inspecté (variables, commande, ports, montages,
// réseaux, santé, ressources…) en remplaçant seulement l'image : recréer un conteneur ne doit rien lui retirer.
func specFromInspect(raw map[string]any, image string) createSpec {
	id, _ := raw["Id"].(string)

	body := cloneMap(asMap(raw["Config"]))
	body["Image"] = image
	// Le nom d'hôte par défaut est l'identifiant court de l'ancien conteneur : il ne doit pas survivre à la recréation.
	if h, _ := body["Hostname"].(string); h != "" && strings.HasPrefix(id, h) {
		delete(body, "Hostname")
	}

	hc := cloneMap(asMap(raw["HostConfig"]))
	if extra := anonymousVolumeBinds(hc, raw["Mounts"]); len(extra) > 0 {
		hc["Binds"] = append(toStrings(hc["Binds"]), extra...)
	}
	body["HostConfig"] = hc

	spec := createSpec{body: body, extraNets: map[string]map[string]any{}}
	mode, _ := hc["NetworkMode"].(string)
	if mode == "host" || mode == "none" || strings.HasPrefix(mode, "container:") {
		return spec
	}
	primary := mode
	if primary == "" || primary == "default" {
		primary = "bridge"
	}
	for name, ep := range asMap(asMap(raw["NetworkSettings"])["Networks"]) {
		cfg := endpointConfig(asMap(ep), id)
		if name == primary {
			body["NetworkingConfig"] = map[string]any{"EndpointsConfig": map[string]any{name: cfg}}
			continue
		}
		spec.extraNets[name] = cfg
	}
	return spec
}

// anonymousVolumeBinds rattache au nouveau conteneur les volumes anonymes de l'ancien : sans cela, Docker en crée de
// nouveaux, vides, et les données restent orphelines dans l'ancien volume.
func anonymousVolumeBinds(hc map[string]any, mounts any) []string {
	covered := map[string]bool{}
	for _, b := range toStrings(hc["Binds"]) {
		if parts := strings.Split(b, ":"); len(parts) >= 2 {
			covered[parts[1]] = true
		}
	}
	if list, ok := hc["Mounts"].([]any); ok {
		for _, m := range list {
			if target, _ := asMap(m)["Target"].(string); target != "" {
				covered[target] = true
			}
		}
	}
	var out []string
	list, _ := mounts.([]any)
	for _, m := range list {
		mm := asMap(m)
		name, _ := mm["Name"].(string)
		dest, _ := mm["Destination"].(string)
		if mm["Type"] != "volume" || name == "" || dest == "" || covered[dest] {
			continue
		}
		bind := name + ":" + dest
		if rw, ok := mm["RW"].(bool); ok && !rw {
			bind += ":ro"
		}
		out = append(out, bind)
	}
	return out
}

// endpointConfig ne garde de l'état d'un réseau que ce qui était demandé (alias, IP fixe, liens, options) et laisse
// Docker recalculer adresses et identifiants.
func endpointConfig(ep map[string]any, id string) map[string]any {
	cfg := map[string]any{}
	var aliases []string
	for _, a := range toStrings(ep["Aliases"]) {
		// Docker ajoute l'identifiant court du conteneur comme alias : celui de l'ancien n'a plus de sens.
		if len(a) >= 12 && strings.HasPrefix(id, a) {
			continue
		}
		aliases = append(aliases, a)
	}
	if len(aliases) > 0 {
		cfg["Aliases"] = aliases
	}
	for _, k := range []string{"IPAMConfig", "Links", "DriverOpts"} {
		if v := ep[k]; v != nil {
			cfg[k] = v
		}
	}
	return cfg
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func toStrings(v any) []string {
	if s, ok := v.([]string); ok {
		return s
	}
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
