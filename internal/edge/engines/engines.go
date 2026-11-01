// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package engines décrit la configuration des moteurs de sécurité globaux de la passerelle —
// Ephor (détection par signaux et Seuils), les Seuils multi-passerelles de l'Admin (erreurs répétées sur plusieurs passerelles), CrowdSec (décisions LAPI) et WAF
// (interrupteur maître du détecteur par route) — par des manifestes (ADR 0007) : valider une
// configuration avant de l'enregistrer, masquer ses secrets, l'afficher. Ces moteurs ne sont pas des
// détecteurs par route : ils partagent un magasin de bans et tournent une fois par passerelle ; ils
// n'entrent donc pas dans la chaîne de middlewares et ce paquet ne les exécute pas. Le WAF reste exécuté
// par route ; sa configuration de moteur ne fait que l'allumer ou l'éteindre pour toute la passerelle.
package engines

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	edgecrowdsec "github.com/vincamok/goproxify/internal/edge/crowdsec"
	"github.com/vincamok/goproxify/internal/edge/threat"
	"github.com/vincamok/goproxify/internal/edge/waf"
	"github.com/vincamok/goproxify/internal/modules"
)

// Types de moteur.
const (
	Ephor    = "ephor"
	Fleet    = "fleet"
	CrowdSec = "crowdsec"
	WAF      = "waf"
)

type engine struct {
	manifest modules.Manifest
	// decode lit strictement la configuration (clé inconnue ⇒ erreur) et contrôle ses valeurs.
	decode func(raw []byte) error
}

var registry = map[string]engine{}
var order []string

func register(e engine) {
	registry[e.manifest.Type] = e
	order = append(order, e.manifest.Type)
}

func init() {
	register(engine{
		manifest: modules.Manifest{Type: Ephor, Label: "Ephor", Fields: secretFields(reflectFields(reflect.TypeOf(threat.Config{}), ""), "challenge.secret")},
		decode:   decodeEphor,
	})
	register(engine{
		manifest: modules.Manifest{Type: Fleet, Label: "Cross-gateway thresholds", Fields: []modules.Field{
			{Key: "enabled", Label: "Enabled", Kind: modules.KindBool},
			{Key: "window_sec", Label: "Window (s)", Kind: modules.KindNumber},
			{Key: "max_errors", Label: "Errors before ban", Kind: modules.KindNumber},
			{Key: "ban_duration_sec", Label: "Ban duration (s, 0 = permanent)", Kind: modules.KindNumber},
			{Key: "trust_forwarded_for", Label: "Trust X-Forwarded-For", Kind: modules.KindBool},
			{Key: "whitelist", Label: "Exempt IPs / CIDRs", Kind: modules.KindList},
		}},
		decode: decodeFleet,
	})
	register(engine{
		manifest: modules.Manifest{Type: CrowdSec, Label: "CrowdSec", Fields: []modules.Field{
			{Key: "enabled", Label: "Enabled", Kind: modules.KindBool},
			{Key: "api_url", Label: "LAPI URL", Placeholder: "http://localhost:8080", Kind: modules.KindText},
			{Key: "api_key", Label: "Bouncer API key", Kind: modules.KindPassword, Secret: true},
		}},
		decode: decodeCrowdSec,
	})
	register(engine{
		manifest: modules.Manifest{Type: WAF, Label: "WAF", Fields: []modules.Field{
			{Key: "enabled", Label: "Enabled", Kind: modules.KindBool},
		}},
		decode: func(raw []byte) error { return strictDecode(raw, &waf.EngineConfig{}) },
	})
}

// Manifests retourne les manifestes des moteurs, dans l'ordre d'affichage.
func Manifests() []modules.Manifest {
	out := make([]modules.Manifest, 0, len(order))
	for _, t := range order {
		out = append(out, registry[t].manifest)
	}
	return out
}

// Manifest retourne le manifeste d'un moteur.
func Manifest(typ string) (modules.Manifest, bool) {
	e, ok := registry[typ]
	return e.manifest, ok
}

// Validate vérifie la configuration d'un moteur : clés connues (à tous les niveaux), valeurs lisibles et
// cohérentes. Une configuration valide se charge toujours côté passerelle.
func Validate(typ string, raw json.RawMessage) error {
	e, ok := registry[typ]
	if !ok {
		return fmt.Errorf("moteur inconnu : %s", typ)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = []byte("{}")
	}
	return e.decode(raw)
}

// MaskConfig masque les secrets d'une configuration (clé d'API CrowdSec).
func MaskConfig(typ string, raw json.RawMessage) json.RawMessage {
	man, ok := Manifest(typ)
	if !ok {
		return raw
	}
	var cfg map[string]any
	if json.Unmarshal(raw, &cfg) != nil || cfg == nil {
		return raw
	}
	b, err := json.Marshal(man.Mask(cfg))
	if err != nil {
		return raw
	}
	return b
}

// KeepSecrets reprend de la configuration enregistrée les secrets que la nouvelle omet ou renvoie masqués.
func KeepSecrets(typ string, old, next json.RawMessage) json.RawMessage {
	man, ok := Manifest(typ)
	if !ok {
		return next
	}
	var o, n map[string]any
	if json.Unmarshal(old, &o) != nil || json.Unmarshal(next, &n) != nil {
		return next
	}
	if n == nil {
		n = map[string]any{}
	}
	b, err := json.Marshal(man.KeepSecrets(o, n))
	if err != nil {
		return next
	}
	return b
}

func strictDecode(raw []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("configuration invalide : %w", err)
	}
	return nil
}

func checkNets(what string, entries []string) error {
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if net.ParseIP(e) != nil {
			continue
		}
		if _, _, err := net.ParseCIDR(e); err != nil {
			return fmt.Errorf("%s : %q n'est ni une adresse IP ni un CIDR", what, e)
		}
	}
	return nil
}

func checkURL(what, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%s : %q n'est pas une URL http(s)", what, raw)
	}
	return nil
}

func nonNegative(what string, v float64) error {
	if v < 0 {
		return fmt.Errorf("%s : %v négatif", what, v)
	}
	return nil
}

func decodeFleet(raw []byte) error {
	var c FleetConfig
	if err := strictDecode(raw, &c); err != nil {
		return err
	}
	for what, v := range map[string]int{"window_sec": c.WindowSec, "max_errors": c.MaxErrors, "ban_duration_sec": c.BanDurationSec} {
		if err := nonNegative(what, float64(v)); err != nil {
			return err
		}
	}
	return checkNets("whitelist", c.Whitelist)
}

func decodeCrowdSec(raw []byte) error {
	var c edgecrowdsec.Config
	if err := strictDecode(raw, &c); err != nil {
		return err
	}
	if c.APIURL != "" {
		if err := checkURL("api_url", c.APIURL); err != nil {
			return err
		}
	}
	if c.Enabled && (strings.TrimSpace(c.APIURL) == "" || strings.TrimSpace(c.APIKey) == "") {
		return fmt.Errorf("api_url et api_key sont requis pour activer CrowdSec")
	}
	return nil
}

func decodeEphor(raw []byte) error {
	var c threat.Config
	if err := strictDecode(raw, &c); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(c.Mode)) {
	case "", "block", "detect":
	default:
		return fmt.Errorf("mode : %q invalide (attendu : block | detect)", c.Mode)
	}
	for what, v := range map[string]float64{
		"score_threshold": float64(c.ScoreThreshold), "global_rps": c.GlobalRPS, "global_burst": float64(c.GlobalBurst),
		"rate_limit": c.RateLimit, "rate_ban_threshold": float64(c.RateBanThreshold), "error_threshold": float64(c.ErrorThreshold),
		"ip_score.ban_threshold": c.IPScore.BanThreshold, "escalation.factor": c.Escalation.Factor,
		"ip_score.errors.default_weight": c.IPScore.Errors.DefaultWeight,
		"tarpit.delay_ms":                float64(c.Tarpit.DelayMs), "tarpit.max_concurrent": float64(c.Tarpit.MaxConcurrent),
		"ban_duration": float64(c.BanDuration.Duration), "rate_window": float64(c.RateWindow.Duration),
		"error_window": float64(c.ErrorWindow.Duration), "rate_ban_window": float64(c.RateBanWindow.Duration),
		"ip_score.half_life": float64(c.IPScore.HalfLife.Duration), "escalation.window": float64(c.Escalation.Window.Duration),
		"escalation.max_duration": float64(c.Escalation.MaxDuration.Duration), "lists.refresh_interval": float64(c.Lists.RefreshInterval.Duration),
	} {
		if err := nonNegative(what, v); err != nil {
			return err
		}
	}
	if c.Tarpit.DelayMs > 30000 {
		return fmt.Errorf("tarpit.delay_ms : %d dépasse 30000", c.Tarpit.DelayMs)
	}
	for code, w := range c.IPScore.Errors.Weights {
		if n, err := strconv.Atoi(code); err != nil || n < 400 || n > 599 {
			return fmt.Errorf("ip_score.errors.weights : %q n'est pas un code d'erreur HTTP (400-599)", code)
		}
		if err := nonNegative("ip_score.errors.weights["+code+"]", w); err != nil {
			return err
		}
	}
	for i, r := range c.IPScore.Errors.Routes {
		if !strings.HasPrefix(r.Prefix, "/") {
			return fmt.Errorf("ip_score.errors.routes[%d].prefix : %q doit commencer par /", i, r.Prefix)
		}
		if err := nonNegative(fmt.Sprintf("ip_score.errors.routes[%d].factor", i), r.Factor); err != nil {
			return err
		}
	}
	if err := checkNets("whitelist.ips", c.Whitelist.IPs); err != nil {
		return err
	}
	if err := checkNets("custom_lists.ips", c.CustomLists.IPs); err != nil {
		return err
	}
	for what, sources := range map[string][]string{"lists.ua_sources": c.Lists.UASources, "lists.path_sources": c.Lists.PathSources, "lists.ip_sources": c.Lists.IPSources} {
		for _, s := range sources {
			if err := checkURL(what, s); err != nil {
				return err
			}
		}
	}
	for _, p := range append(append([]string{}, c.Whitelist.Paths...), c.CustomLists.Paths...) {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("chemin %q : doit commencer par /", p)
		}
	}
	for _, f := range c.CustomLists.TLSFingerprints {
		if strings.TrimSpace(f) == "" || strings.ContainsAny(f, " \t") {
			return fmt.Errorf("custom_lists.tls_fingerprints : %q invalide", f)
		}
	}
	if err := c.ValidateChallenge(); err != nil {
		return err
	}
	if err := c.ValidateDecoys(); err != nil {
		return err
	}
	if err := c.ValidateThresholds(); err != nil {
		return err
	}
	if err := c.ValidateUnknownHost(); err != nil {
		return err
	}
	if err := c.ValidateTLSReputation(); err != nil {
		return err
	}
	if err := c.ValidateEnumeration(); err != nil {
		return err
	}
	if err := c.ValidateSeasonal(); err != nil {
		return err
	}
	if err := checkNets("unknown_host.probes", c.UnknownHost.Probes); err != nil {
		return err
	}
	return c.Behavior.Validate()
}

// secretFields marque comme secrets les champs dont la clé est donnée : masqués à l'affichage, conservés quand la nouvelle
// configuration les renvoie masqués.
func secretFields(fields []modules.Field, keys ...string) []modules.Field {
	for i := range fields {
		for _, k := range keys {
			if fields[i].Key == k {
				fields[i].Kind, fields[i].Secret = modules.KindPassword, true
			}
		}
	}
	return fields
}

// reflectFields dérive les champs d'un manifeste des étiquettes JSON d'une structure de configuration :
// le manifeste suit la structure sans liste à tenir à jour. Les sections imbriquées donnent des
// chemins pointés ; les tableaux et dictionnaires sont des feuilles.
func reflectFields(t reflect.Type, prefix string) []modules.Field {
	var out []modules.Field
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		key := prefix + name
		ft := f.Type
		if ft.Kind() == reflect.Struct && ft.Name() != "Duration" {
			out = append(out, reflectFields(ft, key+".")...)
			continue
		}
		kind := modules.KindText
		switch ft.Kind() {
		case reflect.Bool:
			kind = modules.KindBool
		case reflect.Int, reflect.Int64, reflect.Float64:
			kind = modules.KindNumber
		case reflect.Slice:
			kind = modules.KindList
		}
		if ft.Name() == "Duration" {
			kind = modules.KindText
		}
		out = append(out, modules.Field{Key: key, Label: key, Kind: kind})
	}
	return out
}

// FleetConfig est la configuration des Seuils multi-passerelles, le moteur que l'Admin fait tourner sur les compteurs d'erreurs
// client que les passerelles lui envoient : une IP dont les erreurs se répartissent sur plusieurs passerelles ne dépasse le seuil
// d'aucune d'elles. Il ne tourne pas sur les passerelles : les Seuils d'Ephor (threat.ThresholdsConfig) y font ce travail.
type FleetConfig struct {
	Enabled           bool     `json:"enabled"`
	WindowSec         int      `json:"window_sec"`          // fenêtre glissante (défaut 300)
	MaxErrors         int      `json:"max_errors"`          // seuil déclenchant le ban
	BanDurationSec    int      `json:"ban_duration_sec"`    // 0 = permanent
	TrustForwardedFor bool     `json:"trust_forwarded_for"` // utilise X-Forwarded-For
	Whitelist         []string `json:"whitelist"`
}
