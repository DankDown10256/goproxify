// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/modules"
)

// DetectorCheck vérifie les valeurs d'une configuration de détecteur déjà validée par son manifeste
// (clés connues, champs requis) : énumérations, adresses, expressions régulières.
type DetectorCheck func(cfg map[string]any) error

// detectorRegistry range les détecteurs par route (modules de la famille « Detector », ADR 0007),
// sous le nom de leur type de snippet : ip_filter, geo_ip, bot, waf. Le manifeste décrit la
// configuration d'une route ou d'un snippet ; il sert à la valider, à masquer ses secrets et à
// l'afficher côté Admin. L'exécution reste câblée par champ de route dans la chaîne du dispatch :
// l'ordre des middlewares compte (le WAF s'exécute avant le filtre IP…) et ne se déduit pas d'une
// liste de modules.
//
// Les moteurs globaux à état (Ephor, CrowdSec) ne sont pas des détecteurs par route :
// ils lisent leurs bans partagés et ne rentrent pas dans ce registre.
var detectorRegistry = modules.NewRegistry[DetectorCheck]()

// RegisterDetector déclare un détecteur.
func RegisterDetector(m modules.Manifest, check DetectorCheck) { detectorRegistry.Register(m, check) }

// Detectors retourne les manifestes des détecteurs, dans l'ordre d'affichage.
func Detectors() []modules.Manifest { return detectorRegistry.Manifests() }

// DetectorManifest retourne le manifeste d'un détecteur.
func DetectorManifest(typ string) (modules.Manifest, bool) {
	_, m, ok := detectorRegistry.Lookup(typ)
	return m, ok
}

// DetectorTypes retourne les types de détecteur, triés.
func DetectorTypes() []string { return detectorRegistry.Types() }

// ValidateDetector valide la configuration d'un détecteur : manifeste, puis valeurs.
func ValidateDetector(typ string, cfg map[string]any) error {
	check, man, ok := detectorRegistry.Lookup(typ)
	if !ok {
		return fmt.Errorf("détecteur inconnu : %s", typ)
	}
	if err := man.Validate(cfg); err != nil {
		return err
	}
	if check != nil {
		return check(cfg)
	}
	return nil
}

func detText(key, label, placeholder string, required bool) modules.Field {
	return modules.Field{Key: key, Label: label, Placeholder: placeholder, Kind: modules.KindText, Required: required}
}

func detField(key, label, kind string) modules.Field {
	return modules.Field{Key: key, Label: label, Kind: kind}
}

func detList(key, label, placeholder string, required bool) modules.Field {
	return modules.Field{Key: key, Label: label, Placeholder: placeholder, Kind: modules.KindList, Required: required}
}

func detSecret(key, label string) modules.Field {
	return modules.Field{Key: key, Label: label, Kind: modules.KindPassword, Secret: true}
}

func cfgString(cfg map[string]any, key string) string {
	s, _ := cfg[key].(string)
	return strings.TrimSpace(s)
}

func cfgStrings(cfg map[string]any, key string) []string {
	switch v := cfg[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func oneOf(what, v string, allowed ...string) error {
	for _, a := range allowed {
		if v == a {
			return nil
		}
	}
	return fmt.Errorf("%s : %q invalide (attendu : %s)", what, v, strings.Join(allowed, " | "))
}

// checkNets vérifie que chaque entrée est une adresse IP ou un CIDR.
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

var countryCode = regexp.MustCompile(`^[A-Za-z]{2}$`)

func init() {
	RegisterDetector(modules.Manifest{
		Type: "ip_filter", Label: "IP filter",
		Fields: []modules.Field{
			detText("mode", "Mode", "allow | deny", true),
			detList("cidrs", "Addresses / CIDRs", "10.0.0.0/8", true),
		},
	}, func(cfg map[string]any) error {
		if err := oneOf("mode", strings.ToLower(cfgString(cfg, "mode")), "allow", "deny"); err != nil {
			return err
		}
		return checkNets("cidrs", cfgStrings(cfg, "cidrs"))
	})

	RegisterDetector(modules.Manifest{
		Type: "geo_ip", Label: "GeoIP",
		Fields: []modules.Field{
			detText("mode", "Mode", "allow | deny", true),
			detList("countries", "Countries (ISO 3166-1 alpha-2)", "FR", false),
			// Ancien nom de « countries », encore lu par la résolution des snippets.
			detList("blocked_countries", "Blocked countries (legacy)", "", false),
			detText("db_path", "Database path (.mmdb)", "", false),
		},
	}, func(cfg map[string]any) error {
		if err := oneOf("mode", strings.ToLower(cfgString(cfg, "mode")), "allow", "deny"); err != nil {
			return err
		}
		for _, key := range []string{"countries", "blocked_countries"} {
			for _, c := range cfgStrings(cfg, key) {
				if !countryCode.MatchString(strings.TrimSpace(c)) {
					return fmt.Errorf("%s : %q n'est pas un code pays ISO 3166-1 alpha-2", key, c)
				}
			}
		}
		return nil
	})

	RegisterDetector(modules.Manifest{
		Type: "bot", Label: "Bot protection",
		Fields: []modules.Field{
			detField("enabled", "Enabled", modules.KindBool),
			detText("mode", "Mode", "block | monitor | log | challenge | off", false),
			detList("ua_blacklist", "User-Agent blacklist", "sqlmap", false),
			detField("js_challenge", "Browser challenge", modules.KindBool),
			detSecret("challenge_secret", "Challenge secret"),
			detText("challenge_provider", "Challenge provider", "pow | turnstile | hcaptcha", false),
			detField("challenge_difficulty", "Challenge difficulty (bits)", modules.KindNumber),
			detText("challenge_ttl", "Challenge validity", "24h", false),
			detText("challenge_site_key", "Captcha site key", "", false),
			detSecret("challenge_provider_secret", "Captcha secret key"),
			detList("challenge_exempt_paths", "Exempt path prefixes", "/api/", false),
		},
	}, func(cfg map[string]any) error {
		if err := oneOf("mode", strings.ToLower(cfgString(cfg, "mode")), "", "block", "monitor", "log", "challenge", "off"); err != nil {
			return err
		}
		provider := strings.ToLower(cfgString(cfg, "challenge_provider"))
		if err := oneOf("challenge_provider", provider, "", "pow", "turnstile", "hcaptcha"); err != nil {
			return err
		}
		if provider == "turnstile" || provider == "hcaptcha" {
			if cfgString(cfg, "challenge_site_key") == "" || cfgString(cfg, "challenge_provider_secret") == "" {
				return fmt.Errorf("challenge_provider %s : challenge_site_key et challenge_provider_secret sont requis", provider)
			}
		}
		if d, ok := cfg["challenge_difficulty"].(float64); ok && (d < 0 || d > maxChallengeBits) {
			return fmt.Errorf("challenge_difficulty : %v hors de 0..%d", d, maxChallengeBits)
		}
		if ttl := cfgString(cfg, "challenge_ttl"); ttl != "" {
			d, err := time.ParseDuration(ttl)
			if err != nil || d < minChallengeTTL {
				return fmt.Errorf("challenge_ttl : %q invalide (durée d'au moins %s)", ttl, minChallengeTTL)
			}
		}
		return nil
	})

	RegisterDetector(modules.Manifest{
		Type: "waf", Label: "WAF",
		Fields: []modules.Field{
			detField("enabled", "Enabled", modules.KindBool),
			detText("mode", "Mode", "block | detect", false),
			detList("exclude_ids", "Excluded rule IDs", "", false),
			detField("max_body_mb", "Max inspected body (MB)", modules.KindNumber),
			detField("anomaly_threshold", "Anomaly threshold", modules.KindNumber),
			detList("custom_rules", "Custom rules", "", false),
			detField("behavior_enabled", "Behavior analysis", modules.KindBool),
			detField("behavior_window_s", "Behavior window (s)", modules.KindNumber),
			detField("behavior_threshold", "Behavior threshold", modules.KindNumber),
			detList("trusted_proxies", "Trusted proxies (CIDR)", "10.0.0.0/8", false),
				detList("exclusions", "Path-scoped rule exclusions", "", false),
			detText("custom_rules_path", "Custom rules file", "", false),
			detList("waf_whitelist_ips", "Exempt IPs / CIDRs", "", false),
		},
	}, func(cfg map[string]any) error {
		if err := oneOf("mode", strings.ToLower(cfgString(cfg, "mode")), "", "block", "detect"); err != nil {
			return err
		}
		if err := checkNets("trusted_proxies", cfgStrings(cfg, "trusted_proxies")); err != nil {
			return err
		}
		if err := checkNets("waf_whitelist_ips", cfgStrings(cfg, "waf_whitelist_ips")); err != nil {
			return err
		}
		rules, _ := cfg["custom_rules"].([]any)
		for i, r := range rules {
			rule, ok := r.(map[string]any)
			if !ok {
				return fmt.Errorf("custom_rules[%d] : objet attendu", i)
			}
			pattern := cfgString(rule, "pattern")
			if pattern == "" {
				return fmt.Errorf("custom_rules[%d] : pattern requis", i)
			}
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("custom_rules[%d] : expression invalide : %v", i, err)
			}
			if sev := strings.ToLower(cfgString(rule, "severity")); sev != "" {
				if err := oneOf(fmt.Sprintf("custom_rules[%d].severity", i), sev, "critical", "high", "medium", "low"); err != nil {
					return err
				}
			}
			for _, t := range cfgStrings(rule, "targets") {
				if err := oneOf(fmt.Sprintf("custom_rules[%d].targets", i), t, "uri", "args", "body", "headers", "cookies"); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ValidateRouteDetectors valide les détecteurs portés directement par une route (filtre IP, GeoIP, bot,
// WAF) avec les mêmes manifestes et contrôles que les snippets. Seuls les champs renseignés comptent
// (les valeurs nulles d'une structure ne sont pas « saisies »), et un détecteur sans réglage actif est
// ignoré : un filtre IP sans adresse ou un GeoIP sans mode ni pays est désactivé, pas erroné.
func ValidateRouteDetectors(route *router.Route) []string {
	var errs []string
	check := func(typ string, v any, active bool) {
		if !active {
			return
		}
		cfg := providedFields(v)
		if err := ValidateDetector(typ, cfg); err != nil {
			errs = append(errs, typ+" : "+err.Error())
		}
	}
	if c := route.IPFilter; c != nil {
		check("ip_filter", c, len(c.CIDRs) > 0)
	}
	if c := route.GeoIP; c != nil {
		check("geo_ip", c, strings.TrimSpace(c.Mode) != "" || len(c.Countries) > 0)
	}
	if c := route.Bot; c != nil {
		check("bot", c, true)
	}
	if c := route.WAF; c != nil {
		check("waf", c, true)
	}
	return errs
}

// providedFields sérialise une configuration et en retire les valeurs nulles.
func providedFields(v any) map[string]any {
	b, _ := json.Marshal(v)
	var all map[string]any
	_ = json.Unmarshal(b, &all)
	out := make(map[string]any, len(all))
	for k, val := range all {
		switch t := val.(type) {
		case nil:
		case string:
			if strings.TrimSpace(t) != "" {
				out[k] = val
			}
		case bool:
			if t {
				out[k] = val
			}
		case float64:
			if t != 0 {
				out[k] = val
			}
		case []any:
			if len(t) > 0 {
				out[k] = val
			}
		default:
			out[k] = val
		}
	}
	return out
}
