// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/router"
)

const (
	openAPIRoot         = "gpx://openapi"
	openAPIMaxSpecBytes = 4 << 20
	openAPIMaxRefHops   = 16
)

var openAPIMethods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

type oaParam struct {
	name     string
	in       string // path | query | header | cookie
	required bool
	explode  bool
	typ      string // type JSON Schema ("" si indéterminé)
	itemTyp  string
	schema   *jsonschema.Schema
}

type oaMedia struct {
	contentType string // "application/json", "application/*", "*/*"…
	json        bool
	schema      *jsonschema.Schema // nil : pas de schéma, rien à valider
}

type oaBody struct {
	required bool
	media    []oaMedia
}

type oaOp struct {
	params []oaParam
	body   *oaBody
}

type oaPath struct {
	template string
	re       *regexp.Regexp
	names    []string
	literals int // segments sans paramètre : départage les gabarits ambigus (le plus précis gagne)
	ops      map[string]*oaOp
}

type openAPISpec struct {
	paths []*oaPath
}

// oaBuilder porte l'état de compilation d'une spécification.
type oaBuilder struct {
	root     map[string]any
	compiler *jsonschema.Compiler
	n        int
}

// openAPISpecText extrait le texte de la spécification : une chaîne JSON ("…") ou un objet JSON.
func openAPISpecText(raw json.RawMessage) string {
	t := bytes.TrimSpace(raw)
	if len(t) > 0 && t[0] == '"' {
		var s string
		if json.Unmarshal(t, &s) == nil {
			return s
		}
	}
	return string(t)
}

// normalizeYAML convertit les maps à clés quelconques de yaml.v3 en maps à clés texte (compatibles JSON).
func normalizeYAML(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = normalizeYAML(e)
		}
		return x
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[fmt.Sprint(k)] = normalizeYAML(e)
		}
		return out
	case []any:
		for i, e := range x {
			x[i] = normalizeYAML(e)
		}
		return x
	}
	return v
}

func compileOpenAPI(cfg *router.OpenAPIConfig) (*openAPISpec, error) {
	text := openAPISpecText(cfg.Spec)
	if strings.TrimSpace(text) == "" {
		return nil, fmt.Errorf("openapi.spec vide")
	}
	if len(text) > openAPIMaxSpecBytes {
		return nil, fmt.Errorf("openapi.spec dépasse %d Mo", openAPIMaxSpecBytes>>20)
	}
	var parsed any
	if err := yaml.Unmarshal([]byte(text), &parsed); err != nil {
		return nil, fmt.Errorf("openapi.spec illisible : %w", err)
	}
	root, ok := normalizeYAML(parsed).(map[string]any)
	if !ok {
		return nil, fmt.Errorf("openapi.spec : un objet est attendu")
	}
	version, _ := root["openapi"].(string)
	if !strings.HasPrefix(version, "3.") {
		return nil, fmt.Errorf("openapi.spec : champ « openapi » 3.x requis (Swagger 2.0 non pris en charge)")
	}
	paths, _ := root["paths"].(map[string]any)
	if len(paths) == 0 {
		return nil, fmt.Errorf("openapi.spec : aucun chemin dans « paths »")
	}
	if strings.HasPrefix(version, "3.0") {
		convertOpenAPI30(root)
	}
	if err := rejectExternalRefs(root); err != nil {
		return nil, err
	}

	buf, err := json.Marshal(root)
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	c.UseLoader(noLoader{})
	c.AssertFormat()
	if err := c.AddResource(openAPIRoot, doc); err != nil {
		return nil, err
	}
	b := &oaBuilder{root: root, compiler: c}

	spec := &openAPISpec{}
	templates := make([]string, 0, len(paths))
	for t := range paths {
		templates = append(templates, t)
	}
	sort.Strings(templates)
	for _, tpl := range templates {
		if !strings.HasPrefix(tpl, "/") {
			return nil, fmt.Errorf("paths[%q] : un chemin commence par /", tpl)
		}
		item, err := b.deref(paths[tpl])
		if err != nil {
			return nil, fmt.Errorf("paths[%q] : %w", tpl, err)
		}
		p, err := b.buildPath(tpl, item)
		if err != nil {
			return nil, fmt.Errorf("paths[%q] : %w", tpl, err)
		}
		spec.paths = append(spec.paths, p)
	}
	sort.SliceStable(spec.paths, func(i, j int) bool {
		if spec.paths[i].literals != spec.paths[j].literals {
			return spec.paths[i].literals > spec.paths[j].literals
		}
		return len(spec.paths[i].template) > len(spec.paths[j].template)
	})
	return spec, nil
}

// convertOpenAPI30 ramène un document OpenAPI 3.0 au JSON Schema 2020-12 utilisé par le validateur :
// `nullable` devient un type « null » ajouté, `exclusiveMinimum/Maximum` booléens deviennent numériques.
func convertOpenAPI30(v any) {
	switch x := v.(type) {
	case map[string]any:
		if nb, _ := x["nullable"].(bool); nb {
			switch t := x["type"].(type) {
			case string:
				x["type"] = []any{t, "null"}
			case []any:
				x["type"] = append(t, "null")
			}
			if en, ok := x["enum"].([]any); ok {
				x["enum"] = append(en, nil)
			}
		}
		delete(x, "nullable")
		for _, kw := range [][2]string{{"exclusiveMinimum", "minimum"}, {"exclusiveMaximum", "maximum"}} {
			if on, ok := x[kw[0]].(bool); ok {
				if on {
					if val, has := x[kw[1]]; has {
						x[kw[0]] = val
						delete(x, kw[1])
					} else {
						delete(x, kw[0])
					}
				} else {
					delete(x, kw[0])
				}
			}
		}
		for _, e := range x {
			convertOpenAPI30(e)
		}
	case []any:
		for _, e := range x {
			convertOpenAPI30(e)
		}
	}
}

// rejectExternalRefs refuse tout $ref qui ne soit pas local : la passerelle ne charge rien d'extérieur.
func rejectExternalRefs(v any) error {
	switch x := v.(type) {
	case map[string]any:
		if ref, ok := x["$ref"].(string); ok && !strings.HasPrefix(ref, "#/") {
			return fmt.Errorf("référence externe interdite : %s", ref)
		}
		for _, e := range x {
			if err := rejectExternalRefs(e); err != nil {
				return err
			}
		}
	case []any:
		for _, e := range x {
			if err := rejectExternalRefs(e); err != nil {
				return err
			}
		}
	}
	return nil
}

// resolvePointer suit un pointeur JSON "#/a/b" dans le document.
func (b *oaBuilder) resolvePointer(ref string) (any, error) {
	cur := any(b.root)
	for _, tok := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch c := cur.(type) {
		case map[string]any:
			next, ok := c[tok]
			if !ok {
				return nil, fmt.Errorf("référence introuvable : %s", ref)
			}
			cur = next
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(c) {
				return nil, fmt.Errorf("référence introuvable : %s", ref)
			}
			cur = c[i]
		default:
			return nil, fmt.Errorf("référence introuvable : %s", ref)
		}
	}
	return cur, nil
}

// deref suit les "$ref" d'un objet (paramètre, corps, élément de chemin) jusqu'à l'objet réel.
func (b *oaBuilder) deref(v any) (map[string]any, error) {
	for hops := 0; hops < openAPIMaxRefHops; hops++ {
		m, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("objet attendu")
		}
		ref, isRef := m["$ref"].(string)
		if !isRef {
			return m, nil
		}
		next, err := b.resolvePointer(ref)
		if err != nil {
			return nil, err
		}
		v = next
	}
	return nil, fmt.Errorf("références circulaires")
}

// schemaMap résout les $ref de premier niveau d'un schéma pour en lire le type.
func (b *oaBuilder) schemaMap(v any) map[string]any {
	m, err := b.deref(v)
	if err != nil {
		return nil
	}
	return m
}

func schemaType(m map[string]any) string {
	switch t := m["type"].(type) {
	case string:
		return t
	case []any:
		for _, e := range t {
			if s, _ := e.(string); s != "" && s != "null" {
				return s
			}
		}
	}
	return ""
}

// rewriteRefs copie un schéma en rendant ses "$ref" locaux absolus (gpx://openapi#/…) : le schéma est
// ajouté comme ressource à part et doit continuer à résoudre ses références dans le document.
func rewriteRefs(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			if k == "$ref" {
				if s, ok := e.(string); ok && strings.HasPrefix(s, "#") {
					out[k] = openAPIRoot + s
					continue
				}
			}
			out[k] = rewriteRefs(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = rewriteRefs(e)
		}
		return out
	}
	return v
}

// compileInline compile un schéma en ligne (paramètre ou corps) comme ressource autonome.
func (b *oaBuilder) compileInline(schema any) (*jsonschema.Schema, error) {
	buf, err := json.Marshal(rewriteRefs(schema))
	if err != nil {
		return nil, err
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	b.n++
	url := fmt.Sprintf("gpx://openapi-inline/%d", b.n)
	if err := b.compiler.AddResource(url, doc); err != nil {
		return nil, err
	}
	return b.compiler.Compile(url)
}

var oaTemplateParam = regexp.MustCompile(`\{([^{}/]+)\}`)

func (b *oaBuilder) buildPath(tpl string, item map[string]any) (*oaPath, error) {
	p := &oaPath{template: tpl, ops: map[string]*oaOp{}}
	var names []string
	var re strings.Builder
	re.WriteString("^")
	last := 0
	for _, m := range oaTemplateParam.FindAllStringSubmatchIndex(tpl, -1) {
		re.WriteString(regexp.QuoteMeta(tpl[last:m[0]]))
		re.WriteString(`([^/]+)`)
		names = append(names, tpl[m[2]:m[3]])
		last = m[1]
	}
	re.WriteString(regexp.QuoteMeta(tpl[last:]))
	re.WriteString("$")
	rx, err := regexp.Compile(re.String())
	if err != nil {
		return nil, err
	}
	p.re, p.names = rx, names
	for _, seg := range strings.Split(strings.Trim(tpl, "/"), "/") {
		if !strings.Contains(seg, "{") {
			p.literals++
		}
	}

	common, err := b.buildParams(item["parameters"])
	if err != nil {
		return nil, err
	}
	for _, method := range openAPIMethods {
		raw, ok := item[method]
		if !ok {
			continue
		}
		opMap, err := b.deref(raw)
		if err != nil {
			return nil, fmt.Errorf("%s : %w", method, err)
		}
		own, err := b.buildParams(opMap["parameters"])
		if err != nil {
			return nil, fmt.Errorf("%s : %w", method, err)
		}
		op := &oaOp{params: mergeParams(common, own)}
		if rb, ok := opMap["requestBody"]; ok {
			body, err := b.buildBody(rb)
			if err != nil {
				return nil, fmt.Errorf("%s requestBody : %w", method, err)
			}
			op.body = body
		}
		for _, n := range names {
			found := false
			for _, pr := range op.params {
				if pr.in == "path" && pr.name == n {
					found = true
				}
			}
			if !found {
				return nil, fmt.Errorf("%s : le paramètre de chemin {%s} n'est pas déclaré", method, n)
			}
		}
		p.ops[strings.ToUpper(method)] = op
	}
	return p, nil
}

// mergeParams : un paramètre de l'opération remplace celui du chemin de même nom et même emplacement.
func mergeParams(common, own []oaParam) []oaParam {
	out := make([]oaParam, 0, len(common)+len(own))
	for _, c := range common {
		replaced := false
		for _, o := range own {
			if o.name == c.name && o.in == c.in {
				replaced = true
				break
			}
		}
		if !replaced {
			out = append(out, c)
		}
	}
	return append(out, own...)
}

func (b *oaBuilder) buildParams(raw any) ([]oaParam, error) {
	list, _ := raw.([]any)
	var out []oaParam
	for i, e := range list {
		pm, err := b.deref(e)
		if err != nil {
			return nil, fmt.Errorf("parameters[%d] : %w", i, err)
		}
		name, _ := pm["name"].(string)
		in, _ := pm["in"].(string)
		if name == "" || (in != "path" && in != "query" && in != "header" && in != "cookie") {
			return nil, fmt.Errorf("parameters[%d] : name et in (path, query, header, cookie) requis", i)
		}
		prm := oaParam{name: name, in: in, required: in == "path"}
		if r, ok := pm["required"].(bool); ok && in != "path" {
			prm.required = r
		}
		prm.explode = in == "query" || in == "cookie"
		if ex, ok := pm["explode"].(bool); ok {
			prm.explode = ex
		}
		if sch, ok := pm["schema"]; ok {
			if sm := b.schemaMap(sch); sm != nil {
				prm.typ = schemaType(sm)
				if prm.typ == "array" {
					if im := b.schemaMap(sm["items"]); im != nil {
						prm.itemTyp = schemaType(im)
					}
				}
			}
			s, err := b.compileInline(sch)
			if err != nil {
				return nil, fmt.Errorf("parameters[%d] (%s) : %w", i, name, err)
			}
			prm.schema = s
		}
		out = append(out, prm)
	}
	return out, nil
}

func (b *oaBuilder) buildBody(raw any) (*oaBody, error) {
	rb, err := b.deref(raw)
	if err != nil {
		return nil, err
	}
	body := &oaBody{}
	body.required, _ = rb["required"].(bool)
	content, _ := rb["content"].(map[string]any)
	cts := make([]string, 0, len(content))
	for ct := range content {
		cts = append(cts, ct)
	}
	sort.Strings(cts)
	for _, ct := range cts {
		mt, _ := content[ct].(map[string]any)
		m := oaMedia{contentType: strings.ToLower(strings.TrimSpace(ct))}
		m.json = isJSONContent(m.contentType)
		if sch, ok := mt["schema"]; ok && m.json {
			s, err := b.compileInline(sch)
			if err != nil {
				return nil, fmt.Errorf("content[%s].schema : %w", ct, err)
			}
			m.schema = s
		}
		body.media = append(body.media, m)
	}
	return body, nil
}

// ValidateOpenAPIConfig retourne les erreurs de configuration (utilisé par le dry-run).
func ValidateOpenAPIConfig(cfg *router.OpenAPIConfig) []string {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	var errs []string
	if cfg.Mode != "" && cfg.Mode != "block" && cfg.Mode != "detect" {
		errs = append(errs, "openapi.mode invalide (block ou detect)")
	}
	if cfg.UnknownPaths != "" && cfg.UnknownPaths != "allow" && cfg.UnknownPaths != "block" {
		errs = append(errs, "openapi.unknown_paths invalide (allow ou block)")
	}
	if cfg.MaxBody < 0 {
		errs = append(errs, "openapi.max_body doit être positif")
	}
	if cfg.StripPrefix != "" && !strings.HasPrefix(cfg.StripPrefix, "/") {
		errs = append(errs, "openapi.strip_prefix doit commencer par /")
	}
	for _, reason := range cfg.BlockReasons {
		known := false
		for _, k := range OpenAPIReasons {
			known = known || k == reason
		}
		if !known {
			errs = append(errs, fmt.Sprintf("openapi.block_reasons : %q inconnu (%s)", reason, strings.Join(OpenAPIReasons, ", ")))
		}
	}
	for _, s := range cfg.Skip {
		switch s {
		case "path", "query", "header", "cookie", "body":
		default:
			errs = append(errs, fmt.Sprintf("openapi.skip : %q inconnu (path, query, header, cookie, body)", s))
		}
	}
	if _, err := compileOpenAPI(cfg); err != nil {
		errs = append(errs, err.Error())
	}
	return errs
}

type oaIssue struct {
	In      string `json:"in"`
	Name    string `json:"name,omitempty"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

// match retourne le chemin de la spécification qui correspond et les valeurs de ses paramètres.
func (s *openAPISpec) match(path string) (*oaPath, map[string]string) {
	try := func(p string) (*oaPath, map[string]string) {
		for _, op := range s.paths {
			if m := op.re.FindStringSubmatch(p); m != nil {
				vals := make(map[string]string, len(op.names))
				for i, n := range op.names {
					vals[n] = m[i+1]
				}
				return op, vals
			}
		}
		return nil, nil
	}
	if op, v := try(path); op != nil {
		return op, v
	}
	if len(path) > 1 && strings.HasSuffix(path, "/") {
		return try(strings.TrimSuffix(path, "/"))
	}
	return nil, nil
}

// openAPIPath retourne le chemin de la requête privé de strip_prefix.
func openAPIPath(r *http.Request, cfg *router.OpenAPIConfig) string {
	path := r.URL.Path
	if cfg.StripPrefix != "" && strings.HasPrefix(path, cfg.StripPrefix) {
		path = "/" + strings.TrimPrefix(strings.TrimPrefix(path, cfg.StripPrefix), "/")
	}
	return path
}

// coerceParam construit l'instance JSON d'un paramètre reçu sous forme de texte.
func coerceParam(prm oaParam, values []string) any {
	one := func(typ, v string) any {
		switch typ {
		case "integer", "number", "boolean":
			if doc, err := jsonschema.UnmarshalJSON(strings.NewReader(v)); err == nil {
				return doc
			}
		}
		return v
	}
	if prm.typ == "array" {
		items := values
		if !prm.explode || prm.in == "header" || prm.in == "path" {
			items = nil
			for _, v := range values {
				items = append(items, strings.Split(v, ",")...)
			}
		}
		out := make([]any, len(items))
		for i, v := range items {
			out[i] = one(prm.itemTyp, v)
		}
		return out
	}
	return one(prm.typ, values[0])
}

func (s *openAPISpec) validate(r *http.Request, cfg *router.OpenAPIConfig, skip map[string]bool, maxBody int64) (result string, status int, issues []oaIssue, restore func()) {
	pth, vals := s.match(openAPIPath(r, cfg))
	if pth == nil {
		return "unknown_path", http.StatusNotFound, []oaIssue{{In: "path", Message: "chemin absent de la spécification"}}, nil
	}
	op, ok := pth.ops[r.Method]
	if !ok {
		return "unknown_method", http.StatusMethodNotAllowed, []oaIssue{{In: "path", Message: "méthode absente de la spécification pour ce chemin"}}, nil
	}

	var paramIssues, bodyIssues []oaIssue
	for _, prm := range op.params {
		if skip[prm.in] {
			continue
		}
		var values []string
		switch prm.in {
		case "path":
			if v, ok := vals[prm.name]; ok {
				values = []string{v}
			}
		case "query":
			values = r.URL.Query()[prm.name]
		case "header":
			values = r.Header.Values(prm.name)
		case "cookie":
			if c, err := r.Cookie(prm.name); err == nil {
				values = []string{c.Value}
			}
		}
		if len(values) == 0 {
			if prm.required {
				paramIssues = append(paramIssues, oaIssue{In: prm.in, Name: prm.name, Message: "paramètre requis absent"})
			}
			continue
		}
		if prm.schema == nil {
			continue
		}
		if err := prm.schema.Validate(coerceParam(prm, values)); err != nil {
			paramIssues = append(paramIssues, oaIssue{In: prm.in, Name: prm.name, Message: firstSchemaMessage(err)})
		}
	}

	if op.body != nil && !skip["body"] {
		bodyIssues, restore, status = s.validateBody(r, op.body, maxBody)
	}

	issues = append(paramIssues, bodyIssues...)
	switch {
	case len(issues) == 0:
		return "valid", 0, nil, restore
	case status == http.StatusRequestEntityTooLarge || status == http.StatusUnsupportedMediaType:
		return "invalid", status, issues, restore
	case len(paramIssues) > 0:
		return "invalid", http.StatusBadRequest, issues, restore
	default:
		return "invalid", http.StatusUnprocessableEntity, issues, restore
	}
}

func firstSchemaMessage(err error) string {
	if ve, ok := err.(*jsonschema.ValidationError); ok {
		out := ve.BasicOutput()
		var walk func(u jsonschema.OutputUnit) string
		walk = func(u jsonschema.OutputUnit) string {
			if u.Error != nil {
				return u.Error.String()
			}
			for _, c := range u.Errors {
				if m := walk(c); m != "" {
					return m
				}
			}
			return ""
		}
		if m := walk(*out); m != "" {
			return m
		}
	}
	return "valeur non conforme"
}

func matchMedia(media []oaMedia, ct string) *oaMedia {
	ct = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	for i := range media {
		if media[i].contentType == ct {
			return &media[i]
		}
	}
	for i := range media {
		mt := media[i].contentType
		if mt == "*/*" || (strings.HasSuffix(mt, "/*") && strings.HasPrefix(ct, strings.TrimSuffix(mt, "*"))) {
			return &media[i]
		}
	}
	return nil
}

// validateBody lit et contrôle le corps JSON ; restore remet le corps lu à disposition du backend.
func (s *openAPISpec) validateBody(r *http.Request, body *oaBody, maxBody int64) (issues []oaIssue, restore func(), status int) {
	empty := r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0
	ct := r.Header.Get("Content-Type")
	if empty {
		if body.required {
			return []oaIssue{{In: "body", Message: "corps requis absent"}}, nil, 0
		}
		return nil, nil, 0
	}
	m := matchMedia(body.media, ct)
	if m == nil {
		if len(body.media) == 0 {
			return nil, nil, 0
		}
		return []oaIssue{{In: "body", Message: "type de contenu non déclaré dans la spécification : " + ct}}, nil, http.StatusUnsupportedMediaType
	}
	if m.schema == nil {
		return nil, nil, 0
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		return []oaIssue{{In: "body", Message: "corps illisible"}}, nil, 0
	}
	orig := r.Body
	if int64(len(raw)) > maxBody {
		restore = func() {
			r.Body = struct {
				io.Reader
				io.Closer
			}{io.MultiReader(bytes.NewReader(raw), orig), orig}
		}
		return []oaIssue{{In: "body", Message: "corps trop volumineux pour être validé"}}, restore, http.StatusRequestEntityTooLarge
	}
	restore = func() { r.Body = io.NopCloser(bytes.NewReader(raw)) }
	for _, d := range validateAgainst(m.schema, raw) {
		issues = append(issues, oaIssue{In: "body", Path: d.Path, Message: d.Message})
	}
	return issues, restore, 0
}

type openAPIOutcomeKey struct{}

// OpenAPIOutcome reçoit le verdict du contrôle openapi pour une requête : la passerelle le pose dans le contexte avant la
// chaîne et le relit après, pour que l'apprentissage de surface voie les violations même en mode detect (ADR 0016).
type OpenAPIOutcome struct {
	// Result : valid | invalid | unknown_path | unknown_method ; vide si le contrôle n'a pas jugé la requête.
	Result string
	// Reason : unknown_path | unknown_method | invalid_param | invalid_body | unsupported_media | too_large ; vide si valide, ou
	// si le chemin est inconnu mais que le proxy les laisse passer (unknown_paths = allow : ce n'est pas une violation).
	Reason string
	// Blocked : la requête a été refusée par le contrôle (mode block, ou raison listée dans block_reasons).
	Blocked bool
}

// OpenAPIReasons liste les types de violation que block_reasons accepte.
var OpenAPIReasons = []string{"unknown_path", "unknown_method", "invalid_param", "invalid_body", "unsupported_media", "too_large"}

// openAPIReason donne le type de violation d'un verdict ; vide si la requête est conforme.
func openAPIReason(result string, status int) string {
	switch {
	case result == "unknown_path" || result == "unknown_method":
		return result
	case result != "invalid":
		return ""
	case status == http.StatusRequestEntityTooLarge:
		return "too_large"
	case status == http.StatusUnsupportedMediaType:
		return "unsupported_media"
	case status == http.StatusBadRequest:
		return "invalid_param"
	}
	return "invalid_body"
}

// WithOpenAPIOutcome joint au contexte un verdict à remplir.
func WithOpenAPIOutcome(ctx context.Context) (context.Context, *OpenAPIOutcome) {
	o := &OpenAPIOutcome{}
	return context.WithValue(ctx, openAPIOutcomeKey{}, o), o
}

func recordOpenAPIOutcome(r *http.Request, result, reason string, blocked bool) {
	o, _ := r.Context().Value(openAPIOutcomeKey{}).(*OpenAPIOutcome)
	if o == nil {
		return
	}
	o.Result, o.Reason, o.Blocked = result, reason, blocked
}

// OpenAPI valide les requêtes contre une spécification OpenAPI : le chemin et la méthode doivent
// exister (si unknown_paths vaut « block »), les paramètres et le corps JSON doivent respecter leurs
// schémas. Mode block (défaut) : 400 (paramètre), 422 (corps), 404 / 405 (chemin ou méthode inconnus),
// 413 (corps trop gros) ou 415 (type de contenu non déclaré) ; mode detect : la requête passe toujours,
// seule la métrique compte. Une spécification invalide laisse tout passer (le dry-run la refuse à
// l'enregistrement). La spécification est compilée une seule fois par chargement de la route.
func OpenAPI(host string, cfg *router.OpenAPIConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil || !cfg.Enabled {
			return next
		}
		spec, err := compileOpenAPI(cfg)
		if err != nil {
			return next
		}
		block := cfg.Mode != "detect"
		strictPaths := cfg.UnknownPaths == "block"
		blockReasons := map[string]bool{}
		for _, reason := range cfg.BlockReasons {
			blockReasons[reason] = true
		}
		maxBody := cfg.MaxBody
		if maxBody <= 0 {
			maxBody = requestSchemaDefaultMaxBody
		}
		skip := map[string]bool{}
		for _, k := range cfg.Skip {
			skip[k] = true
		}
		count := func(result string) { metrics.Routing.OpenAPI.WithLabelValues(host, result).Inc() }
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			result, status, issues, restore := spec.validate(r, cfg, skip, maxBody)
			if restore != nil {
				restore()
			}
			count(result)
			reason := openAPIReason(result, status)
			if (result == "unknown_path" || result == "unknown_method") && !strictPaths {
				reason = ""
			}
			refuse := reason != "" && (block || blockReasons[reason])
			recordOpenAPIOutcome(r, result, reason, refuse)
			if !refuse {
				next.ServeHTTP(w, r)
				return
			}
			if result == "unknown_method" {
				if pth, _ := spec.match(openAPIPath(r, cfg)); pth != nil {
					allow := make([]string, 0, len(pth.ops))
					for m := range pth.ops {
						allow = append(allow, m)
					}
					sort.Strings(allow)
					w.Header().Set("Allow", strings.Join(allow, ", "))
				}
			}
			writeOpenAPIError(w, status, issues)
		})
	}
}

func writeOpenAPIError(w http.ResponseWriter, status int, issues []oaIssue) {
	if len(issues) > requestSchemaMaxDetails {
		issues = issues[:requestSchemaMaxDetails]
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":   "request does not match the OpenAPI specification",
		"details": issues,
	})
}
