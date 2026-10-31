// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package launcher

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// L'interface de conception (ADR 0019, section 8) : le même launcher, sur tous les hôtes, propose de dessiner la
// topologie puis de l'installer. Elle donne l'accès d'un root sur l'hôte : un code d'accès aléatoire, affiché dans la
// sortie du conteneur, est demandé à l'ouverture. Le QR code n'en dépend pas (il a son propre jeton).
const (
	designLinger     = 10 * time.Minute
	designSessionTTL = time.Hour
	codeAlphabet     = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	codeLength       = 8
	maxCodeFailures  = 5
	codeLockout      = time.Minute
	maxDesignBody    = 64 << 10
	maxRestoreBody   = 512 << 20 // comme l'import de l'Admin : un snapshot avec états de passerelles pèse une centaine de Mo
	designCookie     = "gpx_launcher"
)

//go:embed design.html
var designHTML string

// DesignHost est un hôte tel que l'interface le décrit : le nom est facultatif, et un seul hôte est « local ».
type DesignHost struct {
	Name  string   `json:"name"`
	Addr  string   `json:"addr"`
	Roles []string `json:"roles"`
	Group string   `json:"group,omitempty"`
	Local bool     `json:"local,omitempty"`
}

// DesignRestore demande de reconstruire l'Admin de la sauvegarde envoyée avant : la topologie est celle du fichier, on ne
// dit que laquelle de ses machines est celle-ci (et, si elle a changé d'adresse, la nouvelle).
type DesignRestore struct {
	Local string `json:"local"`
	Addr  string `json:"addr,omitempty"`
}

// DesignRequest est ce que l'interface envoie pour simuler ou installer.
type DesignRequest struct {
	Hosts   []DesignHost   `json:"hosts"`
	Email   string         `json:"email,omitempty"`
	Restore *DesignRestore `json:"restore,omitempty"`
}

// Topology convertit la demande en topologie validée. Un hôte sans nom est nommé d'après son adresse ; sans hôte local
// désigné, l'hôte unique l'est d'office.
func (r DesignRequest) Topology() (*Topology, error) {
	t := &Topology{}
	locals := 0
	for i, h := range r.Hosts {
		addr := strings.TrimSpace(h.Addr)
		if !addrRe.MatchString(addr) {
			return nil, fmt.Errorf("hôte n°%d : adresse %q invalide", i+1, addr)
		}
		name := strings.TrimSpace(h.Name)
		if name == "" {
			name = DefaultHostName(addr)
		}
		if h.Local {
			locals++
			t.Local = name
		}
		t.Hosts = append(t.Hosts, Host{Name: name, Addr: addr, Roles: h.Roles, Group: strings.TrimSpace(h.Group)})
	}
	if locals == 0 && len(t.Hosts) == 1 {
		t.Local, locals = t.Hosts[0].Name, 1
	}
	if locals != 1 {
		return nil, fmt.Errorf("désignez l'hôte sur lequel tourne ce launcher (un seul)")
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return t, nil
}

// Draft est la topologie telle qu'elle est à l'écran, sans la valider : le schéma se dessine pendant la saisie, avec des
// adresses encore vides et des noms à déduire. Elle ne sert jamais à installer.
func (r DesignRequest) Draft() *Topology {
	t := &Topology{}
	for i, h := range r.Hosts {
		addr, name := strings.TrimSpace(h.Addr), strings.TrimSpace(h.Name)
		switch {
		case name != "":
		case addr != "":
			name = DefaultHostName(addr)
		default:
			name = fmt.Sprintf("hôte %d", i+1)
		}
		var roles []string
		for _, role := range h.Roles {
			if knownRole(role) {
				roles = append(roles, role)
			}
		}
		if h.Local && t.Local == "" {
			t.Local = name
		}
		t.Hosts = append(t.Hosts, Host{Name: name, Addr: addr, Roles: roles, Group: strings.TrimSpace(h.Group)})
	}
	if t.Local == "" && len(t.Hosts) > 0 {
		t.Local = t.Hosts[0].Name
	}
	return t
}

// DesignRequestOf est l'inverse de Topology : la topologie donnée en ligne de commande préremplit l'interface.
func DesignRequestOf(t *Topology, email string) DesignRequest {
	r := DesignRequest{Email: email}
	for _, h := range t.Hosts {
		r.Hosts = append(r.Hosts, DesignHost{Name: h.Name, Addr: h.Addr, Roles: h.Roles, Group: h.Group, Local: h.Name == t.Local})
	}
	return r
}

type designState struct {
	mu          sync.Mutex
	code        string
	sessions    map[string]time.Time
	fails       int
	lockedUntil time.Time
}

// NewAccessCode produit un code d'accès lisible à voix haute (alphabet sans caractères ambigus), de la forme ABCD-EFGH.
func NewAccessCode() (string, error) {
	b := make([]byte, codeLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, 0, codeLength+1)
	for i, v := range b {
		if i == codeLength/2 {
			out = append(out, '-')
		}
		out = append(out, codeAlphabet[int(v)%len(codeAlphabet)])
	}
	return string(out), nil
}

func normalizeCode(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, strings.ToUpper(strings.TrimSpace(s)))
}

// check compare le code en temps constant ; cinq échecs de suite verrouillent les essais une minute.
func (d *designState) check(code string, now time.Time) (ok bool, lockedFor time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if now.Before(d.lockedUntil) {
		return false, d.lockedUntil.Sub(now)
	}
	if subtle.ConstantTimeCompare([]byte(normalizeCode(code)), []byte(normalizeCode(d.code))) == 1 {
		d.fails = 0
		return true, 0
	}
	if d.fails++; d.fails >= maxCodeFailures {
		d.fails, d.lockedUntil = 0, now.Add(codeLockout)
		return false, codeLockout
	}
	return false, 0
}

func (d *designState) open(now time.Time) string {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.sessions == nil {
		d.sessions = map[string]time.Time{}
	}
	for k, exp := range d.sessions {
		if now.After(exp) {
			delete(d.sessions, k)
		}
	}
	tok := randToken()
	d.sessions[tok] = now.Add(designSessionTTL)
	return tok
}

func (d *designState) valid(tok string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	exp, ok := d.sessions[tok]
	return ok && now.Before(exp)
}

func (l *listener) designRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /design", l.handleDesignPage)
	mux.HandleFunc("POST /design/login", l.handleDesignLogin)
	mux.HandleFunc("GET /design/api/state", l.api(l.handleDesignState))
	mux.HandleFunc("POST /design/api/restore", l.apiWith("application/octet-stream", maxRestoreBody, l.handleDesignRestore))
	mux.HandleFunc("POST /design/api/restore/clear", l.api(l.handleDesignRestoreClear))
	mux.HandleFunc("POST /design/api/diagram", l.api(l.handleDesignDiagram))
	mux.HandleFunc("POST /design/api/plan", l.api(l.handleDesignPlan))
	mux.HandleFunc("POST /design/api/deploy", l.api(l.handleDesignDeploy))
	mux.HandleFunc("GET /design/api/status", l.api(l.handleDesignStatus))
	mux.HandleFunc("POST /design/api/finish", l.api(l.handleDesignFinish))
}

func (l *listener) authenticated(r *http.Request) bool {
	c, err := r.Cookie(designCookie)
	return err == nil && l.design.valid(c.Value, l.opt.now())
}

// api protège un point d'entrée JSON : session ouverte avec le code, et pour une écriture, une requête qui vient de la page
// (origine, type JSON). Toute action de l'interface compte comme une activité : la fenêtre d'écoute se prolonge.
func (l *listener) api(h http.HandlerFunc) http.HandlerFunc {
	return l.apiWith("application/json", maxDesignBody, h)
}

// apiWith est api pour une écriture d'un autre type et d'une autre taille (le fichier d'une sauvegarde).
func (l *listener) apiWith(contentType string, limit int64, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !l.authenticated(r) {
			jsonError(w, http.StatusUnauthorized, "code d'accès requis")
			return
		}
		if r.Method != http.MethodGet {
			if !sameOrigin(r) || !strings.HasPrefix(r.Header.Get("Content-Type"), contentType) {
				jsonError(w, http.StatusForbidden, "requête refusée : elle ne vient pas de la page")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		l.touch()
		h(w, r)
	}
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func jsonReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// touch signale une activité : Listen repart pour une fenêtre entière tant qu'aucune installation n'a commencé.
func (l *listener) touch() {
	select {
	case l.activity <- struct{}{}:
	default:
	}
}

var (
	designTmpl = template.Must(template.New("design").Parse(designHTML))
	loginTmpl  = template.Must(template.New("login").Parse(pageHead + `</head><body><main>
<h1>GoProxify — concevoir l'infrastructure</h1>
<p>Cette interface installe des conteneurs sur ce serveur : elle équivaut à un accès root. Entrez le code d'accès affiché
dans la sortie du conteneur (<code>docker logs</code>, ou le terminal où vous l'avez lancé).</p>
{{if .Message}}<p class="err">{{.Message}}</p>{{end}}
<form method="post" action="/design/login"><p><input name="code" autocomplete="off" autofocus placeholder="ABCD-EFGH"
style="font-size:1.2rem;padding:10px;width:100%;box-sizing:border-box;text-transform:uppercase"></p>
<button type="submit">Ouvrir</button></form>
</main></body></html>`))
)

// securePage pose les en-têtes d'une page qui exécute un script : seul celui qui porte le nonce de la réponse peut tourner.
func securePage(w http.ResponseWriter, nonce string) {
	h := w.Header()
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-"+nonce+
		"'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	h.Set("Cache-Control", "no-store")
	h.Set("Referrer-Policy", "same-origin")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Type", "text/html; charset=utf-8")
}

func (l *listener) handleDesignPage(w http.ResponseWriter, r *http.Request) {
	if !l.authenticated(r) {
		secure(w, false)
		render(w, http.StatusOK, loginTmpl, map[string]any{"Message": ""})
		return
	}
	l.touch()
	nonce := randToken()
	securePage(w, nonce)
	_ = designTmpl.Execute(w, map[string]any{"Nonce": nonce, "CSS": template.CSS(launcherCSS)})
}

func (l *listener) handleDesignLogin(w http.ResponseWriter, r *http.Request) {
	secure(w, false)
	if !sameOrigin(r) {
		render(w, http.StatusForbidden, pageError, map[string]any{"Message": "Requête refusée : elle ne vient pas de la page de connexion."})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		render(w, http.StatusBadRequest, pageError, map[string]any{"Message": "Requête illisible."})
		return
	}
	now := l.opt.now()
	ok, locked := l.design.check(r.PostForm.Get("code"), now)
	if !ok {
		msg := "Code d'accès incorrect."
		status := http.StatusForbidden
		if locked > 0 {
			msg = fmt.Sprintf("Trop d'essais : réessayez dans %d s.", int(locked.Seconds())+1)
			status = http.StatusTooManyRequests
		}
		render(w, status, loginTmpl, map[string]any{"Message": msg})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: designCookie, Value: l.design.open(now), Path: "/design", HttpOnly: true, SameSite: http.SameSiteStrictMode,
		MaxAge: int(designSessionTTL.Seconds()),
	})
	l.touch()
	http.Redirect(w, r, "/design", http.StatusSeeOther)
}

func (l *listener) handleDesignState(w http.ResponseWriter, r *http.Request) {
	req := DesignRequest{Email: l.opt.InitialEmail}
	if l.opt.Initial != nil {
		req = DesignRequestOf(l.opt.Initial, l.opt.InitialEmail)
	}
	jsonReply(w, http.StatusOK, map[string]any{
		"request": req, "default_email": DefaultAdminEmail, "restore_email": RestoreAdminEmail, "registry": l.opt.Registry, "tag": l.opt.Tag, "message": l.opt.InitialNote,
	})
}

func (l *listener) readDesign(w http.ResponseWriter, r *http.Request) (*Topology, DesignRequest, bool) {
	var req DesignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "demande illisible")
		return nil, req, false
	}
	var (
		t   *Topology
		err error
	)
	if req.Restore != nil {
		// La topologie est celle de la sauvegarde, avec les identifiants de ses nœuds : en refaire une depuis l'écran
		// changerait les clés dérivées, que les hôtes en place ne reconnaîtraient plus.
		rst := l.restoredBackup()
		if rst == nil {
			jsonError(w, http.StatusBadRequest, "aucune sauvegarde lue : envoyez d'abord le fichier et sa clé")
			return nil, req, false
		}
		if t, err = rst.TopologyFromBackup(strings.TrimSpace(req.Restore.Local), strings.TrimSpace(req.Restore.Addr)); err == nil {
			err = t.Validate()
		}
	} else {
		t, err = req.Topology()
	}
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return nil, req, false
	}
	return t, req, true
}

func (l *listener) restoredBackup() *Restored {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.restored
}

// handleDesignRestore lit le fichier d'une sauvegarde (corps) avec sa clé (en-tête X-Backup-Key) et la garde en mémoire
// pour l'installation : rien n'est écrit sur disque. Elle rend les hôtes de la sauvegarde, pour que la page demande lequel
// est cette machine.
func (l *listener) handleDesignRestore(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	started := l.started
	l.mu.Unlock()
	if started {
		jsonError(w, http.StatusConflict, "une installation est déjà en cours sur ce serveur")
		return
	}
	data, err := io.ReadAll(r.Body)
	if err != nil {
		jsonError(w, http.StatusRequestEntityTooLarge, "fichier illisible ou trop volumineux (512 Mio au plus)")
		return
	}
	rst, err := ReadBackup(data, r.Header.Get("X-Backup-Key"))
	if err != nil {
		jsonError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if rst.Architecture == nil {
		jsonError(w, http.StatusUnprocessableEntity, "la sauvegarde ne contient pas architecture.json : il n'y a pas d'infrastructure à reconstruire")
		return
	}
	topo := TopologyFromArchitecture(rst.Architecture)
	if len(topo.Hosts) == 0 {
		jsonError(w, http.StatusUnprocessableEntity, "architecture.json de la sauvegarde ne déclare aucun hôte")
		return
	}
	l.mu.Lock()
	l.restored = rst
	l.mu.Unlock()
	fp := ""
	if rst.Cert != nil {
		fp = rst.Cert.Fingerprint
	}
	jsonReply(w, http.StatusOK, map[string]any{"hosts": hostRows(topo.Hosts), "has_cert": rst.Cert != nil, "fingerprint": fp})
}

// handleDesignDiagram dessine l'infrastructure décrite à l'écran : le texte Mermaid et le même schéma en SVG. La saisie n'a
// pas à être valide, le schéma se met à jour pendant qu'on la complète ; une sauvegarde lue donne en revanche la topologie
// du fichier. Rien n'est créé ni lu sur le démon.
func (l *listener) handleDesignDiagram(w http.ResponseWriter, r *http.Request) {
	var req DesignRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "demande illisible")
		return
	}
	var t *Topology
	if req.Restore != nil {
		rst := l.restoredBackup()
		if rst == nil {
			jsonError(w, http.StatusBadRequest, "aucune sauvegarde lue")
			return
		}
		var err error
		if t, err = rst.TopologyFromBackup(strings.TrimSpace(req.Restore.Local), strings.TrimSpace(req.Restore.Addr)); err != nil {
			jsonError(w, http.StatusBadRequest, err.Error())
			return
		}
	} else {
		t = req.Draft()
	}
	jsonReply(w, http.StatusOK, map[string]string{"mermaid": t.Mermaid(), "svg": t.SVG()})
}

// handleDesignRestoreClear abandonne la sauvegarde lue (et les secrets qu'elle a mis en mémoire).
func (l *listener) handleDesignRestoreClear(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	l.restored = nil
	l.mu.Unlock()
	jsonReply(w, http.StatusOK, map[string]bool{"cleared": true})
}

// handleDesignPlan : simulation. Elle valide, regarde ce que le démon a déjà, et n'écrit rien.
func (l *listener) handleDesignPlan(w http.ResponseWriter, r *http.Request) {
	t, req, ok := l.readDesign(w, r)
	if !ok {
		return
	}
	rep, err := Run(r.Context(), l.opt.API, l.designOptions(t, req, true, io.Discard))
	if err != nil {
		jsonError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	jsonReply(w, http.StatusOK, map[string]any{
		"admin_url": rep.AdminURL, "pull": orEmpty(rep.Plan.Pull), "networks": orEmpty(rep.Plan.Networks), "volumes": orEmpty(rep.Plan.Volumes),
		"pending": hostRows(rep.Pending),
	})
}

func (l *listener) designOptions(t *Topology, req DesignRequest, dry bool, out io.Writer) Options {
	opt := Options{
		Topology: t, AdminEmail: strings.TrimSpace(req.Email), AdminPassword: l.opt.AdminPassword,
		Registry: l.opt.Registry, Tag: l.opt.Tag, TZ: l.opt.TZ, DryRun: dry, Out: out,
	}
	if req.Restore != nil {
		opt.Restore = l.restoredBackup()
	}
	return opt
}

// handleDesignDeploy lance l'installation de l'hôte local. Elle est exclusive avec le déclenchement par QR code : un
// launcher n'installe qu'une fois.
func (l *listener) handleDesignDeploy(w http.ResponseWriter, r *http.Request) {
	t, req, ok := l.readDesign(w, r)
	if !ok {
		return
	}
	l.mu.Lock()
	if l.started {
		l.mu.Unlock()
		jsonError(w, http.StatusConflict, "une installation est déjà en cours sur ce serveur")
		return
	}
	l.started, l.done, l.failure, l.steps = true, false, "", nil
	l.mu.Unlock()
	go l.runDesign(t, req)
	jsonReply(w, http.StatusAccepted, map[string]bool{"started": true})
}

func (l *listener) runDesign(t *Topology, req DesignRequest) {
	rep, err := Run(l.ctx, l.opt.API, l.designOptions(t, req, false, lineWriter{l.step}))
	l.mu.Lock()
	if err != nil {
		// Le moteur a défait ce qu'il avait créé : l'utilisateur peut corriger et recommencer depuis la même page.
		l.started, l.failure = false, err.Error()
		l.mu.Unlock()
		fmt.Fprintf(l.opt.Out, "Installation échouée : %v\n", err)
		l.touch()
		return
	}
	l.done, l.dreport, l.lingerFor = true, rep, designLinger
	l.restored = nil // l'installation est faite : le secret racine et la clé n'ont plus à rester en mémoire
	l.mu.Unlock()
	fmt.Fprint(l.opt.Out, rep.Summary())
	close(l.doneCh)
}

// orEmpty : la page lit ces listes avec .length, une liste vide doit être [] et non null.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

type hostRow struct {
	Name  string   `json:"name"`
	Addr  string   `json:"addr"`
	Roles []string `json:"roles"`
}

func hostRows(hs []Host) []hostRow {
	out := make([]hostRow, 0, len(hs))
	for _, h := range hs {
		out = append(out, hostRow{h.Name, h.Addr, h.Roles})
	}
	return out
}

func (l *listener) handleDesignStatus(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := map[string]any{"started": l.started, "done": l.done, "steps": append([]string{}, l.steps...), "error": l.failure}
	if l.dreport != nil {
		st["report"] = map[string]any{
			"admin_url": l.dreport.AdminURL, "fingerprint": l.dreport.Fingerprint, "email": l.dreport.AdminEmail,
			"password": l.dreport.AdminPassword, "backup_key": l.dreport.BackupKey, "pending": hostRows(l.dreport.Pending), "containers": orEmpty(l.dreport.Containers),
			"restored": l.dreport.Restored, "kept_certificate": l.dreport.KeptCertificate,
		}
	}
	jsonReply(w, http.StatusOK, st)
}

// handleDesignFinish rend la main : le launcher sort sans attendre la fin du délai de lecture.
func (l *listener) handleDesignFinish(w http.ResponseWriter, r *http.Request) {
	l.mu.Lock()
	done := l.done
	l.mu.Unlock()
	if !done {
		jsonError(w, http.StatusConflict, "aucune installation terminée")
		return
	}
	l.finishOnce.Do(func() { close(l.finishCh) })
	jsonReply(w, http.StatusOK, map[string]bool{"finished": true})
}

// lineWriter transmet chaque ligne écrite par le moteur à l'avancement affiché.
type lineWriter struct{ fn func(string) }

func (w lineWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(string(p), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			w.fn(line)
		}
	}
	return len(p), nil
}
