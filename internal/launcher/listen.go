// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package launcher

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/deploy"
)

// Valeurs par défaut du mode attente.
const (
	DefaultListenPort   = 8080
	DefaultListenAddr   = ":8080"
	DefaultListenWindow = 15 * time.Minute
	defaultLinger       = 20 * time.Second
	nonceTTL            = 10 * time.Minute
	maxNonces           = 64
)

// ErrWindowElapsed : personne n'a déclenché l'installation avant la fin de la fenêtre d'écoute.
var ErrWindowElapsed = errors.New("fenêtre d'écoute écoulée sans déclenchement")

var tokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

// ListenOptions règle le mode attente : le launcher écoute, un scan de QR code ouvre une page de confirmation, et le
// clic lance l'installation (ADR 0019, section 4).
type ListenOptions struct {
	// Addr est l'adresse d'écoute (DefaultListenAddr par défaut). Listener la remplace quand il est donné (tests).
	Addr     string
	Listener net.Listener
	// Window borne l'attente d'un déclenchement (DefaultListenWindow par défaut). Une installation commencée va à son terme.
	Window time.Duration
	// PinnedAdmin (https://hôte:port) et PinnedFingerprint épinglent l'Admin attendu : un lien qui en désigne un autre
	// est refusé. Avec les deux, un lien qui y correspond n'attend pas de clic (la page se valide seule, par un POST).
	PinnedAdmin       string
	PinnedFingerprint string
	API               deploy.API
	Out               io.Writer
	// Linger est le temps pendant lequel la page d'état reste servie après la fin, pour que le téléphone la lise.
	Linger time.Duration

	// Réglages de l'interface de conception (design.go), qui tourne dans tout launcher en attente.
	// AccessCode est le code demandé à son ouverture ; aléatoire s'il est vide. Initial préremplit l'interface (indicateurs
	// de la ligne de commande), InitialNote dit pourquoi elle s'ouvre. AdminPassword, Registry, Tag et TZ s'appliquent à
	// l'installation qu'elle lance.
	AccessCode                       string
	Initial                          *Topology
	InitialEmail, InitialNote        string
	AdminPassword, Registry, Tag, TZ string
	// Now sert aux tests.
	Now func() time.Time
}

type trigger struct {
	admin, token, fp, host, roles string
	expires                       time.Time
}

type listener struct {
	opt ListenOptions
	ctx context.Context

	mu      sync.Mutex
	nonces  map[string]trigger
	started bool
	// adminURL est l'Admin que l'installation en cours rejoint : la page d'état y renvoie une fois terminée.
	adminURL string
	steps    []string
	done    bool
	err     error
	report  *JoinReport
	doneCh  chan struct{}

	// Interface de conception : session, rapport de l'installation qu'elle a lancée, dernier échec (elle peut réessayer).
	design     designState
	dreport    *Report
	restored   *Restored // sauvegarde lue par l'interface, gardée en mémoire jusqu'à l'installation
	failure    string
	lingerFor  time.Duration
	activity   chan struct{}
	finishCh   chan struct{}
	finishOnce sync.Once
}

func (o ListenOptions) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

// normalizeAdmin ne garde d'une adresse d'Admin que https://hôte[:port] ; tout le reste est refusé.
func normalizeAdmin(s string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("adresse de l'Admin invalide : https://hôte[:port] attendu")
	}
	return "https://" + strings.ToLower(u.Host), nil
}

// Listen attend un déclenchement, installe l'hôte, puis rend la main. Il rend nil si l'installation a abouti, ErrWindowElapsed si
// personne ne l'a déclenchée à temps, l'erreur de l'installation sinon (qui a été défaite).
func Listen(ctx context.Context, opt ListenOptions) error {
	if opt.API == nil {
		return errors.New("API Docker manquante")
	}
	if opt.Window <= 0 {
		opt.Window = DefaultListenWindow
	}
	if opt.Linger <= 0 {
		opt.Linger = defaultLinger
	}
	if opt.Out == nil {
		opt.Out = io.Discard
	}
	var err error
	if opt.PinnedAdmin != "" {
		if opt.PinnedAdmin, err = normalizeAdmin(opt.PinnedAdmin); err != nil {
			return err
		}
	}
	if opt.PinnedFingerprint, err = NormalizeFingerprint(opt.PinnedFingerprint); err != nil {
		return err
	}

	ln := opt.Listener
	if ln == nil {
		addr := opt.Addr
		if addr == "" {
			addr = DefaultListenAddr
		}
		if ln, err = net.Listen("tcp", addr); err != nil {
			return fmt.Errorf("écoute sur %s : %w", addr, err)
		}
	}

	code := opt.AccessCode
	if code == "" {
		if code, err = NewAccessCode(); err != nil {
			return err
		}
	}
	l := &listener{
		opt: opt, ctx: ctx, nonces: map[string]trigger{}, doneCh: make(chan struct{}), lingerFor: opt.Linger,
		design: designState{code: code}, activity: make(chan struct{}, 1), finishCh: make(chan struct{}),
	}
	srv := &http.Server{Handler: l.routes(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	shutdown := func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}
	defer shutdown()

	fmt.Fprintf(opt.Out, "En attente d'un déclenchement sur %s jusqu'à %s (scannez le QR code de l'Admin).\n",
		ln.Addr(), opt.now().Add(opt.Window).Format("15:04"))
	if opt.InitialNote != "" {
		fmt.Fprintln(opt.Out, opt.InitialNote)
	}
	fmt.Fprintf(opt.Out, "Interface de conception : http://<adresse de cet hôte>:%s/design\nCode d'accès : %s\n", portOf(ln.Addr()), code)

	window := time.NewTimer(opt.Window)
	defer window.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-l.activity:
			// Une personne conçoit l'infrastructure : la fenêtre repart tant que rien n'est lancé.
			l.mu.Lock()
			started := l.started
			l.mu.Unlock()
			if !started {
				if !window.Stop() {
					select {
					case <-window.C:
					default:
					}
				}
				window.Reset(opt.Window)
			}
		case <-window.C:
			l.mu.Lock()
			started := l.started
			l.mu.Unlock()
			if !started {
				return ErrWindowElapsed
			}
			window.Reset(time.Hour) // une installation commencée va à son terme
		case <-l.doneCh:
			l.mu.Lock()
			linger := l.lingerFor
			l.mu.Unlock()
			select {
			case <-time.After(linger):
			case <-l.finishCh:
			case <-ctx.Done():
			}
			l.mu.Lock()
			err := l.err
			l.mu.Unlock()
			return err
		}
	}
}

func (l *listener) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", l.handleWaiting)
	mux.HandleFunc("GET /join", l.handleConfirm)
	mux.HandleFunc("POST /join", l.handleStart)
	mux.HandleFunc("GET /status", l.handleStatus)
	l.designRoutes(mux)
	return mux
}

func portOf(a net.Addr) string {
	if _, port, err := net.SplitHostPort(a.String()); err == nil {
		return port
	}
	return fmt.Sprint(DefaultListenPort)
}

func secure(w http.ResponseWriter, allowScript bool) {
	h := w.Header()
	script := ""
	if allowScript {
		script = "script-src 'unsafe-inline'; "
	}
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; "+script+"form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	h.Set("Cache-Control", "no-store")
	// Pas « no-referrer » : le navigateur enverrait « Origin: null » avec les formulaires, que sameOrigin refuse.
	h.Set("Referrer-Policy", "same-origin")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Type", "text/html; charset=utf-8")
}

func (l *listener) handleWaiting(w http.ResponseWriter, r *http.Request) {
	secure(w, false)
	render(w, http.StatusOK, pageWaiting, nil)
}

// handleConfirm : GET /join. Il n'a aucun effet : il montre à qui l'installation serait confiée et attend un POST.
func (l *listener) handleConfirm(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	admin, err := normalizeAdmin(q.Get("admin"))
	fp, ferr := NormalizeFingerprint(q.Get("fp"))
	token := q.Get("token")
	secure(w, false)
	if err != nil || ferr != nil || !tokenRe.MatchString(token) {
		render(w, http.StatusBadRequest, pageError, map[string]any{"Message": "Lien d'installation invalide."})
		return
	}
	if l.opt.PinnedAdmin != "" && admin != l.opt.PinnedAdmin {
		render(w, http.StatusForbidden, pageError, map[string]any{"Message": "Ce lien désigne un autre Admin que celui attendu par ce serveur : refusé."})
		return
	}
	if l.opt.PinnedFingerprint != "" && fp != l.opt.PinnedFingerprint {
		render(w, http.StatusForbidden, pageError, map[string]any{"Message": "Ce lien porte une autre empreinte de certificat que celle attendue par ce serveur : refusé."})
		return
	}

	l.mu.Lock()
	if l.started {
		l.mu.Unlock()
		http.Redirect(w, r, "/status", http.StatusSeeOther)
		return
	}
	l.pruneNoncesLocked()
	if len(l.nonces) >= maxNonces {
		l.mu.Unlock()
		render(w, http.StatusTooManyRequests, pageError, map[string]any{"Message": "Trop de demandes en attente, réessayez dans un instant."})
		return
	}
	nonce := randToken()
	l.nonces[nonce] = trigger{admin: admin, token: token, fp: fp, host: clip(q.Get("host")), roles: clip(q.Get("roles")),
		expires: l.opt.now().Add(nonceTTL)}
	l.mu.Unlock()

	auto := l.opt.PinnedAdmin != "" && l.opt.PinnedFingerprint != ""
	if auto {
		secure(w, true)
	}
	render(w, http.StatusOK, pageConfirm, map[string]any{
		"Admin": admin, "Fingerprint": groupFingerprint(fp), "Host": clip(q.Get("host")), "Roles": clip(q.Get("roles")),
		"Nonce": nonce, "Until": l.opt.now().Add(l.opt.Window).Format("15:04"), "Auto": auto,
	})
}

// handleStart : POST /join. C'est le seul endroit qui déclenche, et seulement avec le nonce que le GET vient de donner.
func (l *listener) handleStart(w http.ResponseWriter, r *http.Request) {
	secure(w, false)
	if !sameOrigin(r) {
		render(w, http.StatusForbidden, pageError, map[string]any{"Message": "Requête refusée : elle ne vient pas de la page de confirmation."})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		render(w, http.StatusBadRequest, pageError, map[string]any{"Message": "Requête illisible."})
		return
	}

	l.mu.Lock()
	t, ok := l.nonces[r.PostForm.Get("nonce")]
	delete(l.nonces, r.PostForm.Get("nonce"))
	switch {
	case l.started:
		l.mu.Unlock()
		render(w, http.StatusConflict, pageError, map[string]any{"Message": "Une installation est déjà en cours sur ce serveur."})
		return
	case !ok || l.opt.now().After(t.expires):
		l.mu.Unlock()
		render(w, http.StatusForbidden, pageError, map[string]any{"Message": "Confirmation expirée : rouvrez le lien depuis le QR code."})
		return
	}
	l.started = true
	l.adminURL = t.admin
	l.mu.Unlock()

	go l.run(t)
	http.Redirect(w, r, "/status", http.StatusSeeOther)
}

func (l *listener) run(t trigger) {
	l.step("Récupération de la description auprès de l'Admin")
	rep, err := Join(l.ctx, l.opt.API, t.admin+"/api/v1/join/"+t.token, t.fp, func(e deploy.Event) {
		l.step(stepLabel(e))
	})
	l.mu.Lock()
	l.done, l.err, l.report = true, err, rep
	l.mu.Unlock()
	if err != nil {
		fmt.Fprintf(l.opt.Out, "Installation échouée : %v\n", err)
	} else {
		fmt.Fprintf(l.opt.Out, "Installation terminée : %s\n", strings.Join(rep.Containers, ", "))
	}
	close(l.doneCh)
}

func (l *listener) step(s string) {
	l.mu.Lock()
	l.steps = append(l.steps, s)
	l.mu.Unlock()
	fmt.Fprintln(l.opt.Out, "  "+s)
}

func (l *listener) handleStatus(w http.ResponseWriter, r *http.Request) {
	secure(w, false)
	l.mu.Lock()
	data := map[string]any{"Steps": append([]string(nil), l.steps...), "Started": l.started, "Done": l.done}
	if l.err != nil {
		data["Error"] = l.err.Error()
	}
	if l.adminURL != "" {
		data["Admin"] = l.adminURL
	}
	if l.report != nil {
		data["Containers"] = strings.Join(l.report.Containers, ", ")
		data["Host"] = l.report.Host
	}
	l.mu.Unlock()
	render(w, http.StatusOK, pageStatus, data)
}

func (l *listener) pruneNoncesLocked() {
	now := l.opt.now()
	for k, t := range l.nonces {
		if now.After(t.expires) {
			delete(l.nonces, k)
		}
	}
}

// sameOrigin refuse un POST qui ne vient pas de cette page : une page quelconque ouverte sur le réseau local ne doit pas
// pouvoir déclencher l'installation.
func sameOrigin(r *http.Request) bool {
	if s := r.Header.Get("Sec-Fetch-Site"); s != "" && s != "same-origin" && s != "none" {
		return false
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		return err == nil && u.Host == r.Host
	}
	return true
}

func randToken() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// clip borne un texte annoncé par le lien (nom d'hôte, rôles) : il n'est qu'affiché, jamais cru.
func clip(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

func groupFingerprint(fp string) string {
	if fp == "" {
		return ""
	}
	parts := make([]string, 0, len(fp)/2)
	for i := 0; i+1 < len(fp); i += 2 {
		parts = append(parts, strings.ToUpper(fp[i:i+2]))
	}
	return strings.Join(parts, ":")
}

func stepLabel(e deploy.Event) string {
	verbs := map[string]string{
		"pull": "Téléchargement de l'image", "network": "Réseau", "volume": "Volume", "create": "Création de",
		"files": "Fichiers de", "start": "Démarrage de", "healthy": "Attente de santé de", "rollback": "Retour arrière :",
	}
	if v, ok := verbs[e.Step]; ok {
		return v + " " + e.Name
	}
	return e.Step + " " + e.Name
}

func render(w http.ResponseWriter, status int, t *template.Template, data any) {
	w.WriteHeader(status)
	_ = t.Execute(w, data)
}

// launcherCSS est le style commun de toutes les pages du launcher (clair et sombre, sans ressource externe).
//
//go:embed launcher.css
var launcherCSS string

var pageHead = `<!doctype html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>GoProxify — installation</title>
<style>` + launcherCSS + `</style>`

var (
	pageWaiting = template.Must(template.New("w").Parse(pageHead + `</head><body><main>
<h1>GoProxify</h1><p>Ce serveur attend un lien d'installation de votre Admin (QR code de la fiche de l'hôte).</p>
<p><small>Pas encore d'Admin ? <a href="/design">Concevoir l'infrastructure ici</a> (code d'accès affiché dans la sortie du conteneur).</small></p></main></body></html>`))

	pageError = template.Must(template.New("e").Parse(pageHead + `</head><body><main>
<h1>GoProxify</h1><p class="err">{{.Message}}</p></main></body></html>`))

	pageConfirm = template.Must(template.New("c").Parse(pageHead + `</head><body><main>
<h1>Installer GoProxify sur ce serveur ?</h1>
<p>Ce lien demande à ce serveur de s'installer depuis l'Admin ci-dessous. <b>Vérifiez que c'est le vôtre</b> : il lui
confiera des conteneurs à lancer.</p>
<dl><dt>Admin</dt><dd>{{.Admin}}</dd>
<dt>Empreinte</dt><dd>{{if .Fingerprint}}{{.Fingerprint}}{{else}}aucune : certificat public, vérifié par le système{{end}}</dd>
{{if .Host}}<dt>Hôte annoncé</dt><dd>{{.Host}}{{if .Roles}} ({{.Roles}}){{end}}</dd>{{end}}</dl>
<p><small>Comparez l'empreinte à celle de l'Admin (écran du launcher qui l'a installé). Cette page reste valable jusqu'à {{.Until}}.</small></p>
<form method="post" action="/join" id="f"><input type="hidden" name="nonce" value="{{.Nonce}}"><button type="submit">Installer</button></form>
{{if .Auto}}<script>document.getElementById("f").submit()</script>{{end}}
</main></body></html>`))

	pageStatus = template.Must(template.New("s").Parse(pageHead + `{{if and .Started (not .Done)}}<meta http-equiv="refresh" content="2">{{end}}{{if and .Done .Admin (not .Error)}}<meta http-equiv="refresh" content="5;url={{.Admin}}">{{end}}</head><body><main>
<h1>Installation{{if .Host}} de {{.Host}}{{end}}</h1>
{{if not .Started}}<p>Aucune installation n'a été lancée.</p>{{end}}
{{if .Steps}}<ul>{{range .Steps}}<li>{{.}}</li>{{end}}</ul>{{end}}
{{if .Error}}<p class="err">Échec : {{.Error}}</p><p><small>Ce qui avait été créé a été retiré. Le ticket reste valable tant qu'il n'a pas expiré : rouvrez le lien pour réessayer.</small></p>
{{else if .Done}}<p class="ok">Terminé : {{.Containers}}.</p><p><small>Les composants rejoignent l'Admin d'eux-mêmes.</small></p>
{{if .Admin}}<p><a href="{{.Admin}}">Ouvrir l'Admin</a> <small>(redirection dans quelques secondes ; le certificat est auto-signé, comparez son empreinte à celle de l'Admin)</small></p>{{end}}
{{else if .Started}}<p>En cours…</p>{{end}}
</main></body></html>`))
)
