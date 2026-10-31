// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/archstore"
	"github.com/vincamok/goproxify/internal/deploy"
	"github.com/vincamok/goproxify/internal/launcher"
)

var hostsDBSeq atomic.Int32

type hostsFixture struct {
	h    *api.HostsHandler
	db   *sql.DB
	mux  *http.ServeMux
	now  time.Time
	cert *launcher.AdminCert
	root string
}

// newHostsFixture déclare, comme le launcher le fait, un Admin avec sa passerelle (main) et deux hôtes : nas (un Agent)
// et vps (une passerelle).
func newHostsFixture(t *testing.T) *hostsFixture {
	t.Helper()
	db, err := sql.Open("sqlite", fmt.Sprintf("file:hosts_test_%d?mode=memory&cache=shared", hostsDBSeq.Add(1)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE nodes (id TEXT PRIMARY KEY, node_name TEXT UNIQUE NOT NULL, role TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'online')`); err != nil {
		t.Fatal(err)
	}

	topo := &launcher.Topology{Local: "main", Hosts: []launcher.Host{
		{Name: "main", Addr: "192.168.1.10", Roles: []string{"admin", "edge"}},
		{Name: "nas", Addr: "192.168.1.50", Roles: []string{"agent"}},
		{Name: "vps", Addr: "203.0.113.5", Roles: []string{"edge"}},
	}}
	dir := t.TempDir()
	store := archstore.New(dir)
	for _, n := range topo.Architecture().Nodes {
		if err := store.Upsert(n); err != nil {
			t.Fatal(err)
		}
	}
	cert, err := launcher.NewAdminCert([]string{"192.168.1.10"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	certFile := filepath.Join(dir, "admin.crt")
	if err := os.WriteFile(certFile, []byte(cert.CertPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	f := &hostsFixture{db: db, now: time.Now().UTC().Truncate(time.Second), cert: cert, root: "root-secret-for-tests"}
	f.h = &api.HostsHandler{
		DB: db, Arch: store, Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
		PublicURL: func(*http.Request) string { return "https://192.168.1.10:9443" },
		Root:      func() string { return f.root },
		CertFile:  func() string { return certFile },
		Registry:  "reg.example/gpx", Tag: "v1", TZ: "Europe/Paris",
		Now: func() time.Time { return f.now },
	}
	f.mux = http.NewServeMux()
	f.mux.HandleFunc("GET /api/v1/hosts", f.h.ServeList)
	f.mux.HandleFunc("POST /api/v1/hosts/{name}/join-ticket", f.h.ServeCreateTicket)
	f.mux.HandleFunc("GET /api/v1/join/{token}", f.h.ServeSpec)
	return f
}

func (f *hostsFixture) do(method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

func (f *hostsFixture) ticket(t *testing.T, host string) api.JoinTicket {
	t.Helper()
	rec := f.do(http.MethodPost, "/api/v1/hosts/"+host+"/join-ticket")
	if rec.Code != http.StatusOK {
		t.Fatalf("ticket de %s : %d %s", host, rec.Code, rec.Body.String())
	}
	var tk api.JoinTicket
	if err := json.Unmarshal(rec.Body.Bytes(), &tk); err != nil {
		t.Fatal(err)
	}
	return tk
}

func TestHostsListShowsPendingAndJoinedHosts(t *testing.T) {
	f := newHostsFixture(t)
	_, _ = f.db.Exec(`INSERT INTO nodes(id, node_name, role, status) VALUES('1', 'main-edge', 'edge', 'online')`)

	rec := f.do(http.MethodGet, "/api/v1/hosts")
	if rec.Code != http.StatusOK {
		t.Fatalf("liste : %d %s", rec.Code, rec.Body.String())
	}
	var rows []api.HostRow
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	by := map[string]api.HostRow{}
	for _, r := range rows {
		by[r.Name] = r
	}
	if len(rows) != 3 || by["main"].Status != "joined" || by["nas"].Status != "pending" || by["vps"].Status != "pending" {
		t.Fatalf("hôtes = %+v", rows)
	}
	if by["nas"].Addr != "192.168.1.50" || by["nas"].Nodes[0].Name != "goproxify-agent" || by["nas"].Nodes[0].Status != "declared" {
		t.Errorf("nas = %+v", by["nas"])
	}
	if by["nas"].Ticket != nil {
		t.Error("aucun ticket avant d'en demander un")
	}

	f.ticket(t, "nas")
	rec = f.do(http.MethodGet, "/api/v1/hosts")
	_ = json.Unmarshal(rec.Body.Bytes(), &rows)
	for _, r := range rows {
		if r.Name == "nas" && (r.Ticket == nil || r.Ticket.ExpiresAt != f.now.Add(15*time.Minute).Format(time.RFC3339)) {
			t.Errorf("le ticket en cours doit paraître, avec son échéance : %+v", r.Ticket)
		}
	}
	if strings.Contains(rec.Body.String(), "token") {
		t.Error("la liste ne doit jamais révéler un jeton")
	}
}

func TestJoinTicketLastsFifteenMinutesAndReplacesThePreviousOne(t *testing.T) {
	f := newHostsFixture(t)

	first := f.ticket(t, "nas")
	if first.ExpiresAt != f.now.Add(15*time.Minute).Format(time.RFC3339) || first.NodeNames[0] != "goproxify-agent" {
		t.Errorf("ticket = %+v", first)
	}
	if first.SpecURL != "https://192.168.1.10:9443/api/v1/join/"+first.Token {
		t.Errorf("spec_url = %q", first.SpecURL)
	}
	if first.Fingerprint != f.cert.Fingerprint {
		t.Errorf("l'empreinte donnée doit être celle du certificat de l'Admin : %q", first.Fingerprint)
	}

	second := f.ticket(t, "nas")
	if second.Token == first.Token {
		t.Fatal("chaque affichage crée un nouveau ticket")
	}
	if rec := f.do(http.MethodGet, "/api/v1/join/"+first.Token); rec.Code != http.StatusNotFound {
		t.Errorf("l'ancien ticket doit cesser de valoir : %d", rec.Code)
	}
	if rec := f.do(http.MethodGet, "/api/v1/join/"+second.Token); rec.Code != http.StatusOK {
		t.Errorf("le nouveau ticket doit valoir : %d", rec.Code)
	}
	var n int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM bootstrap_tickets WHERE host_name='nas'`).Scan(&n)
	if n != 1 {
		t.Errorf("un seul ticket par hôte, trouvé %d", n)
	}

	f.now = f.now.Add(16 * time.Minute)
	if rec := f.do(http.MethodGet, "/api/v1/join/"+second.Token); rec.Code != http.StatusNotFound {
		t.Errorf("le ticket expire après 15 minutes : %d", rec.Code)
	}
}

func TestJoinTicketRefusals(t *testing.T) {
	f := newHostsFixture(t)
	if rec := f.do(http.MethodPost, "/api/v1/hosts/absent/join-ticket"); rec.Code != http.StatusNotFound {
		t.Errorf("hôte inconnu : %d", rec.Code)
	}
	_, _ = f.db.Exec(`INSERT INTO nodes(id, node_name, role, status) VALUES('2', 'vps-edge', 'edge', 'online')`)
	if rec := f.do(http.MethodPost, "/api/v1/hosts/vps/join-ticket"); rec.Code != http.StatusConflict {
		t.Errorf("hôte déjà intégré : %d", rec.Code)
	}
}

func TestJoinSpecIsTheHostDescriptionWithDerivedKeys(t *testing.T) {
	f := newHostsFixture(t)
	tk := f.ticket(t, "vps")

	rec := f.do(http.MethodGet, "/api/v1/join/"+tk.Token)
	if rec.Code != http.StatusOK {
		t.Fatalf("description : %d %s", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
	var spec deploy.HostSpec
	if err := json.Unmarshal(rec.Body.Bytes(), &spec); err != nil {
		t.Fatal(err)
	}
	if err := spec.Validate(nil); err != nil {
		t.Fatalf("la description servie doit être valide : %v", err)
	}
	if len(spec.Containers) != 1 || spec.Containers[0].Image != "reg.example/gpx/edge:v1" || spec.Containers[0].Env["TZ"] != "Europe/Paris" {
		t.Fatalf("description = %+v", spec.Containers)
	}
	if strings.Contains(rec.Body.String(), f.root) {
		t.Error("la description ne doit jamais contenir le secret racine")
	}
	env := spec.Containers[0].Env
	if env["GPX_EDGE_CHANNEL_KEY"] == "" || env["GPX_AGENT_PAIRING_KEY"] == "" {
		t.Errorf("clés dérivées absentes : %v", env)
	}
	hub := false
	for _, p := range spec.Containers[0].Ports {
		hub = hub || p.ContainerPort == 8000
	}
	if !hub {
		t.Error("une passerelle distante publie son hub : c'est par lui que l'Admin la joint")
	}

	// Une description sans secret racine ne peut pas être servie.
	f.root = ""
	if rec := f.do(http.MethodGet, "/api/v1/join/"+tk.Token); rec.Code != http.StatusInternalServerError {
		t.Errorf("sans secret racine : %d", rec.Code)
	}
}

func TestJoinSpecRefusesUnknownAndForeignTickets(t *testing.T) {
	f := newHostsFixture(t)
	if rec := f.do(http.MethodGet, "/api/v1/join/nimporte"); rec.Code != http.StatusNotFound {
		t.Errorf("jeton inconnu : %d", rec.Code)
	}
	// Un ticket d'intégration ordinaire (curl|bash) ne donne pas accès aux clés d'un hôte.
	_, _ = f.db.Exec(`INSERT INTO bootstrap_tickets(token, host_name, payload, expires_at) VALUES('autre', 'nas', '{"compose_text":"x"}', ?)`,
		f.now.Add(time.Hour).UTC().Format("2006-01-02 15:04:05"))
	if rec := f.do(http.MethodGet, "/api/v1/join/autre"); rec.Code != http.StatusNotFound {
		t.Errorf("ticket d'une autre nature : %d", rec.Code)
	}
}

func TestJoinTicketGrantsAutoAcceptUntilItsNodesArrive(t *testing.T) {
	f := newHostsFixture(t)
	if api.NodeAutoAccept(f.db, "goproxify-agent") {
		t.Fatal("sans ticket, un nœud déclaré attend l'approbation")
	}
	tk := f.ticket(t, "nas")
	if !api.NodeAutoAccept(f.db, "goproxify-agent") {
		t.Fatal("le ticket valide accepte les nœuds de l'hôte")
	}
	if api.NodeAutoAccept(f.db, "autre-agent") {
		t.Error("le ticket ne couvre que les nœuds de son hôte")
	}

	// Lire la description ne consomme pas le ticket : un échec en route se relance avec le même.
	f.do(http.MethodGet, "/api/v1/join/"+tk.Token)
	if rec := f.do(http.MethodGet, "/api/v1/join/"+tk.Token); rec.Code != http.StatusOK {
		t.Fatalf("relecture : %d", rec.Code)
	}

	// Il l'est quand les nœuds arrivent.
	api.ConsumeBootstrapTicket(f.db, "goproxify-agent")
	if api.NodeAutoAccept(f.db, "goproxify-agent") {
		t.Error("le ticket est à usage unique")
	}
	if rec := f.do(http.MethodGet, "/api/v1/join/"+tk.Token); rec.Code != http.StatusNotFound {
		t.Errorf("le ticket consommé ne sert plus : %d", rec.Code)
	}
}

func TestJoinTicketOfAHostWithTwoNodesIsConsumedWhenBothArrive(t *testing.T) {
	f := newHostsFixture(t)
	// vps porte aussi un Agent : deux nœuds à attendre.
	_ = f.h.Arch.Upsert(archstore.NodeEntry{ID: "dn_a", Role: "agent", Name: "vps-agent",
		Config: json.RawMessage(`{"host":"vps","reachable_host":"203.0.113.5","target_edge":"vps-edge"}`)})
	tk := f.ticket(t, "vps")
	if len(tk.NodeNames) != 2 {
		t.Fatalf("nœuds du ticket = %v", tk.NodeNames)
	}

	api.ConsumeBootstrapTicket(f.db, "vps-edge")
	if !api.NodeAutoAccept(f.db, "vps-agent") {
		t.Error("l'Agent attend encore : le ticket reste valable pour lui")
	}
	if rec := f.do(http.MethodGet, "/api/v1/join/"+tk.Token); rec.Code != http.StatusOK {
		t.Errorf("le ticket reste lisible tant qu'un nœud n'est pas arrivé : %d", rec.Code)
	}
	api.ConsumeBootstrapTicket(f.db, "vps-agent")
	if rec := f.do(http.MethodGet, "/api/v1/join/"+tk.Token); rec.Code != http.StatusNotFound {
		t.Errorf("tous les nœuds sont arrivés : %d", rec.Code)
	}
}

func TestHostsFingerprintIsEmptyWithoutTLS(t *testing.T) {
	f := newHostsFixture(t)
	f.h.CertFile = func() string { return "" }
	if tk := f.ticket(t, "nas"); tk.Fingerprint != "" {
		t.Errorf("derrière un reverse proxy, pas d'empreinte à épingler : %q", tk.Fingerprint)
	}
}

// Une passerelle déclarée mais pas encore installée ne répond jamais : lister les hôtes ou créer un ticket ne doit pas
// attendre le délai du client interne (deux minutes).
func TestHostsDoNotWaitForAnUnreachableEdge(t *testing.T) {
	f := newHostsFixture(t)
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-block }))
	t.Cleanup(func() { close(block); srv.Close() })

	if _, err := f.db.Exec(`CREATE TABLE tokens (id TEXT PRIMARY KEY, token TEXT UNIQUE NOT NULL, role TEXT NOT NULL,
		node_name TEXT NOT NULL, node_endpoint TEXT, expires_at DATETIME, revoked INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO tokens(id, token, role, node_name, node_endpoint) VALUES('t1', 'tok', 'edge', 'vps-edge', ?)`,
		srv.URL); err != nil {
		t.Fatal(err)
	}
	f.h.Nodes = &api.NodesHandler{DB: f.db, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}

	start := time.Now()
	if rec := f.do(http.MethodGet, "/api/v1/hosts"); rec.Code != http.StatusOK {
		t.Fatalf("liste : %d", rec.Code)
	}
	f.ticket(t, "nas")
	if elapsed := time.Since(start); elapsed > 6*time.Second {
		t.Errorf("l'attente d'une passerelle muette doit être bornée, %s écoulées", elapsed)
	}
}

func TestJoinTicketGivesTheTriggerURLTheQRCodeAndTheCommands(t *testing.T) {
	f := newHostsFixture(t)
	tk := f.ticket(t, "nas")

	u, err := url.Parse(tk.TriggerURL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "http" || u.Host != "192.168.1.50:8080" || u.Path != "/join" {
		t.Errorf("le QR vise la page de confirmation du launcher de l'hôte : %s", tk.TriggerURL)
	}
	q := u.Query()
	if q.Get("admin") != "https://192.168.1.10:9443" || q.Get("token") != tk.Token || q.Get("fp") != f.cert.Fingerprint ||
		q.Get("host") != "nas" || q.Get("roles") != "agent" {
		t.Errorf("paramètres du lien = %v", q)
	}
	if !strings.HasPrefix(tk.QRCode, "data:image/png;base64,") {
		t.Errorf("qr_code = %.40s", tk.QRCode)
	}

	const image = "reg.example/gpx/launcher:v1"
	if tk.ListenCommand != "docker run --rm -p 8080:8080 -v /var/run/docker.sock:/var/run/docker.sock "+image {
		t.Errorf("commande d'attente = %q", tk.ListenCommand)
	}
	want := "docker run --rm -v /var/run/docker.sock:/var/run/docker.sock " + image + " join " + tk.SpecURL + " --fingerprint " + f.cert.Fingerprint
	if tk.JoinCommand != want {
		t.Errorf("commande d'installation = %q", tk.JoinCommand)
	}
	if tk.Warning != "" {
		t.Errorf("avertissement inattendu : %s", tk.Warning)
	}
}

// Le launcher n'accepte qu'un Admin en https : sans adresse publique en https, pas de lien ni de QR code, et on le dit.
func TestJoinTicketWithoutHTTPSAdminGivesNoQRCode(t *testing.T) {
	f := newHostsFixture(t)
	f.h.PublicURL = func(*http.Request) string { return "http://192.168.1.10:9443" }
	tk := f.ticket(t, "nas")
	if tk.TriggerURL != "" || tk.QRCode != "" {
		t.Errorf("pas de lien ni de QR code vers un Admin en clair : %q", tk.TriggerURL)
	}
	if !strings.Contains(tk.Warning, "https") {
		t.Errorf("avertissement = %q", tk.Warning)
	}
	if tk.JoinCommand == "" {
		t.Error("la commande reste donnée")
	}
}
