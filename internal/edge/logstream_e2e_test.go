// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/edgelogs"
	"github.com/vincamok/goproxify/internal/admin/edgews"
	"github.com/vincamok/goproxify/internal/admin/logs"
	"github.com/vincamok/goproxify/internal/config"
	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	"github.com/vincamok/goproxify/internal/edge/logapi"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/logstore"
	edgews2 "github.com/vincamok/goproxify/internal/edge/ws"
)

const streamEdgeID = "22222222-2222-2222-2222-222222222222"
const streamEdgeID2 = "33333333-3333-3333-3333-333333333333"

// streamGateway est une passerelle réelle (base de logs, hub WebSocket) qui ne traite que la reprise des logs.
type streamGateway struct {
	*Server
	url string
}

func newStreamGateway(t *testing.T, dir string) *streamGateway {
	return newNamedStreamGateway(t, dir, "gw-stream")
}

func newNamedStreamGateway(t *testing.T, dir, name string) *streamGateway {
	t.Helper()
	t.Setenv("GPX_LOG_IP_KEY_PATH", filepath.Join(dir, "log-ip-key.gpx"))
	cfg := &config.EdgeConfig{}
	cfg.Engine.LogStoreDir = filepath.Join(dir, "logs")
	cfg.Identity.NodeName = name
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	s := &Server{
		cfg:       cfg,
		log:       edgelog.New("error", "text", ""),
		accessLog: edgelog.NewAccessLogger(),
		cache:     edgecache.New(filepath.Join(dir, "edge-cache.gpx"), "cle-passerelle"),
		wsHub:     edgews2.NewHub("e2e-hmac", quiet),
	}
	s.initLogStore()
	if s.logStore == nil {
		t.Fatal("base de logs indisponible")
	}
	s.wsHub.SetAdminMessageHandler(func(connID string, msg edgews2.Message) error {
		if msg.Type == edgews2.TypeLogResume || msg.Type == edgews2.TypeLogLive || msg.Type == edgews2.TypeLogAck {
			return s.handleWSAdminMessage(connID, msg)
		}
		return nil
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/ws/admin", s.wsHub.ServeAdmin)
	mux.HandleFunc("GET "+logapi.PathSearch, s.handleLogSearch)
	mux.HandleFunc("GET "+logapi.PathHistogram, s.handleLogHistogram)
	mux.HandleFunc("GET "+logapi.PathFacets, s.handleLogFacets)
	mux.HandleFunc("POST "+logapi.PathTop, s.handleLogTop)
	mux.HandleFunc("GET "+logapi.PathUniqueIPs, s.handleLogUniqueIPs)
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		srv.Close()
		s.logStreams.stopAll()
		s.logLive.stopAll()
		_ = s.logStore.Close()
	})
	return &streamGateway{Server: s, url: srv.URL}
}

// traffic écrit n événements de sécurité /<prefix>/<i> (accès signalés par le WAF) dans la base de la passerelle : ce
// sont les seuls accès que l'Admin reçoit ligne à ligne.
func (g *streamGateway) traffic(prefix string, n int) {
	g.addAccess(prefix, n, true)
}

// adminSide est l'Admin : sa base et un gestionnaire WebSocket qu'on peut arrêter puis recréer.
type adminSide struct {
	db      *sql.DB
	store   *logs.Store
	manager *edgews.Manager
	quiet   *slog.Logger
	vault   *edgelogs.Vault
}

func newAdminSide(t *testing.T, dir string) *adminSide {
	return newAdminSideWithVault(t, dir, filepath.Join(dir, "admin-logs"))
}

// newAdminSideWithVault monte un Admin dont la base est dans dir et le volume de logs dans vaultDir : deux Admin qui
// partagent vaultDir sont le même volume de logs monté sur une base neuve.
func newAdminSideWithVault(t *testing.T, dir, vaultDir string) *adminSide {
	t.Helper()
	db, err := admindb.Open(filepath.Join(dir, "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	vault, err := edgelogs.Open(vaultDir, nil, quiet)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(vault.Close)
	return &adminSide{db: db, store: logs.New(db), quiet: quiet, vault: vault}
}

// start (re)démarre le gestionnaire et enregistre la passerelle : comme un démarrage de l'Admin.
func (a *adminSide) start(t *testing.T, gatewayURL string) {
	t.Helper()
	a.manager = edgews.NewManager("e2e-hmac", a.db, a.quiet)
	a.manager.SetLogStreamIngestor(&edgews.LogStreamIngestor{Store: a.store, Log: a.quiet, Vault: a.vault})
	a.manager.Register(streamEdgeID, "gw-stream", gatewayURL, "admin")
}

func (a *adminSide) stop() {
	if a.manager != nil {
		a.manager.Close()
		a.manager = nil
	}
}

func (a *adminSide) count(t *testing.T, where string) int {
	t.Helper()
	var n int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM logs WHERE ` + where).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("délai dépassé : %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Une coupure de l'Admin ne laisse plus de trou : ce que la passerelle a journalisé pendant la coupure arrive à
// la reconnexion, sans doublon, y compris quand la passerelle redémarre pendant la coupure.
func TestAdminOutageLeavesNoGapInTheLogs(t *testing.T) {
	dir := t.TempDir()
	gwDir := filepath.Join(dir, "gw")
	gw := newStreamGateway(t, gwDir)
	admin := newAdminSide(t, dir)
	t.Cleanup(admin.stop)

	admin.start(t, gw.url)
	gw.traffic("avant", 30)
	waitUntil(t, "les 30 accès d'avant la coupure", func() bool { return admin.count(t, `path LIKE '/avant/%'`) == 30 })

	// Coupure de l'Admin : la passerelle continue de journaliser dans sa base.
	admin.stop()
	waitUntil(t, "déconnexion de l'Admin", func() bool { return !gw.wsHub.HasAdmin(streamEdgeID) })
	gw.traffic("pendant", 40)
	gw.log.Error("incident pendant la coupure", "domain", "app.example.com")
	gw.logStore.Flush()
	if n := admin.count(t, `path LIKE '/pendant/%'`); n != 0 {
		t.Fatalf("%d lignes reçues alors que l'Admin est coupé", n)
	}

	// Retour de l'Admin : tout ce qui manquait arrive, une seule fois.
	admin.start(t, gw.url)
	waitUntil(t, "les 40 accès de la coupure", func() bool { return admin.count(t, `path LIKE '/pendant/%'`) == 40 })
	waitUntil(t, "le log système de la coupure", func() bool {
		return admin.count(t, `status = 0 AND message LIKE 'incident pendant la coupure%'`) == 1
	})
	gw.traffic("apres", 10)
	waitUntil(t, "le trafic en direct après le retour", func() bool { return admin.count(t, `path LIKE '/apres/%'`) == 10 })

	for _, prefix := range []string{"avant", "pendant", "apres"} {
		var total, distinct int
		if err := admin.db.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT path) FROM logs WHERE path LIKE ?`, "/"+prefix+"/%").Scan(&total, &distinct); err != nil {
			t.Fatal(err)
		}
		if total != distinct {
			t.Errorf("/%s : %d lignes pour %d chemins distincts (doublons)", prefix, total, distinct)
		}
	}
	if c, _ := admin.store.StreamCursor(streamEdgeID, "access"); c == 0 {
		t.Error("la position du flux d'accès n'est pas enregistrée")
	}
}

func TestGatewayRestartDuringAnAdminOutageLosesNothing(t *testing.T) {
	dir := t.TempDir()
	gwDir := filepath.Join(dir, "gw")
	gw := newStreamGateway(t, gwDir)
	admin := newAdminSide(t, dir)
	t.Cleanup(admin.stop)

	admin.start(t, gw.url)
	gw.traffic("avant", 20)
	waitUntil(t, "les accès d'avant la coupure", func() bool { return admin.count(t, `path LIKE '/avant/%'`) == 20 })
	admin.stop()

	gw.traffic("pendant", 25)
	gw.logStore.Flush()
	// La passerelle redémarre pendant la coupure : son processus disparaît, sa base reste sur le volume.
	gw.logStreams.stopAll()
	_ = gw.logStore.Close()

	gw2 := newStreamGateway(t, gwDir)
	gw2.traffic("apres", 5)
	admin.start(t, gw2.url)
	waitUntil(t, "tout ce qui manquait", func() bool {
		return admin.count(t, `path LIKE '/pendant/%'`) == 25 && admin.count(t, `path LIKE '/apres/%'`) == 5
	})
	if n := admin.count(t, `path LIKE '/avant/%'`); n != 20 {
		t.Fatalf("%d lignes d'avant la coupure, attendu 20 (pas de rejeu en double)", n)
	}
}

// Un Admin dont la base est neuve (position 0) reçoit tout l'historique de la passerelle.
func TestAFreshAdminReceivesTheWholeHistory(t *testing.T) {
	dir := t.TempDir()
	gw := newStreamGateway(t, filepath.Join(dir, "gw"))
	gw.traffic("histoire", 60)
	gw.logStore.Flush()

	admin := newAdminSide(t, dir)
	t.Cleanup(admin.stop)
	admin.start(t, gw.url)
	waitUntil(t, "tout l'historique", func() bool { return admin.count(t, `path LIKE '/histoire/%'`) == 60 })
}

// Si l'Admin n'arrive pas à écrire un lot, rien n'est gardé et la position ne bouge pas : la passerelle renvoie
// le lot depuis cette position dès que l'Admin la redemande, et tout arrive une seule fois.
func TestAdminWriteFailureIsRetriedFromThePersistedPosition(t *testing.T) {
	dir := t.TempDir()
	gw := newStreamGateway(t, filepath.Join(dir, "gw"))
	admin := newAdminSide(t, dir)
	t.Cleanup(admin.stop)
	if _, err := admin.db.Exec(`CREATE TRIGGER fail_on_boom BEFORE INSERT ON logs WHEN NEW.path = '/boom/1'
		BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatal(err)
	}

	gw.traffic("ok", 5)
	gw.traffic("boom", 1)
	gw.traffic("suite", 5)
	gw.logStore.Flush()
	admin.start(t, gw.url)

	time.Sleep(1500 * time.Millisecond)
	if n := admin.count(t, `path LIKE '/ok/%' OR path LIKE '/boom/%' OR path LIKE '/suite/%'`); n != 0 {
		t.Fatalf("%d lignes gardées alors que le lot échoue (tout ou rien)", n)
	}
	if _, err := admin.db.Exec(`DROP TRIGGER fail_on_boom`); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "le renvoi après la réparation", func() bool {
		return admin.count(t, `path LIKE '/ok/%'`) == 5 && admin.count(t, `path LIKE '/boom/%'`) == 1 && admin.count(t, `path LIKE '/suite/%'`) == 5
	})
	var total, distinct int
	if err := admin.db.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT path) FROM logs WHERE status > 0`).Scan(&total, &distinct); err != nil {
		t.Fatal(err)
	}
	if total != 11 || distinct != 11 {
		t.Fatalf("%d lignes pour %d chemins distincts, attendu 11 et 11", total, distinct)
	}
}

// Les logs de conteneurs d'un Agent envoyés à la passerelle pendant une coupure de l'Admin arrivent à son retour,
// avec le nom du conteneur et la mention de l'Agent.
func TestAgentContainerLogsDuringAnAdminOutageReachTheAdmin(t *testing.T) {
	dir := t.TempDir()
	gw := newStreamGateway(t, filepath.Join(dir, "gw"))
	admin := newAdminSide(t, dir)
	t.Cleanup(admin.stop)

	admin.start(t, gw.url)
	waitUntil(t, "connexion de l'Admin", func() bool { return gw.wsHub.HasAdmin(streamEdgeID) })
	admin.stop()
	waitUntil(t, "déconnexion de l'Admin", func() bool { return !gw.wsHub.HasAdmin(streamEdgeID) })

	post := func(body string) {
		rec := httptest.NewRecorder()
		gw.handleAgentLogs(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/agent/logs", strings.NewReader(body)))
		if rec.Code != http.StatusNoContent {
			t.Fatalf("lot refusé : %d", rec.Code)
		}
	}
	post(`{"container_id":"c1","container_name":"web","entries":[{"t":"2026-10-21T10:00:00Z","line":"démarrage"},{"t":"2026-10-21T10:00:01Z","line":"prêt"}]}`)
	post(`{"container_id":"c1","container_name":"web","entries":[{"t":"2026-10-21T10:00:01Z","line":"prêt"},{"t":"2026-10-21T10:00:02Z","line":"requête"}]}`) // renvoi qui chevauche

	admin.start(t, gw.url)
	waitUntil(t, "les logs du conteneur", func() bool { return admin.count(t, `component = 'agent' AND domain = 'web'`) == 3 })
	time.Sleep(300 * time.Millisecond)
	if n := admin.count(t, `component = 'agent' AND domain = 'web'`); n != 3 {
		t.Fatalf("%d lignes, attendu 3 (aucun doublon)", n)
	}
	var node string
	if err := admin.db.QueryRow(`SELECT node_name FROM logs WHERE component = 'agent' LIMIT 1`).Scan(&node); err != nil || node == "" {
		t.Fatalf("nom de la passerelle absent : %q, %v", node, err)
	}
}

// mixed fait passer n requêtes de domaines et de codes variés par le journal d'accès de la passerelle.
func (g *streamGateway) mixed(prefix string, n int) {
	statuses := []int{200, 200, 404, 502, 301}
	for i := 1; i <= n; i++ {
		status := statuses[i%len(statuses)]
		h := g.accessLog.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://d%d.example.com/%s/%d", i%3, prefix, i), nil)
		req.Host = fmt.Sprintf("d%d.example.com", i%3)
		req.RemoteAddr = "198.51.100.7:4000"
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
}

// minuteTotals relit logs_minute de l'Admin et le recalcule depuis les lignes brutes que la passerelle garde : l'Admin
// n'en reçoit aucune, ses cumuls viennent tous de la passerelle.
func (a *adminSide) minuteTotals(t *testing.T, gw *streamGateway) (fromGateway, fromRaw map[string][2]int64) {
	t.Helper()
	rows, err := a.db.Query(`SELECT minute, domain, status, requests, bytes FROM logs_minute WHERE node_name = 'gw-stream'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	fromGateway = map[string][2]int64{}
	for rows.Next() {
		var m, d string
		var st int
		var v [2]int64
		if err := rows.Scan(&m, &d, &st, &v[0], &v[1]); err != nil {
			t.Fatal(err)
		}
		fromGateway[fmt.Sprintf("%s|%s|%d", m, d, st)] = v
	}
	gw.logStore.Flush()
	raw, err := gw.logStore.ReadAfter(logstore.KindAccess, 0, 100000)
	if err != nil {
		t.Fatal(err)
	}
	fromRaw = map[string][2]int64{}
	for _, r := range raw {
		k := fmt.Sprintf("%s|%s|%d", r.Ts.UTC().Format("2006-01-02T15:04"), r.Domain, r.Status)
		v := fromRaw[k]
		v[0]++
		v[1] += r.Bytes
		fromRaw[k] = v
	}
	return fromGateway, fromRaw
}

// Les cumuls calculés par la passerelle arrivent à l'Admin, y compris ceux d'une coupure, et égalent un GROUP BY
// sur les lignes brutes que la passerelle garde : l'Admin ne reçoit aucune de ces lignes.
func TestMinuteTotalsFromTheGatewayMatchTheRawLinesAfterAnOutage(t *testing.T) {
	dir := t.TempDir()
	gw := newStreamGateway(t, filepath.Join(dir, "gw"))
	admin := newAdminSide(t, dir)
	t.Cleanup(admin.stop)

	admin.start(t, gw.url)
	gw.mixed("avant", 60)
	waitUntil(t, "les cumuls d'avant", func() bool { return admin.minuteRequests(t) == 60 })
	admin.stop()
	waitUntil(t, "déconnexion de l'Admin", func() bool { return !gw.wsHub.HasAdmin(streamEdgeID) })
	gw.mixed("pendant", 90)
	gw.logStore.Flush()
	admin.start(t, gw.url)
	waitUntil(t, "les cumuls de la coupure", func() bool { return admin.minuteRequests(t) == 150 })
	gw.mixed("apres", 30)

	waitUntil(t, "des cumuls égaux aux lignes brutes", func() bool {
		agg, raw := admin.minuteTotals(t, gw)
		if len(agg) == 0 || len(agg) != len(raw) {
			return false
		}
		for k, v := range raw {
			if agg[k] != v {
				return false
			}
		}
		return true
	})
	agg, _ := admin.minuteTotals(t, gw)
	var total int64
	for _, v := range agg {
		total += v[0]
	}
	if total != 180 {
		t.Fatalf("%d requêtes cumulées, attendu 180", total)
	}
	if c, _ := admin.store.StreamCursor(streamEdgeID, "minute"); c == 0 {
		t.Error("la position du flux de cumuls n'est pas enregistrée")
	}
}

// minuteRequests rend le nombre de requêtes cumulées par la passerelle chez l'Admin.
func (a *adminSide) minuteRequests(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := a.db.QueryRow(`SELECT COALESCE(SUM(requests), 0) FROM logs_minute WHERE node_name = 'gw-stream'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// errorsFrom fait passer n requêtes refusées (403) depuis ip.
func (g *streamGateway) errorsFrom(ip string, n int) {
	h := g.accessLog.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	for i := 1; i <= n; i++ {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://app.example.com/refus/%d", i), nil)
		req.RemoteAddr = ip + ":4000"
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
}

// Les compteurs d'erreurs par IP arrivent à l'Admin après une coupure et égalent un GROUP BY sur les lignes brutes
// que la passerelle garde : le Fail2Ban global n'a besoin d'aucune ligne.
func TestIPErrorCountersFromTheGatewayMatchTheRawLinesAfterAnOutage(t *testing.T) {
	dir := t.TempDir()
	gw := newStreamGateway(t, filepath.Join(dir, "gw"))
	admin := newAdminSide(t, dir)
	t.Cleanup(admin.stop)

	admin.start(t, gw.url)
	gw.errorsFrom("203.0.113.9", 12)
	waitUntil(t, "les refus d'avant", func() bool { return admin.ipErrorTotal(t) == 12 })
	admin.stop()
	waitUntil(t, "déconnexion de l'Admin", func() bool { return !gw.wsHub.HasAdmin(streamEdgeID) })
	gw.errorsFrom("203.0.113.9", 15)
	gw.errorsFrom("203.0.113.77", 4)
	gw.logStore.Flush()
	admin.start(t, gw.url)
	waitUntil(t, "les refus de la coupure", func() bool { return admin.ipErrorTotal(t) == 31 })

	waitUntil(t, "des compteurs égaux aux lignes brutes", func() bool {
		read := func(q string) map[string]int64 {
			rows, err := admin.db.Query(q)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			out := map[string]int64{}
			for rows.Next() {
				var m, ip string
				var n int64
				if err := rows.Scan(&m, &ip, &n); err != nil {
					t.Fatal(err)
				}
				out[m+"|"+ip] = n
			}
			return out
		}
		agg := read(`SELECT minute, ip, errors FROM edge_ip_errors WHERE node_id = '` + streamEdgeID + `'`)
		raw := map[string]int64{}
		rows, err := gw.logStore.ReadAfter(logstore.KindAccess, 0, 100000)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.Status == http.StatusForbidden {
				raw[r.Ts.UTC().Format("2006-01-02T15:04")+"|"+r.IP]++
			}
		}
		if len(agg) == 0 || len(agg) != len(raw) {
			return false
		}
		for k, v := range raw {
			if agg[k] != v {
				return false
			}
		}
		return true
	})
	if c, _ := admin.store.StreamCursor(streamEdgeID, "iperr"); c == 0 {
		t.Error("la position du flux de compteurs n'est pas enregistrée")
	}
}

// ipErrorTotal rend le total des compteurs d'erreurs par IP reçus de la passerelle.
func (a *adminSide) ipErrorTotal(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := a.db.QueryRow(`SELECT COALESCE(SUM(errors), 0) FROM edge_ip_errors WHERE node_id = ?`, streamEdgeID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Une IP anonymisée ou pseudonymisée ne produit aucun compteur : le Fail2Ban global ne peut pas la viser.
func TestNoIPCounterIsSentForATruncatedIP(t *testing.T) {
	dir := t.TempDir()
	gw := newStreamGateway(t, filepath.Join(dir, "gw"))
	gw.accessLog.SetIPProtection(true, false)
	gw.errorsFrom("203.0.113.9", 10)
	gw.logStore.Flush()
	rows, err := gw.logStore.ReadIPErrorsAfter(0, 100)
	if err != nil || len(rows) != 0 {
		t.Fatalf("%d compteurs pour une IP anonymisée, %v", len(rows), err)
	}
}
