package edge

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/config"
	"github.com/vincamok/goproxify/internal/edge/bansdb"
	"github.com/vincamok/goproxify/internal/edge/lastua"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/logthrottle"
	"github.com/vincamok/goproxify/internal/edge/router"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// Un scanner qui ouvre des centaines de connexions avant que son ban soit actif rappelait le callback à
// chaque requête (base, pairs, rechargement, Admin) : un seul ban par IP et par minute.
func TestThreatBanCallbackRunsOncePerIPPerMinute(t *testing.T) {
	logFile := filepath.Join(os.TempDir(), "gpx-threatban-"+strings.ReplaceAll(t.Name(), "/", "_")+".log")
	os.Remove(logFile)
	t.Cleanup(func() { os.Remove(logFile) }) // le logger garde le fichier ouvert : échec toléré sous Windows

	cfg := &config.EdgeConfig{}
	cfg.Identity.NodeName = "frontal"
	s := &Server{
		cfg:          cfg,
		log:          edgelog.New("info", "text", logFile),
		table:        &router.Table{},
		banStore:     router.NewBanStore(),
		profileStore: router.NewIPProfileStore(),
		blockLog:     logthrottle.New(time.Minute),
		lastUA:       lastua.New(),
		wsHub:        edgews.NewHub("", slog.New(slog.NewTextHandler(io.Discard, nil))),
	}
	cb := s.threatBanCallback()
	exp := time.Now().Add(time.Hour)
	for i := 0; i < 50; i++ {
		cb("203.0.113.9", "threat: path", exp, nil)
	}
	cb("203.0.113.10", "threat: path", exp, nil)

	data, _ := os.ReadFile(logFile)
	if n := strings.Count(string(data), "IP bannie"); n != 2 {
		t.Fatalf("%d lignes « IP bannie » pour 51 appels sur 2 IP, attendu 2\n%s", n, data)
	}
}

// Un ban automatique emporte le dernier User-Agent vu pour l'IP : c'est lui qui explique le ban dans la chronologie.
func TestThreatBanCarriesTheLastUserAgent(t *testing.T) {
	logFile := filepath.Join(os.TempDir(), "gpx-threatban-ua-"+strings.ReplaceAll(t.Name(), "/", "_")+".log")
	os.Remove(logFile)
	t.Cleanup(func() { os.Remove(logFile) })

	cfg := &config.EdgeConfig{}
	cfg.Identity.NodeName = "frontal"
	hub := edgews.NewHub("", slog.New(slog.NewTextHandler(io.Discard, nil)))
	bans, err := bansdb.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer bans.Close()
	s := &Server{
		cfg:          cfg,
		log:          edgelog.New("info", "text", logFile),
		table:        &router.Table{},
		banStore:     router.NewBanStore(),
		profileStore: router.NewIPProfileStore(),
		blockLog:     logthrottle.New(time.Minute),
		lastUA:       lastua.New(),
		bansDB:       bans,
		wsHub:        hub,
	}
	s.lastUA.Note("203.0.113.9", "Nikto/2.5")
	s.threatBanCallback()("203.0.113.9", "threat: ua", time.Now().Add(time.Hour), nil)

	rows, err := bans.ActiveBans()
	if err != nil || len(rows) != 1 || rows[0].UserAgent != "Nikto/2.5" {
		t.Fatalf("ban sans le User-Agent vu : %v %+v", err, rows)
	}
}
