package core

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/config"
)

func TestRejectTrace(t *testing.T) {
	h := rejectTrace(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	for method, want := range map[string]int{
		"TRACE": http.StatusMethodNotAllowed, "TRACK": http.StatusMethodNotAllowed,
		http.MethodGet: http.StatusOK, http.MethodPost: http.StatusOK, http.MethodOptions: http.StatusOK,
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest(method, "/", nil))
		if w.Code != want {
			t.Errorf("%s : %d, attendu %d", method, w.Code, want)
		}
	}
}

func TestMaxHeaderBytes(t *testing.T) {
	cfg := &config.CoreConfig{}
	if got := cfg.MaxHeaderBytes(); got != 32<<10 {
		t.Fatalf("défaut = %d, attendu 32 Ko", got)
	}
	cfg.Timeouts.MaxHeaderKB = 8
	if got := cfg.MaxHeaderBytes(); got != 8<<10 {
		t.Fatalf("configuré = %d, attendu 8 Ko", got)
	}
}

// Vérifie l'effet réel de la limite sur un serveur net/http configuré comme le Core.
func TestMaxHeaderBytes_ServerRejectsOversizedHeaders(t *testing.T) {
	cfg := &config.CoreConfig{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Config.MaxHeaderBytes = cfg.MaxHeaderBytes()
	srv.Start()
	defer srv.Close()

	for _, tc := range []struct {
		size int
		want int
	}{{8 << 10, http.StatusOK}, {64 << 10, http.StatusRequestHeaderFieldsTooLarge}} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		req.Header.Set("X-Big", strings.Repeat("a", tc.size))
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("%d o : %v", tc.size, err)
		}
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("en-tête de %d o : %d, attendu %d", tc.size, resp.StatusCode, tc.want)
		}
	}
}
